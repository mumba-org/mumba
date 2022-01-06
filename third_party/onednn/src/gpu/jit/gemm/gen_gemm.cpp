/*******************************************************************************
* Copyright 2019-2021 Intel Corporation
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*******************************************************************************/

#include "gpu/jit/gemm/gen_gemm.hpp"
#include "common/c_types_map.hpp"
#include "common/dnnl_traits.hpp"
#include "common/float16.hpp"
#include "common/math_utils.hpp"
#include "common/type_helpers.hpp"
#include "gpu/jit/gemm/gen_gemm_kernel_common.hpp"

namespace dnnl {
namespace impl {
namespace gpu {
namespace jit {

status_t gen_gemm_t::launch_nocopy(const gemm_exec_ctx_t &ctx,
        compute::compute_stream_t *compute_stream, const memory_storage_t &a,
        const memory_storage_t &b, const memory_storage_t &c,
        const memory_storage_t &co, int64_t offset_a, int64_t offset_b,
        int64_t offset_c, int32_t offset_co, int32_t lda, int32_t ldb,
        int32_t ldc, int32_t m, int32_t n, int32_t k, float alpha, float beta,
        int16_t ao, int16_t bo, int32_t cmask, bool last_k_block) const {

    bool with_offset = (pd()->desc()->c_type() == data_type::s32);
    uint32_t flags = 0;

    auto stride_a0 = int32_t(pd()->desc()->stride_a(0));
    auto stride_b0 = int32_t(pd()->desc()->stride_b(0));
    auto stride_c0 = int32_t(pd()->desc()->stride_c(0));

    auto stride_a1 = int32_t(pd()->desc()->stride_a(1));
    auto stride_b1 = int32_t(pd()->desc()->stride_b(1));
    auto stride_c1 = int32_t(pd()->desc()->stride_c(1));

    if (!last_k_block) flags |= FlagNonfinalKBlock;
    if (cmask & 1) flags |= FlagCOColumn;
    if (cmask & 2) flags |= FlagCORow;

    compute::kernel_arg_list_t arg_list;
    int argn = 0;

    arg_list.set(argn++, a);
    arg_list.set(argn++, b);
    arg_list.set(argn++, c);
    arg_list.set(argn++, offset_a);
    arg_list.set(argn++, offset_b);
    arg_list.set(argn++, offset_c);
    arg_list.set(argn++, lda);
    arg_list.set(argn++, ldb);
    arg_list.set(argn++, ldc);
    arg_list.set(argn++, m);
    arg_list.set(argn++, n);
    arg_list.set(argn++, k);
    arg_list.set(argn++, alpha);
    arg_list.set(argn++, beta);
    if (with_offset) {
        uint32_t abo = uint16_t(-ao) | (uint16_t(-bo) << 16);
        arg_list.set(argn++, abo);
    }
    if (pd()->with_c_offset() || pd()->with_bias()) {
        arg_list.set(argn++, co);
        arg_list.set(argn++, offset_co);
    }
    arg_list.set(argn++, flags);

    if (pd()->batch_dims() >= 1) {
        arg_list.set(argn++, stride_a0);
        arg_list.set(argn++, stride_b0);
        arg_list.set(argn++, stride_c0);
    }

    if (pd()->batch_dims() >= 2) {
        auto batchSize1 = uint32_t(pd()->desc()->c_desc.dims[1]);
        uint32_t recipBatchSize1 = utils::div_up(
                uint64_t(0x100000000) << math::ilog2q(batchSize1), batchSize1);
        arg_list.set(argn++, stride_a1);
        arg_list.set(argn++, stride_b1);
        arg_list.set(argn++, stride_c1);
        arg_list.set(argn++, batchSize1);
        arg_list.set(argn++, recipBatchSize1);
    }

    size_t gws[3] = {0, 0, 1};

    gws[0] = utils::div_up(m, nocopy_info_.unroll[0]);
    gws[1] = utils::div_up(n, nocopy_info_.unroll[1]);
    gws[2] = pd()->desc()->batch();

    size_t lws[3] = {size_t(nocopy_info_.wg[0]), size_t(nocopy_info_.wg[1]), 1};

    if (nocopy_info_.loopOrder[0] == LoopN) {
        std::swap(lws[0], lws[1]);
        std::swap(gws[0], gws[1]);
    }

    if (nocopy_info_.fusedEUs && (lws[0] > 1))
        gws[0] = utils::rnd_up(gws[0], 2);

    for (int d = 0; d < 2; d++)
        if (nocopy_info_.fixedWG || (gws[d] > lws[d]))
            gws[d] = utils::rnd_up(gws[d], lws[d]);
        else
            lws[d] = gws[d];

    lws[0] *= nocopy_info_.subgroupSize;
    gws[0] *= nocopy_info_.subgroupSize;

    auto nd_range = compute::nd_range_t(gws, lws);
    return parallel_for(ctx, nd_range, nocopy_kernel_, arg_list);
}

status_t gen_gemm_t::execute(const gemm_exec_ctx_t &ctx) const {
    auto a_type = pd()->desc()->a_type();
    auto b_type = pd()->desc()->b_type();
    auto c_type = pd()->desc()->c_type();

    auto *compute_stream
            = utils::downcast<compute::compute_stream_t *>(ctx.stream());

    auto m = pd()->desc()->m();
    auto n = pd()->desc()->n();
    auto k = pd()->desc()->k();

    bool transa = (pd()->desc()->transa() == dnnl_trans);
    bool transb = (pd()->desc()->transb() == dnnl_trans);

    auto lda = pd()->desc()->lda();
    auto ldb = pd()->desc()->ldb();
    auto ldc = pd()->desc()->ldc();

    auto alpha = pd()->alpha();
    auto beta = pd()->beta();

    auto &a = GEMM_CTX_ARG_STORAGE(b);
    auto &b = GEMM_CTX_ARG_STORAGE(a);
    auto &c = GEMM_CTX_ARG_STORAGE(c);
    auto &c_zp = GEMM_CTX_ARG_STORAGE(c_zero_point);
    auto &bias = GEMM_CTX_ARG_STORAGE(bias);
    auto *co = &c_zp;

    size_t off_a0
            = a.offset() / types::data_type_size(a_type) + pd()->dyn_offset_a;
    size_t off_b0
            = b.offset() / types::data_type_size(b_type) + pd()->dyn_offset_b;
    size_t off_c0
            = c.offset() / types::data_type_size(c_type) + pd()->dyn_offset_c;
    size_t off_co0 = 0;

    int16_t ao = 0, bo = 0;
    int cmask = 0;

    if (c_type == data_type::s32) {
        const int *ao_i32 = nullptr;
        const int *bo_i32 = nullptr;
        pd()->attr()->zero_points_.get(DNNL_ARG_SRC, nullptr, nullptr, &ao_i32);
        pd()->attr()->zero_points_.get(
                DNNL_ARG_WEIGHTS, nullptr, nullptr, &bo_i32);
        ao = *ao_i32;
        bo = *bo_i32;
        off_co0 = co->offset() / types::data_type_size(c_type)
                + pd()->dyn_offset_co;
    } else if (pd()->with_bias()) {
        off_co0 = bias.offset() / types::data_type_size(c_type);
        co = &bias;
        cmask = pd()->bias_cmask();
        off_co0 = bias.offset() / types::data_type_size(c_type);
    }

    if (pd()->with_c_offset())
        pd()->attr()->zero_points_.get(DNNL_ARG_DST, nullptr, &cmask, nullptr);

    status_t status;

    auto block_m
            = utils::rnd_up(nocopy_info_.blocking[0], nocopy_info_.unroll[0]);
    auto block_n
            = utils::rnd_up(nocopy_info_.blocking[1], nocopy_info_.unroll[1]);
    auto block_k
            = utils::rnd_up(nocopy_info_.blocking[2], nocopy_info_.unroll[2]);

    if (!utils::one_of(pd()->desc()->c_type(), data_type::f32, data_type::f16))
        block_k = k;

    for (int64_t Bk = 0; Bk < k; Bk += block_k) {
        int64_t size_k = k - Bk;
        bool last_k_block = (size_k <= block_k);
        if (!last_k_block) size_k = block_k;

        for (int64_t Bm = 0; Bm < m; Bm += block_m) {
            int64_t size_m = m - Bm;
            if (size_m > block_m) size_m = block_m;

            auto off_a_src
                    = off_a0 + (!transa ? (Bm + Bk * lda) : (Bk + Bm * lda));

            for (int64_t Bn = 0; Bn < n; Bn += block_n) {
                int64_t size_n = n - Bn;
                if (size_n > block_n) size_n = block_n;

                auto off_b_src = off_b0
                        + (!transb ? (Bk + Bn * ldb) : (Bn + Bk * ldb));

                auto off_c = off_c0 + Bm + Bn * ldc;
                auto off_co = int32_t(off_co0);
                if (cmask & 1) off_co += Bn;
                if (cmask & 2) off_co += Bm;

                float eff_beta = (Bk == 0) ? beta : 1.0f;
                status = launch_nocopy(ctx, compute_stream, a, b, c, *co,
                        off_a_src, off_b_src, off_c, off_co, lda, ldb, ldc,
                        size_m, size_n, size_k, alpha, eff_beta, ao, bo, cmask,
                        last_k_block);

                if (status) return status;
            }
        }
    }

    return status::success;
}

} // namespace jit
} // namespace gpu
} // namespace impl
} // namespace dnnl

// vim: et ts=4 sw=4 cindent cino+=l0,\:4,N-s
