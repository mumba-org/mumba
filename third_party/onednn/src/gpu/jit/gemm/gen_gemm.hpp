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

#ifndef GPU_JIT_GEMM_GEN_GEMM_HPP
#define GPU_JIT_GEMM_GEN_GEMM_HPP

#include <assert.h>
#include <memory>

#include "common/c_types_map.hpp"
#include "common/gemm_utils.hpp"
#include "common/utils.hpp"
#include "gpu/compute/compute.hpp"
#include "gpu/compute/kernel.hpp"
#include "gpu/gemm/gpu_gemm.hpp"
#include "gpu/gpu_gemm_pd.hpp"
#include "gpu/jit/gemm/gen_gemm_kernel.hpp"
#include "gpu/primitive_conf.hpp"

namespace dnnl {
namespace impl {
namespace gpu {
namespace jit {

struct gen_gemm_t : public gpu_gemm_t {
    using gpu_gemm_t::gpu_gemm_t;

    struct pd_t : public gpu_gemm_pd_t {
        using gpu_gemm_pd_t::gpu_gemm_pd_t;

        DECLARE_COMMON_PD_T("jit:gemm:any", gen_gemm_t);

        status_t init(engine_t *engine) {
            using namespace prop_kind;
            using namespace data_type;
            using namespace primitive_kind;
            using smask_t = primitive_attr_t::skip_mask_t;
            using arch_t = compute::gpu_arch_t;

            assert(engine->kind() == engine_kind::gpu);
            auto *compute_engine
                    = utils::downcast<compute::compute_engine_t *>(engine);

            // LIMITATIONS:
            // - runtime dims are not supported
            // - bias only supported for f16 and f32 with same c_type.
            // - postops only supported for f32.
            bool ok = true;

            auto attr_skip_mask = smask_t::oscale | smask_t::post_ops;

            ok = set_default_formats();
            if (!ok) return status::unimplemented;

            const auto d = desc();

            if (d->c_type() == s32) {
                ok = ok && utils::one_of(d->a_type(), u8, s8)
                        && utils::one_of(d->b_type(), u8, s8)
                        && d->acc_type == d->c_type()
                        && attr()->zero_points_.defined(DNNL_ARG_SRC)
                        && attr()->zero_points_.defined(DNNL_ARG_WEIGHTS)
                        && (attr()->zero_points_.has_default_values(
                                    DNNL_ARG_DST)
                                || !attr()->zero_points_.defined(DNNL_ARG_DST));

                int cmask = 0;
                attr()->zero_points_.get(
                        DNNL_ARG_DST, nullptr, &cmask, nullptr);
                ok &= utils::one_of(cmask, 0, 1 << 0, 1 << 1);

                attr_skip_mask |= smask_t::zero_points_runtime;
            } else {
                ok = ok && utils::one_of(d->c_type(), f32, f16)
                        && d->a_type() == d->c_type()
                        && d->b_type() == d->c_type()
                        && d->acc_type == d->c_type();
            }

            ok = ok && !has_blocks() && batch_dims() <= 2
                    && !utils::one_of(DNNL_RUNTIME_DIM_VAL, d->m(), d->n(),
                            d->k(), d->lda(), d->ldb(), d->ldc(), d->batch())
                    && IMPLICATION(with_bias(),
                            (d->bias_type() == d->c_type())
                                    && utils::one_of(
                                            bias_cmask(), 0, 1 << 0, 1 << 1))
                    && compute_engine->mayiuse_ngen_kernels()
                    && attr()->has_default_values(attr_skip_mask)
                    && attr()->output_scales_.mask_ == 0
                    && attr()->post_ops_.len() <= 2
                    && IMPLICATION(attr()->post_ops_.len() == 1,
                            attr()->post_ops_.find(eltwise) != -1
                                    || attr()->post_ops_.find(sum) != -1)
                    && IMPLICATION(attr()->post_ops_.len() == 2,
                            attr()->post_ops_.find(sum) == 0
                                    && attr()->post_ops_.find(eltwise) == 1);

            if (!ok) return status::unimplemented;

            auto *dev_info = compute_engine->device_info();

            arch_ = dev_info->gpu_arch();

            ok &= utils::one_of(arch_, arch_t::gen9, arch_t::xe_lp);

            if (!ok) return status::unimplemented;

            eu_count_ = dev_info->eu_count();
            hw_threads_ = dev_info->hw_threads();

            attr_info_ = attr_info_t::create(attr());

            ok &= IMPLICATION(with_eltwise(),
                    jit_eltwise_injector_f32_is_supported(
                            attr_info()->eltwise_alg));

            if (!ok) return status::unimplemented;

            return status::success;
        }

        bool set_default_formats() {
            return gpu_gemm_pd_t::set_default_formats();
        }

        bool with_c_offset() const {
            return !attr()->zero_points_.has_default_values(DNNL_ARG_DST);
        }

        bool with_eltwise() const {
            return attr_info()->eltwise_alg != alg_kind::undef;
        }

        alg_kind_t eltwise_alg() const { return attr_info()->eltwise_alg; }

        float eltwise_alpha() const { return attr_info()->eltwise_alpha; }

        float eltwise_beta() const { return attr_info()->eltwise_beta; }

        float eltwise_scale() const { return attr_info()->eltwise_scale; }

        float alpha() const { return attr()->output_scales_.scales_[0]; }

        float beta() const {
            using namespace primitive_kind;
            const auto &p = attr()->post_ops_;
            return p.contain(sum, 0) ? p.entry_[0].sum.scale : 0.f;
        }

        bool with_bias() const {
            return desc()->bias_type() != data_type::undef;
        }

        int bias_cmask() const {
            unsigned char to_cmask[4] = {0, 2, 1, 3};
            return with_bias() ? to_cmask[(desc()->bias_mask() >> 1) & 3] : -1;
        }

        int batch_dims() const {
            return nstl::max(desc()->c_desc.ndims - 2, 0);
        }

        const attr_info_t *attr_info() const { return &attr_info_; }

        size_t dyn_offset_a = 0;
        size_t dyn_offset_b = 0;
        size_t dyn_offset_c = 0;
        size_t dyn_offset_co = 0;
        int hw_threads_ = 0;
        int eu_count_ = 0;
        compute::gpu_arch_t arch_ = compute::gpu_arch_t::unknown;

        attr_info_t attr_info_ = {};
    };

    status_t init(engine_t *engine) override { return init_nocopy(engine); }

    status_t init_nocopy(engine_t *engine) {
        using kernel_t = gen_gemm_nocopy_kernel_t;

        int unroll_m, unroll_n;
        auto batch = pd()->desc()->batch();
        int batch_dims = pd()->batch_dims();
        bool transa = (pd()->desc()->transa() == dnnl_trans);
        bool transb = (pd()->desc()->transb() == dnnl_trans);
        auto a_type = pd()->desc()->a_type();
        auto b_type = pd()->desc()->b_type();
        auto c_type = pd()->desc()->c_type();
        auto eltwise_alg = pd()->eltwise_alg();
        auto eltwise_alpha = pd()->eltwise_alpha();
        auto eltwise_beta = pd()->eltwise_beta();
        auto eltwise_scale = pd()->eltwise_scale();

        kernel_t::choose_unrolls(pd()->arch_, pd()->hw_threads_, transa, transb,
                a_type, b_type, c_type, pd()->desc()->m(), pd()->desc()->n(),
                pd()->desc()->k(), batch, unroll_m, unroll_n);

        kernel_t kernel;

        auto status = kernel.init(pd()->arch_, batch_dims, transa, transb,
                pd()->with_c_offset(), pd()->with_bias(), eltwise_alg,
                eltwise_alpha, eltwise_beta, eltwise_scale, a_type, b_type,
                c_type, unroll_m, unroll_n);
        if (status != status::success) return status;

        create_kernel(engine, &nocopy_kernel_, kernel);

        nocopy_info_ = kernel.driver_info();

        return status::success;
    }

    status_t execute(const gemm_exec_ctx_t &ctx) const override;

private:
    status_t launch_nocopy(const gemm_exec_ctx_t &ctx,
            compute::compute_stream_t *s, const memory_storage_t &a,
            const memory_storage_t &b, const memory_storage_t &c,
            const memory_storage_t &co, int64_t offset_a, int64_t offset_b,
            int64_t offset_c, int32_t offset_co, int32_t lda, int32_t ldb,
            int32_t ldc, int32_t m, int32_t n, int32_t k, float alpha,
            float beta, int16_t ao, int16_t bo, int32_t cmask,
            bool last_k_block) const;

    compute::kernel_t nocopy_kernel_;
    CommonDriverInfo nocopy_info_;

    const pd_t *pd() const { return (const pd_t *)primitive_t::pd().get(); }
};

} // namespace jit
} // namespace gpu
} // namespace impl
} // namespace dnnl
#endif

// vim: et ts=4 sw=4 cindent cino+=l0,\:4,N-s
