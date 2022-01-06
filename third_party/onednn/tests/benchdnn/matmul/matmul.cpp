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

#include <float.h>
#include <math.h>
#include <random>
#include <stdio.h>
#include <stdlib.h>

#include "oneapi/dnnl/dnnl.h"

#include "tests/test_thread.hpp"

#include "compare.hpp"
#include "dnnl_common.hpp"
#include "dnnl_memory.hpp"

#include "binary/binary.hpp"
#include "matmul/matmul.hpp"

namespace matmul {

void prep_bia_dims(const prb_t *prb, dims_t &bia_dims, const dims_t &dst_dims) {
    bia_dims.resize(dst_dims.size());
    for (int d = 0; d < prb->ndims; ++d)
        bia_dims[d] = (prb->bia_mask & (1 << d)) ? dst_dims[d] : 1;
}

dims_t get_runtime_dims(const dims_t &dims, const dims_mask_t &mask) {
    if (mask.none() || dims.empty()) return dims;
    dims_t runtime_dims;
    runtime_dims.resize(dims.size());
    for (size_t i = 0; i < dims.size(); ++i) {
        runtime_dims[i] = mask[i] ? DNNL_RUNTIME_DIM_VAL : dims[i];
    }
    return runtime_dims;
}

static int init_pd(dnnl_engine_t engine, const prb_t *prb,
        dnnl_primitive_desc_t &mpd, res_t *res, dir_t dir,
        const_dnnl_primitive_desc_t hint) {

    dnnl_memory_desc_t src_d, wei_d, dst_d, bia_d {};
    const auto &src_rt_dims
            = get_runtime_dims(prb->src_dims(), prb->src_runtime_dim_mask());
    const auto &weights_rt_dims = get_runtime_dims(
            prb->weights_dims(), prb->weights_runtime_dim_mask());
    const auto &dst_rt_dims
            = get_runtime_dims(prb->dst_dims(), prb->dst_runtime_dim_mask());

    SAFE(init_md(&src_d, prb->ndims, src_rt_dims.data(), prb->cfg[SRC].dt,
                 prb->stag, prb->strides[STRIDES_SRC]),
            CRIT);

    SAFE(init_md(&wei_d, prb->ndims, weights_rt_dims.data(), prb->cfg[WEI].dt,
                 prb->wtag, prb->strides[STRIDES_WEI]),
            CRIT);

    SAFE(init_md(&dst_d, prb->ndims, dst_rt_dims.data(), prb->cfg[DST].dt,
                 prb->dtag, prb->strides[STRIDES_DST]),
            CRIT);

    if (prb->bia_dt != dnnl_data_type_undef) {
        dims_t bia_dims;
        prep_bia_dims(prb, bia_dims, prb->dst_dims());
        bia_dims = get_runtime_dims(bia_dims, prb->dst_runtime_dim_mask());
        DNN_SAFE(dnnl_memory_desc_init_by_strides(&bia_d, prb->ndims,
                         bia_dims.data(), prb->bia_dt, nullptr),
                WARN);
    }

    dnnl_matmul_desc_t op_d;
    DNN_SAFE(
            dnnl_matmul_desc_init(&op_d, &src_d, &wei_d, &bia_d, &dst_d), WARN);
    DNN_SAFE(op_d.accum_data_type == prb->cfg[ACC].dt ? dnnl_success
                                                      : dnnl_unimplemented,
            CRIT);

    // Overload PER_OC mask definition for batched case
    int mask = 0;
    if (prb->attr.oscale.policy == policy_t::PER_OC)
        mask = (1 << (dst_rt_dims.size() - 1));

    attr_args_t attr_args;
    const auto &dst_dims = prb->dst_dims();
    attr_args.prepare_output_scales(prb->attr, prb->scales, prb->n, mask);
    attr_args.prepare_binary_post_op_mds(
            prb->attr, prb->ndims, dst_dims.data());
    auto dnnl_attr = make_benchdnn_dnnl_wrapper(
            create_dnnl_attr(prb->attr, attr_args));

    dnnl_status_t init_status = dnnl_success;
    init_status = dnnl_primitive_desc_create(
            &mpd, &op_d, dnnl_attr, engine, nullptr);
    if (init_status == dnnl_unimplemented)
        return res->state = UNIMPLEMENTED, OK;
    else
        SAFE(init_status, WARN);

    res->impl_name = query_impl_info(mpd);
    if (maybe_skip(res->impl_name)) {
        BENCHDNN_PRINT(2, "SKIPPED: oneDNN implementation: %s\n",
                res->impl_name.c_str());
        return res->state = SKIPPED, res->reason = SKIP_IMPL_HIT, OK;
    } else {
        BENCHDNN_PRINT(
                5, "oneDNN implementation: %s\n", res->impl_name.c_str());
    }

    return OK;
}

int fill_data(data_kind_t kind, const prb_t *prb, dnn_mem_t &mem_dt,
        dnn_mem_t &mem_fp, res_t *res) {
    const auto nelems = mem_dt.nelems();
    if (nelems == 0) return OK;

    assert(mem_dt.nelems() == mem_fp.nelems());

    const auto &c = prb->cfg[kind];
    float c_f_min = c.f_min, c_f_max = c.f_max;

    if (kind == BIA && mem_dt.dt() == dnnl_u8) c_f_min = 0;

    /* Do fixed partitioning to have same filling for any number of threads */
    const int64_t n_chunks = 16;
    const int64_t chunk_size = div_up(nelems, n_chunks);

    dnnl::impl::parallel_nd(n_chunks, [&](int idx_chunk) {
        int64_t idx_start = idx_chunk * chunk_size;
        int64_t idx_end = MIN2(idx_start + chunk_size, nelems);
        // Note: we use a different seed for each chunk to avoid
        // repeating patterns. We could use discard(idx_start) too but
        // it has a complexity in O(idx_start). We also add 1 to avoid
        // seeding with 0.
        std::minstd_rand msr(kind * nelems + idx_start + 1);
        msr.discard(1);

        std::uniform_int_distribution<> gen(c_f_min, c_f_max);

        // make sure the first element is not zero
        if (idx_start == 0) {
            float val = 0;
            while (val == 0)
                val = (float)gen(msr);
            mem_fp.set_elem(0, val * c.f_scale);
            idx_start += 1;
        }

        for (int64_t idx = idx_start; idx < idx_end; ++idx) {
            auto val = (float)gen(msr) * c.f_scale;
            mem_fp.set_elem(idx, val);
        }
    });

    // work-around mistrusted when A > 0 && B < 0  && C.dt = u8 (or relu)
    if (kind == WEI && nelems == 1 && prb->cfg[SRC].dt == dnnl_u8) {
        if (c.f_max >= 1) mem_fp.set_elem(0, c.f_scale);
    }

    SAFE(mem_dt.reorder(mem_fp), WARN);
    return OK;
}

void check_known_skipped_case(const prb_t *prb, res_t *res) {
    check_known_skipped_case_common(
            {prb->cfg[SRC].dt, prb->cfg[WEI].dt, prb->cfg[DST].dt}, FWD_D, res);
    if (res->state == SKIPPED) return;

    // zero points for non-integral data type does not make sense
    if (!prb->attr.zero_points.is_def() && prb->cfg[WEI].dt != dnnl_s8) {
        res->state = SKIPPED, res->reason = INVALID_CASE;
        return;
    }

    // skip gpu testing for zero points policy other than COMMON
    if (is_gpu()) {
        if (prb->attr.zero_points.get(DNNL_ARG_SRC).policy != policy_t::COMMON
                || prb->attr.zero_points.get(DNNL_ARG_DST).policy
                        != policy_t::COMMON) {
            res->state = SKIPPED, res->reason = CASE_NOT_SUPPORTED;
            return;
        }
    }

    auto src_rt_mask = prb->src_runtime_dim_mask();
    auto wei_rt_mask = prb->weights_runtime_dim_mask();
    auto dst_rt_mask = prb->dst_runtime_dim_mask();

    // memory layout should be defined when some dimension is unknown in pd
    // creation time
    if ((src_rt_mask.any() && prb->stag == "any")
            || (wei_rt_mask.any() && prb->wtag == "any")
            || (dst_rt_mask.any() && prb->dtag == "any")) {
        res->state = SKIPPED, res->reason = INVALID_CASE;
        return;
    }

    // inconsistent runtime mask for m, k, n are not supported
    const int m_idx = prb->ndims - 2;
    const int k_idx_src = prb->ndims - 1;
    const int k_idx_wei = prb->ndims - 2;
    const int n_idx = prb->ndims - 1;
    if (src_rt_mask[m_idx] != dst_rt_mask[m_idx]
            || src_rt_mask[k_idx_src] != wei_rt_mask[k_idx_wei]
            || wei_rt_mask[n_idx] != dst_rt_mask[n_idx]) {
        res->state = SKIPPED, res->reason = INVALID_CASE;
        return;
    }

    // inconsistent runtime masks for batch dims are not supported
    if (prb->ndims > 2) {
        dims_mask_t batch_rt_mask;
        for (int i = 0; i < prb->ndims - 2; ++i)
            batch_rt_mask[i] = true;
        src_rt_mask &= batch_rt_mask;
        wei_rt_mask &= batch_rt_mask;
        dst_rt_mask &= batch_rt_mask;
        if (src_rt_mask != wei_rt_mask || src_rt_mask != dst_rt_mask) {
            res->state = SKIPPED, res->reason = INVALID_CASE;
            return;
        }
    }

    if (is_nvidia_gpu()) {
        const auto &po = prb->attr.post_ops;
        bool post_ops_ok = true;
        for (int i = 0; i < po.len(); ++i) {
            const auto &e = po.entry[i];
            if (e.is_sum_kind())
                continue;
            else if (e.is_eltwise_kind())
                post_ops_ok = post_ops_ok && is_nvidia_eltwise_ok(FLAG_FWD, e);
            else if (e.is_binary_kind() || e.is_convolution_kind())
                post_ops_ok = false;
            else
                assert(!"unknown post-op type");
        }

        const bool oscale_ok = prb->attr.oscale.policy == policy_t::COMMON;

        const bool zp_ok = prb->attr.zero_points.is_def();

        if (!post_ops_ok || !oscale_ok || !zp_ok) {
            res->state = SKIPPED, res->reason = CASE_NOT_SUPPORTED;
            return;
        }
    }
}

int doit(const prb_t *prb, res_t *res) {
    if (bench_mode == LIST) return res->state = LISTED, OK;

    check_known_skipped_case(prb, res);
    if (res->state == SKIPPED) return OK;

    benchdnn_dnnl_wrapper_t<dnnl_primitive_t> prim;
    SAFE(init_prim(prim, init_pd, prb, res), WARN);
    if (res->state == SKIPPED || res->state == UNIMPLEMENTED) return OK;

    const_dnnl_primitive_desc_t const_pd;
    DNN_SAFE(dnnl_primitive_get_primitive_desc(prim, &const_pd), CRIT);

    if (check_mem_size(const_pd) != OK) {
        return res->state = SKIPPED, res->reason = NOT_ENOUGH_RAM, OK;
    }

    const auto q = [&](int index = 0) -> const dnnl_memory_desc_t & {
        return *dnnl_primitive_desc_query_md(
                const_pd, dnnl_query_exec_arg_md, index);
    };

    dnnl_memory_desc_t src_md {}, wei_md {}, dst_md {}, bia_md {}, def_md {};
    // query md if it was defined at pd creation time
    if (prb->src_runtime_dim_mask().none()) src_md = q(DNNL_ARG_SRC);
    if (prb->weights_runtime_dim_mask().none()) wei_md = q(DNNL_ARG_WEIGHTS);
    if (prb->dst_runtime_dim_mask().none()) {
        dst_md = q(DNNL_ARG_DST);
        if (prb->bia_dt != dnnl_data_type_undef) bia_md = q(DNNL_ARG_BIAS);
    }

    // if md is same as default, it means we need to re-create it
    const auto &src_dims = prb->src_dims();
    if (dnnl_memory_desc_equal(&src_md, &def_md)) {
        assert(prb->stag != tag::any);
        SAFE(init_md(&src_md, prb->ndims, src_dims.data(), prb->cfg[SRC].dt,
                     prb->stag, prb->strides[STRIDES_SRC]),
                WARN);
    }

    const auto &weights_dims = prb->weights_dims();
    if (dnnl_memory_desc_equal(&wei_md, &def_md)) {
        assert(prb->wtag != tag::any);
        SAFE(init_md(&wei_md, prb->ndims, weights_dims.data(), prb->cfg[WEI].dt,
                     prb->wtag, prb->strides[STRIDES_WEI]),
                WARN);
    }

    const auto &dst_dims = prb->dst_dims();
    if (dnnl_memory_desc_equal(&dst_md, &def_md)) {
        assert(prb->dtag != tag::any);
        SAFE(init_md(&dst_md, prb->ndims, dst_dims.data(), prb->cfg[DST].dt,
                     prb->dtag, prb->strides[STRIDES_DST]),
                WARN);
    }
    if (prb->bia_dt != dnnl_data_type_undef) {
        dims_t bia_dims;
        prep_bia_dims(prb, bia_dims, dst_dims);
        DNN_SAFE(dnnl_memory_desc_init_by_strides(&bia_md, prb->ndims,
                         bia_dims.data(), prb->bia_dt, nullptr),
                WARN);
    }

    const auto &scratchpad_md = q(DNNL_ARG_SCRATCHPAD);

    const auto &test_engine = get_test_engine();

    dnn_mem_t src_dt(src_md, test_engine);
    dnn_mem_t wei_dt(wei_md, test_engine);
    dnn_mem_t dst_dt(dst_md, test_engine);
    dnn_mem_t bia_dt;
    if (prb->bia_dt != dnnl_data_type_undef)
        bia_dt = dnn_mem_t(bia_md, test_engine);
    dnn_mem_t scratchpad_dt(scratchpad_md, test_engine);

    const auto fp = dnnl_f32;
    dnn_mem_t src_fp(prb->ndims, src_md.dims, fp, nullptr, test_engine);
    dnn_mem_t wei_fp(prb->ndims, wei_md.dims, fp, nullptr, test_engine);
    dnn_mem_t dst_fp(prb->ndims, dst_md.dims, fp, nullptr, test_engine);
    dnn_mem_t bia_fp;
    if (prb->bia_dt != dnnl_data_type_undef)
        bia_fp = dnn_mem_t(prb->ndims, bia_md.dims, fp, nullptr, test_engine);

    SAFE(fill_data(SRC, prb, src_dt, src_fp, res), WARN);
    SAFE(fill_data(WEI, prb, wei_dt, wei_fp, res), WARN);
    if (prb->attr.post_ops.find(attr_t::post_ops_t::SUM) >= 0)
        SAFE(fill_data(DST, prb, dst_dt, dst_fp, res), WARN);
    if (prb->bia_dt != dnnl_data_type_undef)
        SAFE(fill_data(BIA, prb, bia_dt, bia_fp, res), WARN);

    dnn_mem_t scales;
    dnn_mem_t src_zero_points_m, wei_zero_points_m, dst_zero_points_m;
    const auto &wei_zero_point_val
            = prb->attr.zero_points.get(DNNL_ARG_WEIGHTS).value;
    maybe_prepare_runtime_scales(scales, prb->attr.oscale, prb->n, prb->scales);
    maybe_prepare_runtime_zero_points(
            src_zero_points_m, prb->attr, DNNL_ARG_SRC, prb->k, prb->src_zp);
    maybe_prepare_runtime_zero_points(wei_zero_points_m, prb->attr,
            DNNL_ARG_WEIGHTS, 1, &(wei_zero_point_val));
    maybe_prepare_runtime_zero_points(
            dst_zero_points_m, prb->attr, DNNL_ARG_DST, prb->n, prb->dst_zp);

    std::vector<dnn_mem_t> binary_po_fp, binary_po_dt;
    std::vector<int> binary_po_args;
    SAFE(binary::setup_binary_po(
                 const_pd, binary_po_args, binary_po_dt, binary_po_fp),
            WARN);

    args_t args;

    args.set(DNNL_ARG_SRC, src_dt);
    args.set(DNNL_ARG_WEIGHTS, wei_dt);
    args.set(DNNL_ARG_DST, dst_dt);
    if (prb->bia_dt != dnnl_data_type_undef) args.set(DNNL_ARG_BIAS, bia_dt);
    args.set(DNNL_ARG_SCRATCHPAD, scratchpad_dt);
    args.set(DNNL_ARG_ATTR_OUTPUT_SCALES, scales);
    args.set(DNNL_ARG_ATTR_ZERO_POINTS | DNNL_ARG_SRC, src_zero_points_m);
    args.set(DNNL_ARG_ATTR_ZERO_POINTS | DNNL_ARG_WEIGHTS, wei_zero_points_m);
    args.set(DNNL_ARG_ATTR_ZERO_POINTS | DNNL_ARG_DST, dst_zero_points_m);
    args.set(binary_po_args, binary_po_dt);

    SAFE(execute_and_wait(prim, args), WARN);

    if (is_bench_mode(CORR)) {
        compute_ref(
                test_engine, prb, src_fp, wei_fp, bia_fp, binary_po_fp, dst_fp);
        compare::compare_t cmp;
        cmp.set_threshold(prb->cfg[DST].eps);
        cmp.set_data_kind(DST);
        cmp.set_zero_trust_percent(90.f); // TODO: why so bad filling?
        SAFE(cmp.compare(dst_fp, dst_dt, prb->attr, res), WARN);
    }

    return measure_perf(res->timer, prim, args);
}

} // namespace matmul
