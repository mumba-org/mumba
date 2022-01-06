/*******************************************************************************
* Copyright 2020-2021 Intel Corporation
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

#include "cpu/x64/brgemm/brgemm.hpp"

#include "common/c_types_map.hpp"
#include "common/nstl.hpp"
#include "common/type_helpers.hpp"
#include "common/utils.hpp"

#include "cpu/platform.hpp"
#include "cpu/x64/cpu_barrier.hpp"
#include "cpu/x64/injectors/jit_uni_postops_injector.hpp"
namespace dnnl {
namespace impl {
namespace cpu {
namespace x64 {

using namespace dnnl::impl::status;
using namespace dnnl::impl::utils;

using namespace prop_kind;
using namespace data_type;

enum {
    decomposition_2x2 = 101,
    decomposition_3x1_3,
    decomposition_3x1_2,
    not_definded,
};

void brgemm_kernel_execute(const brgemm_kernel_t *brg_kernel, int bs,
        const brgemm_batch_element_t *batch, void *ptr_C, void *scratch) {
    brgemm_kernel_params_t brgemm_p;

    brgemm_p.batch = batch;
    brgemm_p.ptr_A = nullptr;
    brgemm_p.ptr_B = nullptr;
    brgemm_p.ptr_C = ptr_C;
    brgemm_p.ptr_D = ptr_C;
    brgemm_p.ptr_buf = scratch;
    brgemm_p.ptr_bias = nullptr;
    brgemm_p.do_post_ops = 0;
    brgemm_p.skip_accm = 0;
    brgemm_p.BS = bs;
    (*brg_kernel)(&brgemm_p);
}

void brgemm_kernel_execute(const brgemm_kernel_t *brg_kernel, int bs,
        const void *addr_A, const void *addr_B,
        const brgemm_batch_element_t *batch, void *ptr_C, void *scratch) {
    brgemm_kernel_params_t brgemm_p;

    brgemm_p.batch = batch;
    brgemm_p.ptr_A = addr_A;
    brgemm_p.ptr_B = addr_B;
    brgemm_p.ptr_C = ptr_C;
    brgemm_p.ptr_D = ptr_C;
    brgemm_p.ptr_buf = scratch;
    brgemm_p.ptr_bias = nullptr;
    brgemm_p.do_post_ops = 0;
    brgemm_p.skip_accm = 0;
    brgemm_p.BS = bs;
    (*brg_kernel)(&brgemm_p);
}

void brgemm_kernel_execute_postops(const brgemm_kernel_t *brg_kernel, int bs,
        const brgemm_batch_element_t *batch, void *ptr_C, void *ptr_D,
        const brgemm_post_ops_data_t &post_ops_data, void *scratch) {
    brgemm_kernel_params_t brgemm_p;

    brgemm_p.batch = batch;
    brgemm_p.ptr_A = nullptr;
    brgemm_p.ptr_B = nullptr;
    brgemm_p.ptr_C = ptr_C;
    brgemm_p.ptr_D = ptr_D;
    brgemm_p.ptr_buf = scratch;
    brgemm_p.ptr_bias = post_ops_data.bias;
    brgemm_p.ptr_scales = post_ops_data.scales;
    brgemm_p.do_post_ops = 1;
    brgemm_p.skip_accm = post_ops_data.skip_accumulation ? 1 : 0;
    brgemm_p.BS = bs;
    brgemm_p.post_ops_binary_rhs_arg_vec = post_ops_data.binary_post_ops_rhs;
    brgemm_p.oc_logical_off = post_ops_data.oc_logical_off;
    brgemm_p.dst_row_logical_off = post_ops_data.dst_row_logical_off;
    brgemm_p.data_C_ptr_ = post_ops_data.data_C_ptr_;
    brgemm_p.first_mb_matrix_addr_off = post_ops_data.first_mb_matrix_addr_off;
    brgemm_p.a_zp_compensations = post_ops_data.a_zp_compensations;
    brgemm_p.b_zp_compensations = post_ops_data.b_zp_compensations;
    brgemm_p.c_zp_values = post_ops_data.c_zp_values;

    (*brg_kernel)(&brgemm_p);
}

void brgemm_kernel_execute_postops(const brgemm_kernel_t *brg_kernel, int bs,
        const void *addr_A, const void *addr_B,
        const brgemm_batch_element_t *batch, void *ptr_C, void *ptr_D,
        const brgemm_post_ops_data_t &post_ops_data, void *scratch) {
    brgemm_kernel_params_t brgemm_p;

    brgemm_p.batch = batch;
    brgemm_p.ptr_A = addr_A;
    brgemm_p.ptr_B = addr_B;
    brgemm_p.ptr_C = ptr_C;
    brgemm_p.ptr_D = ptr_D;
    brgemm_p.ptr_buf = scratch;
    brgemm_p.ptr_bias = post_ops_data.bias;
    brgemm_p.ptr_scales = post_ops_data.scales;
    brgemm_p.do_post_ops = 1;
    brgemm_p.skip_accm = post_ops_data.skip_accumulation ? 1 : 0;
    brgemm_p.BS = bs;
    brgemm_p.post_ops_binary_rhs_arg_vec = post_ops_data.binary_post_ops_rhs;
    brgemm_p.oc_logical_off = post_ops_data.oc_logical_off;
    brgemm_p.dst_row_logical_off = post_ops_data.dst_row_logical_off;
    brgemm_p.first_mb_matrix_addr_off = post_ops_data.first_mb_matrix_addr_off;

    (*brg_kernel)(&brgemm_p);
}

status_t brgemm_desc_init(brgemm_t *brg, cpu_isa_t isa,
        brgemm_batch_kind_t type, impl::data_type_t dt_a,
        impl::data_type_t dt_b, bool transA, bool transB,
        brgemm_layout_t layout, float alpha, float beta, dim_t LDA, dim_t LDB,
        dim_t LDC, dim_t M, dim_t N, dim_t K, const brgemm_strides_t *strides) {
    /*
    m - number of rows of the matrix op(A) and number of rows of the matrix C
    n - number of columns of the matrix op(B) and number of columns of the matrix C
    k - number of columns of the matrix op(A) and number of rows of the matrix op(B)

    Matrices are in row-major layouts:
        A: lda * m, LDA - lda must be at least max(1, k)
        B: ldb * k, LDB - ldb must be at least max(1, n)
        C: ldc * m, LDC - ldc must be at least max(1, n)

    Matrices are in column-major layouts:
        A: lda * k, LDA - lda must be at least max(1, m)
        B: ldb * n, LDB - ldb must be at least max(1, k)
        C: ldc * n, LDC - ldc must be at least max(1, m)
    */
    if (brg == nullptr) return status::invalid_arguments;
    if (transA || transB) return status::unimplemented;

    brg->layout = layout;
    auto is_row_major = [&]() { return brg->layout == brgemm_row_major; };
    if (M <= 0 || N <= 0 || K <= 0) return status::invalid_arguments;
    bool ldx_check = (is_row_major()) ? (LDA < K || LDB < N || LDC < N)
                                      : (LDA < M || LDB < K || LDC < M);
    if (ldx_check) return status::invalid_arguments;

    brg->dt_a = (is_row_major()) ? dt_a : dt_b;
    brg->dt_b = (is_row_major()) ? dt_b : dt_a;

    brg->is_int8 = (one_of(brg->dt_a, data_type::u8, data_type::s8)
            && brg->dt_b == data_type::s8);
    brg->is_bf16
            = (brg->dt_a == data_type::bf16 && brg->dt_b == data_type::bf16);
    brg->is_f32 = (brg->dt_a == data_type::f32 && brg->dt_b == data_type::f32);
    if (!brg->is_int8 && !brg->is_bf16 && !brg->is_f32)
        return status::unimplemented;
    brg->dt_c = (brg->is_int8) ? data_type::s32 : data_type::f32;
    brg->dt_d = brg->dt_c;
    brg->dt_bias = brg->dt_c;

    if (!IMPLICATION(brg->is_f32, mayiuse(avx512_core)))
        return status::unimplemented;
    if (!IMPLICATION(brg->is_bf16, mayiuse(avx512_core_bf16)))
        return status::unimplemented;
    if (!IMPLICATION(brg->is_int8, mayiuse(avx512_core_vnni)))
        return status::unimplemented;

    if (isa != isa_any) {
        if (!one_of(isa, avx512_core, avx512_core_bf16, avx512_core_vnni,
                    avx512_core_bf16_amx_bf16, avx512_core_bf16_amx_int8)) {
            return status::invalid_arguments;
        }
        brg->is_int8_amx = brg->is_bf16_amx = false;
        if (brg->is_int8 && isa == avx512_core_bf16_amx_int8) {
            if (!mayiuse(avx512_core_bf16_amx_int8))
                return status::invalid_arguments;
            brg->is_int8_amx = true;
        }
        if (brg->is_bf16 && isa == avx512_core_bf16_amx_bf16) {
            if (!mayiuse(avx512_core_bf16_amx_bf16))
                return status::invalid_arguments;
            brg->is_bf16_amx = true;
        }
    } else {
        brg->is_int8_amx = brg->is_int8 && mayiuse(avx512_core_bf16_amx_int8);
        brg->is_bf16_amx = brg->is_bf16 && mayiuse(avx512_core_bf16_amx_bf16);
    }
    brg->is_amx = (brg->is_int8_amx || brg->is_bf16_amx);
    brg->req_s8s8_compensation
            = brg->is_int8 && !brg->is_int8_amx && brg->dt_a == data_type::s8;
    brg->LDA = (is_row_major()) ? (int)LDA : (int)LDB;
    brg->LDB = (is_row_major()) ? (int)LDB : (int)LDA;

    brg->LDC = (int)LDC;
    brg->LDD = (int)LDC;

    brg->bcast_dim = (is_row_major()) ? (int)M : (int)N;
    brg->load_dim = (is_row_major()) ? (int)N : (int)M;
    brg->reduce_dim = (int)K;

    brg->with_bias = false;
    brg->with_eltwise = false;
    brg->with_sum = false;
    brg->sum_scale = 0;
    brg->with_scales = false;

    brg->beta = beta;
    brg->alpha = alpha;

    brg->typesize_A = types::data_type_size(brg->dt_a);
    brg->typesize_B = types::data_type_size(brg->dt_b);
    brg->typesize_C = types::data_type_size(brg->dt_c);
    brg->typesize_D = types::data_type_size(brg->dt_d);
    brg->type = type;

    brg->bd_block2 = 0;
    brg->bdb2 = 0;
    brg->bdb2_tail = 0;

    brg->ld_step = brg->rd_step = 4 / brg->typesize_A;

    if (!brg->is_int8_amx && !brg->is_bf16_amx) {
        brg->ld_block = 16;
        brg->ldb = brg->load_dim / brg->ld_block;
        brg->ldb_tail = brg->load_dim % brg->ld_block;

        brg->ld_block2 = 4; // (M < 9) ? 2 : 4 | TODO - fix this for INT8
        brg->ldb2 = brg->ldb / brg->ld_block2;
        brg->ldb2_tail = brg->ldb % brg->ld_block2;

        if (brg->ldb2 == 0) brg->ld_block2 = nstl::max(1, brg->ldb2_tail);
        brg->embd_bcst = !brg->is_int8 && !brg->is_bf16
                && (brg->ldb2_tail <= 1 && brg->ldb2 == 0);

        int ld_block = (brg->ldb2 != 0) ? brg->ld_block2 : brg->ldb2_tail;
        int adj_ld_block = (ld_block == 0) ? (ld_block + 1) : ld_block;

        const int max_avx512_regs = 32;
        const int max_bcst_regs = 1;
        int max_regs = max_avx512_regs - (adj_ld_block + max_bcst_regs);
        int max_block
                = (brg->embd_bcst ? 28
                                  : ((brg->beta == 1.f || brg->beta == 0.f)
                                                  ? max_regs
                                                  : max_regs - 1));
        max_block -= brg->req_s8s8_compensation;
        max_block /= adj_ld_block;
        int min_block = 1;
        float best_bd_block_eff = 0.f;
        brg->bd_block = 1;
        for (int bd_block = max_block; bd_block >= min_block; bd_block--) {
            const auto bd_block_disb
                    = (float)brg->bcast_dim / rnd_up(brg->bcast_dim, bd_block);
            const auto brgemm_microkernel_eff = ((float)(adj_ld_block)*bd_block)
                    / (((adj_ld_block) + bd_block) * max_block);
            const auto bd_block_eff = bd_block_disb * brgemm_microkernel_eff;

            float block_foot_print
                    = (float)brg->typesize_A * (bd_block * brg->reduce_dim);
            if (block_foot_print <= (float)platform::get_per_core_cache_size(1)
                    && (bd_block_eff > best_bd_block_eff)) {
                brg->bd_block = bd_block;
                best_bd_block_eff = bd_block_eff;
            }
        }
        brg->bdb = brg->bcast_dim / brg->bd_block;
        brg->bdb_tail = brg->bcast_dim % brg->bd_block;

        brg->rd_block = 16 / brg->typesize_A;
        brg->rdb = brg->reduce_dim / brg->rd_block;
        brg->rdb_tail = brg->reduce_dim % brg->rd_block;

        brg->is_M_tail = false;
    } else {
        // Blocking configuration for AMX
        const int max_width = 16, min_width = 1;
        brg->ld_block = 16;
        brg->ldb = brg->load_dim / brg->ld_block;
        brg->ldb_tail = brg->load_dim % brg->ld_block;

        auto set_decomposition_by_ld = [&]() {
            if (brg->bd_block2 == 1 && brg->ldb > 0 && brg->ldb_tail == 0) {
                if (brg->ldb % 3 == 0)
                    brg->ld_block2 = 3;
                else if (brg->ldb % 2 == 0)
                    brg->ld_block2 = 2;
                else
                    brg->ld_block2 = 1;
            } else {
                brg->ld_block2
                        = (brg->ldb > 0 && brg->ldb % 2 == 0
                                  && brg->ldb_tail == 0 && brg->bd_block2 < 3)
                        ? 2
                        : 1;
            }
            brg->ldb2 = brg->ldb / brg->ld_block2;
            brg->ldb2_tail = brg->ldb % brg->ld_block2;

            // Re-adjust the bd_block2 if possible
            if (brg->ld_block2 == 1 && !brg->is_M_tail && brg->ldb_tail == 0) {
                brg->bd_block2 = (brg->bdb >= 3) ? 3 : (brg->bdb >= 2) ? 2 : 1;
                brg->bdb2 = brg->bdb / brg->bd_block2;
                brg->bdb2_tail = (brg->bd_block2 == 1)
                        ? brg->bdb
                        : brg->bdb % brg->bd_block2;
            }
        };

        auto try_3x1_decomposition = [&](int width_step) {
            brg->is_M_tail = false;
            if (brg->bcast_dim > (width_step - 1) * max_width
                    && brg->bcast_dim < width_step * max_width
                    && brg->ldb_tail == 0) {
                brg->bd_block = max_width;
                brg->bdb = div_up(brg->bcast_dim, brg->bd_block);
                brg->bdb_tail = brg->bcast_dim % brg->bd_block;

                brg->bd_block2 = width_step;
                brg->bdb2 = brg->bdb / brg->bd_block2;
                brg->bdb2_tail = brg->bdb % brg->bd_block2;
                brg->is_M_tail = true;
            }
            set_decomposition_by_ld();

            return brg->is_M_tail;
        };

        auto try_2x2_decomposition = [&]() {
            for (int m_block = max_width; m_block >= min_width; m_block--) {
                if (brg->bcast_dim % m_block == 0) {
                    brg->bd_block = m_block;
                    break;
                }
            }
            if (brg->bd_block == 1) {
                brg->bd_block = nstl::min(max_width, brg->bcast_dim);
                brg->bdb_tail = brg->bcast_dim % max_width;
                for (int i = max_width; i >= min_width; i--) {
                    int i_tail = brg->bcast_dim % i;
                    if (i_tail > brg->bdb_tail || i_tail == 0) {
                        brg->bd_block = i;
                        brg->bdb_tail = i_tail;
                        if (i_tail == 0) break;
                    }
                }
            }
            brg->bdb = brg->bcast_dim / brg->bd_block;
            brg->bdb_tail = brg->bcast_dim % brg->bd_block;

            brg->bd_block2 = (brg->bdb >= 2) ? 2 : 1;
            brg->bdb2 = brg->bdb / brg->bd_block2;
            brg->bdb2_tail = (brg->bd_block2 == 1) ? brg->bdb
                                                   : brg->bdb % brg->bd_block2;
            brg->is_M_tail = false;

            set_decomposition_by_ld();

            return !(brg->ld_block2 == 1 || brg->bd_block2 == 1
                    || brg->bd_block < 8);
        };

        bool is_decomposition_defined = false;
        for (int i = decomposition_2x2; i != not_definded; i++) {
            switch (i) {
                case decomposition_2x2:
                    is_decomposition_defined = try_2x2_decomposition();
                    break;
                case decomposition_3x1_3:
                    is_decomposition_defined = try_3x1_decomposition(3);
                    break;
                case decomposition_3x1_2:
                    is_decomposition_defined = try_3x1_decomposition(2);
                    break;
                default: assert(!"invalid value"); break;
            };
            if (is_decomposition_defined) break;
        }
        if (!is_decomposition_defined) try_2x2_decomposition();

        brg->rd_block = brg->is_bf16_amx ? 32 : 64;
        brg->rdb = brg->reduce_dim / brg->rd_block;
        brg->rdb_tail = brg->reduce_dim % brg->rd_block;

        // Remove these guard in the future (add tail processing by reduction dimension)
        if (brg->rdb > 0 && brg->rdb_tail) return status::unimplemented;
        if (brg->rdb_tail % ((brg->is_bf16_amx) ? 2 : 4))
            return status::unimplemented;
    }

    if (strides != nullptr) {
        brg->stride_a = strides->stride_a;
        brg->stride_b = strides->stride_b;
    } else {
        brg->stride_a = brg->stride_b = 0;
    }

    return status::success;
}

status_t brgemm_desc_set_postops(brgemm_t *brg, const primitive_attr_t *attr,
        const memory_desc_t *dst_md, int LDD, impl::data_type_t dt_bias) {
    if (!brg || !dst_md) return status::invalid_arguments;

    brg->attr = attr;
    brg->dst_md = dst_md;

    brg->with_bias = (dt_bias == data_type::undef) ? false : true;
    brg->dt_bias = dt_bias;
    brg->typesize_bias = (dt_bias == data_type::undef)
            ? 0
            : types::data_type_size(brg->dt_bias);

    brg->LDD = LDD;
    const auto dt_d = dst_md->data_type;

    if ((brg->dt_a == data_type::u8 && brg->dt_b == data_type::s8)
            && (!one_of(dt_d, data_type::u8, data_type::s8, data_type::s32,
                    data_type::f32))
            && (!one_of(dt_bias, data_type::undef, data_type::u8, data_type::s8,
                    data_type::s32, data_type::f32)))
        return status::unimplemented;
    if ((brg->dt_a == data_type::bf16 && brg->dt_b == data_type::bf16)
            && (!one_of(dt_d, data_type::bf16, data_type::f32))
            && (!one_of(dt_bias, data_type::undef, data_type::bf16,
                    data_type::f32)))
        return status::unimplemented;
    if ((brg->dt_a == data_type::f32 && brg->dt_b == data_type::f32)
            && (!one_of(dt_d, data_type::f32))
            && (!one_of(dt_bias, data_type::undef, data_type::f32)))
        return status::unimplemented;

    brg->dt_d = dt_d;
    brg->typesize_D = types::data_type_size(brg->dt_d);

    if (!brg->attr) return status::success;

    using namespace injector;

    const auto &post_ops = brg->attr->post_ops_;
    const memory_desc_wrapper dst_d(dst_md);

    const int binary_ind = post_ops.find(primitive_kind::binary);
    brg->with_binary = binary_ind != -1;
    const cpu_isa_t isa = get_max_cpu_isa();

    if ((brg->with_binary && !dst_md)
            || !injector::post_ops_ok(
                    post_ops_ok_args_t(isa, {sum, eltwise, binary}, post_ops,
                            &dst_d, false /*sum_at_pos_0_only*/,
                            false /*sum_requires_scale_one*/,
                            {broadcasting_strategy_t::per_oc,
                                    broadcasting_strategy_t::scalar,
                                    broadcasting_strategy_t::per_mb_spatial,
                                    broadcasting_strategy_t::no_broadcast})))
        return status::unimplemented;

    const int sum_idx = post_ops.find(primitive_kind::sum);
    brg->with_sum = sum_idx != -1;
    brg->sum_scale = (sum_idx != -1) ? post_ops.entry_[sum_idx].sum.scale : 0;

    const int eltwise_ind = post_ops.find(primitive_kind::eltwise);
    brg->with_eltwise = eltwise_ind != -1;

    brg->with_scales = !attr->output_scales_.has_default_values();
    if (brg->with_scales) {
        const auto &oscales = brg->attr->output_scales_;
        // Note. the current version supports only two different output scale
        // types:
        //     1) common (mask_ = 0)
        //     2) per_n_dim_scale - broadcast across n dimension;
        //        for convolution and inner product promitives it corresponds
        //        to "per_oc" mask_ = 1 << 1; for matmul - to
        //        mask_ = (1 << (ndims - 1))), where ndims is number of
        //        dimensions for original matmul problem
        // So if oscales.mask_ != 0 (not common) it's assumed here that scale
        // type is per_n_dim_scale and driver which calls brgemm kernel checked
        // that mask has correct value for this case
        brg->is_oc_scale = oscales.mask_ != 0;
    }

    auto init_zp_type
            = [&](brgemm_broadcast_t &zp_type, int mem_arg) -> status_t {
        auto zero_points = attr->zero_points_;

        // common zero point type is supported for now
        if (!zero_points.common(mem_arg)) return status::unimplemented;

        zp_type = zero_points.has_default_values(mem_arg)
                ? brgemm_broadcast_t::none
                : brgemm_broadcast_t::per_tensor;
        return status::success;
    };

    init_zp_type(brg->zp_type_a, DNNL_ARG_SRC);
    init_zp_type(brg->zp_type_b, DNNL_ARG_WEIGHTS);
    init_zp_type(brg->zp_type_c, DNNL_ARG_DST);

    return status::success;
}

status_t brgemm_desc_set_attr(brgemm_t *brg, const brgemm_attr_t &brgattr) {
    if (brg == nullptr) return status::invalid_arguments;

    // negative padding is not supported
    if (brgattr.max_top_vpad < 0 || brgattr.max_bottom_vpad < 0)
        return status::unimplemented;

    // virtual padding is not supported for "amx"
    if ((brgattr.max_top_vpad > 0 || brgattr.max_bottom_vpad > 0)
            && (brg->is_amx))
        return status::unimplemented;

    // virtual padding size is restricted by MAX_VPAD value
    if (brgattr.max_top_vpad > brgemm_t::MAX_VPAD
            || brgattr.max_bottom_vpad > brgemm_t::MAX_VPAD)
        return status::unimplemented;

    // virtual padding is restricted by bd_block size due to
    // brgemm_kernel implementation. TODO: remove this restriction
    if (brgattr.max_top_vpad > brg->bd_block
            || brgattr.max_bottom_vpad > brg->bd_block)
        return status::unimplemented;

    // virtual padding is supported for "brgemm_row_major" layout
    // TODO: remove this restriction
    if ((brgattr.max_top_vpad > 0 || brgattr.max_bottom_vpad > 0)
            && brg->layout != brgemm_row_major)
        return status::unimplemented;

    brg->brgattr = brgattr;
    return status::success;
}

status_t brgemm_kernel_create(
        brgemm_kernel_t **brg_kernel, const brgemm_t &brg) {
    CHECK(safe_ptr_assign<brgemm_kernel_t>(
            *brg_kernel, new brgemm_kernel_t(brg)));
    return (*brg_kernel)->create_kernel();
}

void brgemm_kernel_destroy(brgemm_kernel_t *brg_kernel) {
    delete brg_kernel;
}

status_t brgemm_init_tiles(const brgemm_t &brg, char palette[64]) {
    constexpr int max_palette_size_in_bytes = 64;

    if (!brg.is_amx) return status::unimplemented;

    //TODO: Add support of tail processing by reduction dimension
    int rd_block = (!brg.rdb && brg.rdb_tail) ? brg.rdb_tail : brg.rd_block;

    palette_config_t *buff = (palette_config_t *)(palette);

    char *_tc = (char *)buff;
    for (int i = 0; i < max_palette_size_in_bytes; i++)
        _tc[i] = 0;

    int rd_step = 4 / brg.typesize_A;

    int Ac = brg.typesize_A * rd_block;

    int Bc = brg.ld_block * brg.typesize_B * rd_step;
    int Bc_t = brg.ldb_tail * brg.typesize_B * rd_step;

    int Cc = brg.ld_block * brg.typesize_C;
    int Cc_t = brg.ldb_tail * brg.typesize_C;

    int Br = (brg.typesize_C != 0) ? Ac / brg.typesize_C : 0;

    if (brg.ldb_tail && (brg.ld_block2 > 1)) return status::unimplemented;

    for (int m = 0; m < brg.bd_block2; m++) {
        int Ar = (brg.is_M_tail && m == brg.bd_block2 - 1) ? brg.bdb_tail
                                                           : brg.bd_block;
        tc_configure_tile(buff, brg.get_A_tensor(m), Ar, Ac);
    }

    for (int n = 0; n < brg.ld_block2; n++)
        tc_configure_tile(buff, brg.get_B_tensor(n), Br, Bc);
    if (brg.ldb_tail)
        tc_configure_tile(buff, brg.get_B_tensor(brg.ld_block2), Br, Bc_t);

    for (int m = 0; m < brg.bd_block2; m++) {
        int Cr = (brg.is_M_tail && m == brg.bd_block2 - 1) ? brg.bdb_tail
                                                           : brg.bd_block;
        for (int n = 0; n < brg.ld_block2; n++)
            tc_configure_tile(buff, brg.get_C_tensor(m, n), Cr, Cc);
        if (brg.ldb_tail)
            tc_configure_tile(
                    buff, brg.get_C_tensor(m, brg.ld_block2), Cr, Cc_t);
    }
    buff->palette_id = amx::get_max_palette();

    return status::success;
}

} // namespace x64
} // namespace cpu
} // namespace impl
} // namespace dnnl

// vim: et ts=4 sw=4 cindent cino+=l0,\:4,N-s
