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

#include "primitive_desc.hpp"
#include "type_helpers.hpp"
#include "utils.hpp"

#include "dnnl_thread.hpp"
#include "engine.hpp"
#include "primitive_hashing.hpp"

namespace dnnl {
namespace impl {
namespace primitive_hashing {

key_t::key_t(const engine_t *engine, const op_desc_t *op_desc,
        const primitive_attr_t *attr, int pd_iterator_offset,
        const std::vector<memory_desc_t> &hint_mds)
    : primitive_kind_(get_pkind(op_desc->kind))
    , op_desc_(op_desc)
    , attr_(attr)
    , pd_iterator_offset_(pd_iterator_offset)
    , impl_nthr_(dnnl_get_max_threads())
    , hint_mds_(hint_mds)
#ifdef DNNL_USE_RT_OBJECTS_IN_PRIMITIVE_CACHE
    , engine_id_(engine->engine_id())
#else
    , engine_kind_(engine->kind())
    , runtime_kind_(engine->runtime_kind())
    , device_id_(engine->device_id())
#endif
    , thread_id_(std::this_thread::get_id()) {
}

key_t::key_t(const primitive_desc_t *pd, const engine_t *engine)
    : key_t(engine, pd->op_desc(), pd->attr(), pd->pd_iterator_offset(),
            pd->hint_mds(false /* is_hint */)) {}

primitive_kind_t key_t::get_pkind(primitive_kind_t pkind) {
    switch (pkind) {
        case primitive_kind::softmax:
        case primitive_kind::logsoftmax: return primitive_kind::softmax;
        default: return pkind;
    }
}

bool key_t::operator==(const key_t &rhs) const {
    DNNL_SHORT_CIRCUIT_SELF_COMPARISON(rhs);
    // clang-format off
    bool ret = true
        // Less expensive comparisons come first
        && primitive_kind_ == rhs.primitive_kind_
#ifdef DNNL_USE_RT_OBJECTS_IN_PRIMITIVE_CACHE
        && engine_id_ == rhs.engine_id_
#else
        && engine_kind_ == rhs.engine_kind_
        && runtime_kind_ == rhs.runtime_kind_
        && device_id_ == rhs.device_id_
#endif
        && hint_mds_.size() == rhs.hint_mds_.size()
        && pd_iterator_offset_ == rhs.pd_iterator_offset_
        && impl_nthr_ == rhs.impl_nthr_
        && (*attr_) == (*rhs.attr_);

    if (!ret) return false;

#define CASE(pkind) \
    case primitive_kind::pkind: \
        ret = cast_to_desc<pkind##_desc_t>(op_desc_) \
                == cast_to_desc<pkind##_desc_t>(rhs.op_desc_); \
        break;

        switch ((int)primitive_kind_) {
            CASE(batch_normalization)
            CASE(binary)
            CASE(concat)
            CASE(convolution)
            CASE(deconvolution)
            CASE(eltwise)
            CASE(gemm)
            CASE(inner_product)
            CASE(layer_normalization)
            CASE(lrn)
            CASE(matmul)
            CASE(pooling)
            CASE(pooling_v2)
            CASE(prelu)
            CASE(reduction)
            CASE(reorder)
            CASE(resampling)
            CASE(rnn)
            CASE(shuffle)
            CASE(softmax)
            CASE(sum)
            CASE(zero_pad)
            default: assert(!"unknown primitive kind");
        }
#undef CASE
    // clang-format on

    if (!ret) return false;

    for (size_t i = 0; i < hint_mds_.size(); ++i)
        if (hint_mds_[i] != rhs.hint_mds_[i]) return false;

    return true;
}

// Combine hash of each memory_desc_t data member
size_t get_md_hash(const memory_desc_t &md) {
    size_t seed = 0;
    seed = get_array_hash(seed, md.dims, md.ndims);
    seed = hash_combine(seed, static_cast<size_t>(md.data_type));
    seed = get_array_hash(seed, md.padded_dims, md.ndims);
    seed = get_array_hash(seed, md.padded_offsets, md.ndims);
    seed = hash_combine(seed, md.offset0);
    seed = hash_combine(seed, static_cast<size_t>(md.format_kind));
    // format desc
    switch (md.format_kind) {
        case format_kind::undef:
        case format_kind::any: break;
        case format_kind::blocked:
            for (int i = 0; i < md.ndims; i++) {
                if (md.dims[i] == 1 && md.padded_dims[i] == 1) continue;
                seed = hash_combine(seed, md.format_desc.blocking.strides[i]);
            }
            seed = hash_combine(seed, md.format_desc.blocking.inner_nblks);
            seed = get_array_hash(seed, md.format_desc.blocking.inner_blks,
                    md.format_desc.blocking.inner_nblks);
            seed = get_array_hash(seed, md.format_desc.blocking.inner_idxs,
                    md.format_desc.blocking.inner_nblks);
            break;
        case format_kind::wino:
            seed = hash_combine(seed,
                    static_cast<size_t>(md.format_desc.wino_desc.wino_format));
            seed = hash_combine(seed, md.format_desc.wino_desc.r);
            seed = hash_combine(seed, md.format_desc.wino_desc.alpha);
            seed = hash_combine(seed, md.format_desc.wino_desc.ic);
            seed = hash_combine(seed, md.format_desc.wino_desc.oc);
            seed = hash_combine(seed, md.format_desc.wino_desc.ic_block);
            seed = hash_combine(seed, md.format_desc.wino_desc.oc_block);
            seed = hash_combine(seed, md.format_desc.wino_desc.ic2_block);
            seed = hash_combine(seed, md.format_desc.wino_desc.oc2_block);
            seed = hash_combine(seed, md.format_desc.wino_desc.adj_scale);
            seed = hash_combine(seed, md.format_desc.wino_desc.size);
            break;
        case format_kind::rnn_packed:
            seed = hash_combine(seed,
                    static_cast<size_t>(md.format_desc.rnn_packed_desc.format));
            seed = hash_combine(seed, md.format_desc.rnn_packed_desc.n_parts);
            seed = hash_combine(seed, md.format_desc.rnn_packed_desc.n);
            seed = hash_combine(seed, md.format_desc.rnn_packed_desc.ldb);
            {
                int n_parts = md.format_desc.rnn_packed_desc.n_parts;
                seed = get_array_hash(
                        seed, md.format_desc.rnn_packed_desc.parts, n_parts);
                seed = get_array_hash(seed,
                        md.format_desc.rnn_packed_desc.part_pack_size, n_parts);
                seed = get_array_hash(seed,
                        md.format_desc.rnn_packed_desc.pack_part, n_parts);
            }
            seed = hash_combine(
                    seed, md.format_desc.rnn_packed_desc.offset_compensation);
            seed = hash_combine(seed, md.format_desc.rnn_packed_desc.size);
            break;
        default: assert(!"unknown format_kind");
    }

    if (md.extra.flags != dnnl_memory_extra_flag_none) {
        seed = hash_combine(seed, md.extra.flags);
        if (md.extra.flags
                & (dnnl_memory_extra_flag_compensation_conv_s8s8
                        | dnnl_memory_extra_flag_rnn_u8s8_compensation)) {
            seed = hash_combine(seed, md.extra.compensation_mask);
        }

        if (md.extra.flags & dnnl_memory_extra_flag_scale_adjust) {
            seed = hash_combine(seed, md.extra.scale_adjust);
        }

        if (md.extra.flags
                & dnnl_memory_extra_flag_compensation_conv_asymmetric_src) {
            seed = hash_combine(seed, md.extra.asymm_compensation_mask);
        }
    }
    // Combined hash for a memory descriptor
    return seed;
}

// Combine hash of each primitive_attr_t data member
size_t get_attr_hash(const primitive_attr_t &attr) {
    size_t seed = 0;
    // scratchpad_mode
    seed = hash_combine(seed, static_cast<size_t>(attr.scratchpad_mode_));

    if (!attr.output_scales_.has_default_values()) {
        // output_scales: mask
        seed = hash_combine(seed, attr.output_scales_.mask_);
        // output_scales: count
        seed = hash_combine(seed, attr.output_scales_.count_);
        // output_scales: scales[:]
        seed = get_array_hash(
                seed, attr.output_scales_.scales_, attr.output_scales_.count_);
    } else if (!attr.scales_.has_default_values()) {
        // go through scales for all arguments
        for (const auto &p : attr.scales_.scales_) {
            seed = hash_combine(seed, p.second.mask_);
            seed = hash_combine(seed, p.second.count_);
            seed = get_array_hash(seed, p.second.scales_, p.second.count_);
        }
    }
    // zero_points
    for (int arg : {DNNL_ARG_SRC, DNNL_ARG_WEIGHTS, DNNL_ARG_DST})
        if (!attr.zero_points_.has_default_values(arg)) {
            dim_t count = 0;
            int mask = 0;
            const int *zero_points = nullptr;
            attr.zero_points_.get(arg, &count, &mask, &zero_points);
            // zero_points: count
            seed = hash_combine(seed, count);
            // zero_points: mask
            seed = hash_combine(seed, mask);
            // zero_points: zero_points[:]
            seed = get_array_hash(seed, zero_points, count);
        }
    // post_ops: entry[:]
    for (int i = 0; i < attr.post_ops_.len(); i++) {
        const auto &entry = attr.post_ops_.entry_[i];
        switch (entry.kind) {
            case primitive_kind::eltwise:
                seed = hash_combine(
                        seed, static_cast<size_t>(entry.eltwise.alg));
                seed = hash_combine(seed, entry.eltwise.scale);
                seed = hash_combine(seed, entry.eltwise.alpha);
                seed = hash_combine(seed, entry.eltwise.beta);
                break;
            case primitive_kind::sum:
                seed = hash_combine(seed, entry.sum.scale);
                seed = hash_combine(seed, static_cast<size_t>(entry.sum.dt));
                break;
            case primitive_kind::convolution:
                seed = hash_combine(
                        seed, static_cast<size_t>(entry.depthwise_conv.stride));
                seed = hash_combine(
                        seed, static_cast<size_t>(entry.depthwise_conv.wei_dt));
                seed = hash_combine(seed,
                        static_cast<size_t>(entry.depthwise_conv.bias_dt));
                seed = hash_combine(
                        seed, static_cast<size_t>(entry.depthwise_conv.dst_dt));
                if (entry.depthwise_conv.scales) {
                    seed = hash_combine(seed, entry.depthwise_conv.mask);
                    seed = hash_combine(seed, entry.depthwise_conv.count);
                    seed = get_array_hash(seed, entry.depthwise_conv.scales,
                            entry.depthwise_conv.count);
                }
                break;
            case primitive_kind::binary:
                seed = hash_combine(
                        seed, static_cast<size_t>(entry.binary.alg));
                seed = hash_combine(seed, get_md_hash(entry.binary.src1_desc));
                break;
            default: assert(!"unknown post_op");
        }
    }
    // rnn_data_qparams: scale, shift
    seed = hash_combine(seed, attr.rnn_data_qparams_.scale_);
    seed = hash_combine(seed, attr.rnn_data_qparams_.shift_);
    if (!attr.rnn_weights_qparams_.has_default_values()) {
        // rnn_weights_qparams: mask
        seed = hash_combine(seed, attr.rnn_weights_qparams_.mask_);
        // rnn_weights_qparams: count
        seed = hash_combine(seed, attr.rnn_weights_qparams_.count_);
        // rnn_weights_qparams: scales[:]
        seed = get_array_hash(seed, attr.rnn_weights_qparams_.scales_,
                attr.rnn_weights_qparams_.count_);
    }
    // Combined hash for attributes
    return seed;
}

// Functions that compute hash for different op_descs
size_t get_desc_hash(const concat_desc_t &desc) {
    size_t seed = 0;
    // Kinds
    seed = hash_combine(seed, static_cast<size_t>(desc.primitive_kind));
    // Memory descriptors
    seed = hash_combine(seed, get_md_hash(*desc.dst_md));
    // N
    seed = hash_combine(seed, desc.n);
    // Concat dimension
    seed = hash_combine(seed, desc.concat_dimension);
    // Array of mds
    seed = get_array_hash(seed, desc.src_mds, desc.n);
    // Combined hash for concat desc
    return seed;
}

size_t get_desc_hash(const batch_normalization_desc_t &desc) {
    size_t seed = 0;
    // Kinds
    seed = hash_combine(seed, static_cast<size_t>(desc.primitive_kind));
    seed = hash_combine(seed, static_cast<size_t>(desc.prop_kind));
    // Memory descriptors
    seed = hash_combine(seed, get_md_hash(desc.data_desc));
    seed = hash_combine(seed, get_md_hash(desc.diff_data_desc));
    seed = hash_combine(seed, get_md_hash(desc.data_scaleshift_desc));
    seed = hash_combine(seed, get_md_hash(desc.diff_data_scaleshift_desc));
    seed = hash_combine(seed, get_md_hash(desc.stat_desc));
    // Epsilon
    seed = hash_combine(seed, desc.batch_norm_epsilon);
    // Flags
    seed = hash_combine(seed, desc.flags);
    // Combined hash for batch normalization desc
    return seed;
}

size_t get_desc_hash(const binary_desc_t &desc) {
    size_t seed = 0;
    // Kinds
    seed = hash_combine(seed, static_cast<size_t>(desc.primitive_kind));
    seed = hash_combine(seed, static_cast<size_t>(desc.alg_kind));
    // Memory descriptors
    seed = hash_combine(seed, get_md_hash(desc.src_desc[0]));
    seed = hash_combine(seed, get_md_hash(desc.src_desc[1]));
    seed = hash_combine(seed, get_md_hash(desc.dst_desc));
    // Combined hash for binary op desc
    return seed;
}

// (De-)Convolution
size_t get_desc_hash(const convolution_desc_t &desc) {
    size_t seed = 0;
    // Kinds
    seed = hash_combine(seed, static_cast<size_t>(desc.primitive_kind));
    seed = hash_combine(seed, static_cast<size_t>(desc.prop_kind));
    seed = hash_combine(seed, static_cast<size_t>(desc.alg_kind));
    // Memory descriptors
    seed = hash_combine(seed, get_md_hash(desc.src_desc));
    seed = hash_combine(seed, get_md_hash(desc.diff_src_desc));
    seed = hash_combine(seed, get_md_hash(desc.weights_desc));
    seed = hash_combine(seed, get_md_hash(desc.diff_weights_desc));
    seed = hash_combine(seed, get_md_hash(desc.bias_desc));
    seed = hash_combine(seed, get_md_hash(desc.diff_bias_desc));
    seed = hash_combine(seed, get_md_hash(desc.dst_desc));
    seed = hash_combine(seed, get_md_hash(desc.diff_dst_desc));
    // Strides, dilates, padding
    seed = get_array_hash(seed, desc.strides, DNNL_MAX_NDIMS);
    seed = get_array_hash(seed, desc.dilates, DNNL_MAX_NDIMS);
    seed = get_array_hash(seed, desc.padding[0], DNNL_MAX_NDIMS);
    seed = get_array_hash(seed, desc.padding[1], DNNL_MAX_NDIMS);
    // Accumulator type
    seed = hash_combine(seed, static_cast<size_t>(desc.accum_data_type));
    // Combined hash for (de-)convolution desc
    return seed;
}

// Eltwise
size_t get_desc_hash(const eltwise_desc_t &desc) {
    size_t seed = 0;
    // Kinds
    seed = hash_combine(seed, static_cast<size_t>(desc.primitive_kind));
    seed = hash_combine(seed, static_cast<size_t>(desc.prop_kind));
    seed = hash_combine(seed, static_cast<size_t>(desc.alg_kind));
    // Memory descriptors
    seed = hash_combine(seed, get_md_hash(desc.data_desc));
    seed = hash_combine(seed, get_md_hash(desc.diff_data_desc));
    // Alpha, beta
    seed = hash_combine(seed, desc.alpha);
    seed = hash_combine(seed, desc.beta);
    // Combined hash for eltwise desc
    return seed;
}

size_t get_desc_hash(const gemm_desc_t &desc) {
    size_t seed = 0;
    // Kinds
    seed = hash_combine(seed, static_cast<size_t>(desc.primitive_kind));
    seed = hash_combine(seed, get_md_hash(desc.a_desc));
    seed = hash_combine(seed, get_md_hash(desc.b_desc));
    seed = hash_combine(seed, get_md_hash(desc.c_desc));
    seed = hash_combine(seed, get_md_hash(desc.bias_desc));
    // Accumulator type
    seed = hash_combine(seed, static_cast<size_t>(desc.acc_type));
    // Combined hash for gemm desc
    return seed;
}

size_t get_desc_hash(const inner_product_desc_t &desc) {
    size_t seed = 0;
    // Kinds
    seed = hash_combine(seed, static_cast<size_t>(desc.primitive_kind));
    seed = hash_combine(seed, static_cast<size_t>(desc.prop_kind));
    // Memory descriptors
    seed = hash_combine(seed, get_md_hash(desc.src_desc));
    seed = hash_combine(seed, get_md_hash(desc.diff_src_desc));
    seed = hash_combine(seed, get_md_hash(desc.weights_desc));
    seed = hash_combine(seed, get_md_hash(desc.diff_weights_desc));
    seed = hash_combine(seed, get_md_hash(desc.bias_desc));
    seed = hash_combine(seed, get_md_hash(desc.diff_bias_desc));
    seed = hash_combine(seed, get_md_hash(desc.dst_desc));
    seed = hash_combine(seed, get_md_hash(desc.diff_dst_desc));
    // Accumulator type
    seed = hash_combine(seed, static_cast<size_t>(desc.accum_data_type));
    // Combined hash for inner_product desc
    return seed;
}

// Layer normalization
size_t get_desc_hash(const layer_normalization_desc_t &desc) {
    size_t seed = 0;
    // Kinds
    seed = hash_combine(seed, static_cast<size_t>(desc.primitive_kind));
    seed = hash_combine(seed, static_cast<size_t>(desc.prop_kind));
    // Memory descriptors
    seed = hash_combine(seed, get_md_hash(desc.data_desc));
    seed = hash_combine(seed, get_md_hash(desc.diff_data_desc));
    seed = hash_combine(seed, get_md_hash(desc.data_scaleshift_desc));
    seed = hash_combine(seed, get_md_hash(desc.diff_data_scaleshift_desc));
    seed = hash_combine(seed, get_md_hash(desc.stat_desc));
    // Epsilon
    seed = hash_combine(seed, desc.layer_norm_epsilon);
    // Flags
    seed = hash_combine(seed, desc.flags);
    // Combined hash for layer_normalization desc
    return seed;
}

size_t get_desc_hash(const lrn_desc_t &desc) {
    size_t seed = 0;
    // Kinds
    seed = hash_combine(seed, static_cast<size_t>(desc.primitive_kind));
    seed = hash_combine(seed, static_cast<size_t>(desc.prop_kind));
    seed = hash_combine(seed, static_cast<size_t>(desc.alg_kind));
    // Memory descriptors
    seed = hash_combine(seed, get_md_hash(desc.data_desc));
    seed = hash_combine(seed, get_md_hash(desc.diff_data_desc));
    // Local size
    seed = hash_combine(seed, desc.local_size);
    // Alpha, beta
    seed = hash_combine(seed, desc.lrn_alpha);
    seed = hash_combine(seed, desc.lrn_beta);
    // k
    seed = hash_combine(seed, desc.lrn_k);
    // Combined hash for lrn desc
    return seed;
}

size_t get_desc_hash(const matmul_desc_t &desc) {
    size_t seed = 0;
    // Kinds
    seed = hash_combine(seed, static_cast<size_t>(desc.primitive_kind));
    // Memory descriptors
    seed = hash_combine(seed, get_md_hash(desc.src_desc));
    seed = hash_combine(seed, get_md_hash(desc.weights_desc));
    seed = hash_combine(seed, get_md_hash(desc.bias_desc));
    seed = hash_combine(seed, get_md_hash(desc.dst_desc));
    // Accumulator type
    seed = hash_combine(seed, static_cast<size_t>(desc.accum_data_type));
    // Combined hash for matmul op desc
    return seed;
}

size_t get_desc_hash(const pooling_desc_t &desc) {
    size_t seed = 0;
    // Kinds
    seed = hash_combine(seed, static_cast<size_t>(desc.primitive_kind));
    seed = hash_combine(seed, static_cast<size_t>(desc.prop_kind));
    seed = hash_combine(seed, static_cast<size_t>(desc.alg_kind));
    // Memory descriptors
    seed = hash_combine(seed, get_md_hash(desc.src_desc));
    seed = hash_combine(seed, get_md_hash(desc.diff_src_desc));
    seed = hash_combine(seed, get_md_hash(desc.dst_desc));
    seed = hash_combine(seed, get_md_hash(desc.diff_dst_desc));
    // Strides, dilates, padding
    seed = get_array_hash(seed, desc.strides, DNNL_MAX_NDIMS);
    seed = get_array_hash(seed, desc.kernel, DNNL_MAX_NDIMS);
    seed = get_array_hash(seed, desc.padding[0], DNNL_MAX_NDIMS);
    seed = get_array_hash(seed, desc.padding[1], DNNL_MAX_NDIMS);
    // Accumulator type
    seed = hash_combine(seed, static_cast<size_t>(desc.accum_data_type));
    // Combined hash for pooling desc
    return seed;
}

size_t get_desc_hash(const pooling_v2_desc_t &desc) {
    const auto &v1_desc = *reinterpret_cast<const pooling_desc_t *>(&desc);
    size_t seed = get_desc_hash(v1_desc);
    seed = get_array_hash(seed, desc.dilation, DNNL_MAX_NDIMS);
    return seed;
}

size_t get_desc_hash(const prelu_desc_t &desc) {
    size_t seed = 0;
    // Kinds
    seed = hash_combine(seed, static_cast<size_t>(desc.primitive_kind));
    seed = hash_combine(seed, static_cast<size_t>(desc.prop_kind));
    // Memory descriptors
    seed = hash_combine(seed, get_md_hash(desc.data_desc));
    seed = hash_combine(seed, get_md_hash(desc.diff_data_desc));
    seed = hash_combine(seed, get_md_hash(desc.weights_desc));
    seed = hash_combine(seed, get_md_hash(desc.diff_weights_desc));
    // Combined hash for pooling desc
    return seed;
}

size_t get_desc_hash(const reduction_desc_t &desc) {
    size_t seed = 0;
    // Kinds
    seed = hash_combine(seed, static_cast<size_t>(desc.primitive_kind));
    seed = hash_combine(seed, static_cast<size_t>(desc.alg_kind));
    // Memory descriptors
    seed = hash_combine(seed, get_md_hash(desc.src_desc));
    seed = hash_combine(seed, get_md_hash(desc.dst_desc));
    // P, eps
    seed = hash_combine(seed, desc.p);
    seed = hash_combine(seed, desc.eps);
    // Combined hash for reduction desc
    return seed;
}

size_t get_desc_hash(const reorder_desc_t &desc) {
    size_t seed = 0;
    // Kinds
    seed = hash_combine(seed, static_cast<size_t>(desc.primitive_kind));
    // Memory descriptors
    seed = hash_combine(seed, get_md_hash(*desc.src_md));
    seed = hash_combine(seed, get_md_hash(*desc.dst_md));
    // Kinds of source and destination engines
    seed = hash_combine(seed, static_cast<size_t>(desc.src_engine_kind));
    seed = hash_combine(seed, static_cast<size_t>(desc.dst_engine_kind));
    seed = hash_combine(seed, desc.is_cross_engine);
    // Combined hash for reorder desc
    return seed;
}

size_t get_desc_hash(const resampling_desc_t &desc) {
    size_t seed = 0;
    // Kinds
    seed = hash_combine(seed, static_cast<size_t>(desc.primitive_kind));
    seed = hash_combine(seed, static_cast<size_t>(desc.alg_kind));
    // Memory descriptors
    seed = hash_combine(seed, get_md_hash(desc.src_desc));
    seed = hash_combine(seed, get_md_hash(desc.diff_src_desc));
    seed = hash_combine(seed, get_md_hash(desc.dst_desc));
    seed = hash_combine(seed, get_md_hash(desc.diff_dst_desc));
    // Factors
    seed = get_array_hash(seed, desc.factors, DNNL_MAX_NDIMS);
    // Combined hash for resampling op desc
    return seed;
}

size_t get_desc_hash(const rnn_desc_t &desc) {
    size_t seed = 0;
    // Kinds
    seed = hash_combine(seed, static_cast<size_t>(desc.primitive_kind));
    seed = hash_combine(seed, static_cast<size_t>(desc.prop_kind));
    seed = hash_combine(seed, static_cast<size_t>(desc.cell_kind));
    seed = hash_combine(seed, static_cast<size_t>(desc.direction));
    // Memory descriptors
    seed = hash_combine(seed, get_md_hash(desc.src_layer_desc));
    seed = hash_combine(seed, get_md_hash(desc.src_iter_desc));
    seed = hash_combine(seed, get_md_hash(desc.src_iter_c_desc));
    seed = hash_combine(seed, get_md_hash(desc.weights_layer_desc));
    seed = hash_combine(seed, get_md_hash(desc.weights_iter_desc));
    seed = hash_combine(seed, get_md_hash(desc.bias_desc));
    seed = hash_combine(seed, get_md_hash(desc.dst_layer_desc));
    seed = hash_combine(seed, get_md_hash(desc.dst_iter_desc));
    seed = hash_combine(seed, get_md_hash(desc.dst_iter_c_desc));
    seed = hash_combine(seed, get_md_hash(desc.weights_peephole_desc));
    seed = hash_combine(seed, get_md_hash(desc.weights_projection_desc));
    seed = hash_combine(seed, get_md_hash(desc.diff_src_layer_desc));
    seed = hash_combine(seed, get_md_hash(desc.diff_src_iter_desc));
    seed = hash_combine(seed, get_md_hash(desc.diff_src_iter_c_desc));
    seed = hash_combine(seed, get_md_hash(desc.diff_weights_layer_desc));
    seed = hash_combine(seed, get_md_hash(desc.diff_weights_iter_desc));
    seed = hash_combine(seed, get_md_hash(desc.diff_bias_desc));
    seed = hash_combine(seed, get_md_hash(desc.diff_dst_layer_desc));
    seed = hash_combine(seed, get_md_hash(desc.diff_dst_iter_desc));
    seed = hash_combine(seed, get_md_hash(desc.diff_dst_iter_c_desc));
    seed = hash_combine(seed, get_md_hash(desc.diff_weights_peephole_desc));
    seed = hash_combine(seed, get_md_hash(desc.diff_weights_projection_desc));
    // Flags
    seed = hash_combine(seed, desc.flags);
    // Activation kind
    seed = hash_combine(seed, static_cast<size_t>(desc.activation_kind));
    // Alpha, beta
    seed = hash_combine(seed, desc.alpha);
    seed = hash_combine(seed, desc.beta);
    // Combined hash for rnn desc
    return seed;
}

// Shuffle
size_t get_desc_hash(const shuffle_desc_t &desc) {
    size_t seed = 0;
    // Kinds
    seed = hash_combine(seed, static_cast<size_t>(desc.primitive_kind));
    seed = hash_combine(seed, static_cast<size_t>(desc.prop_kind));
    // Memory descriptors
    seed = hash_combine(seed, get_md_hash(desc.data_desc));
    // Axis
    seed = hash_combine(seed, desc.axis);
    // Groupe size
    seed = hash_combine(seed, desc.group_size);
    // Combined hash for shuffle desc
    return seed;
}

size_t get_desc_hash(const softmax_desc_t &desc) {
    size_t seed = 0;
    // Kinds
    seed = hash_combine(seed, static_cast<size_t>(desc.primitive_kind));
    seed = hash_combine(seed, static_cast<size_t>(desc.prop_kind));
    // Memory descriptors
    seed = hash_combine(seed, get_md_hash(desc.data_desc));
    seed = hash_combine(seed, get_md_hash(desc.diff_desc));
    // Axis
    seed = hash_combine(seed, desc.softmax_axis);
    // Combined hash for softmax desc
    return seed;
}

size_t get_desc_hash(const sum_desc_t &desc) {
    size_t seed = 0;
    // Kinds
    seed = hash_combine(seed, static_cast<size_t>(desc.primitive_kind));
    // Memory descriptors
    seed = hash_combine(seed, get_md_hash(*desc.dst_md));
    // N
    seed = hash_combine(seed, desc.n);
    // Scales
    if (desc.scales) { seed = get_array_hash(seed, desc.scales, desc.n); }
    // Array of mds
    seed = get_array_hash(seed, desc.src_mds, desc.n);
    // Combined hash for sum desc
    return seed;
}

size_t get_desc_hash(const zero_pad_desc_t &desc) {
    size_t seed = 0;
    // Kinds
    seed = hash_combine(seed, static_cast<size_t>(desc.primitive_kind));
    return seed;
}

} // namespace primitive_hashing
} // namespace impl
} // namespace dnnl
