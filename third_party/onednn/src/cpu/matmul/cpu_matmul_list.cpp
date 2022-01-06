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

#include "cpu/cpu_engine.hpp"

#include "cpu/matmul/gemm_bf16_matmul.hpp"
#include "cpu/matmul/gemm_f32_matmul.hpp"
#include "cpu/matmul/gemm_x8s8s32x_matmul.hpp"
#include "cpu/matmul/ref_matmul.hpp"

#if DNNL_X64
#include "cpu/x64/matmul/brgemm_matmul.hpp"
using namespace dnnl::impl::cpu::x64::matmul;
using namespace dnnl::impl::cpu::x64;
#endif

namespace dnnl {
namespace impl {
namespace cpu {

namespace {
using namespace dnnl::impl::data_type;
using namespace dnnl::impl::cpu::matmul;

// clang-format off
const impl_list_item_t impl_list[] = {
        CPU_INSTANCE(gemm_f32_matmul_t)
        CPU_INSTANCE_X64(brgemm_matmul_t<avx512_core_bf16_amx_bf16>)
        CPU_INSTANCE(gemm_bf16_matmul_t<f32>)
        CPU_INSTANCE(gemm_bf16_matmul_t<bf16>)
        CPU_INSTANCE_X64(brgemm_matmul_t<avx512_core_bf16_amx_int8>)
        CPU_INSTANCE(gemm_x8s8s32x_matmul_t<s8, s8, f32>)
        CPU_INSTANCE(gemm_x8s8s32x_matmul_t<s8, s8, s32>)
        CPU_INSTANCE(gemm_x8s8s32x_matmul_t<s8, s8, s8>)
        CPU_INSTANCE(gemm_x8s8s32x_matmul_t<s8, s8, u8>)
        CPU_INSTANCE(gemm_x8s8s32x_matmul_t<u8, s8, f32>)
        CPU_INSTANCE(gemm_x8s8s32x_matmul_t<u8, s8, s32>)
        CPU_INSTANCE(gemm_x8s8s32x_matmul_t<u8, s8, s8>)
        CPU_INSTANCE(gemm_x8s8s32x_matmul_t<u8, s8, u8>)
        CPU_INSTANCE(ref_matmul_t<f32>)
        CPU_INSTANCE(ref_matmul_t<bf16, bf16, f32, f32>)
        CPU_INSTANCE(ref_matmul_t<bf16, bf16, bf16, f32>)
        CPU_INSTANCE(ref_matmul_t<s8, s8, f32, s32>)
        CPU_INSTANCE(ref_matmul_t<s8, s8, s32, s32>)
        CPU_INSTANCE(ref_matmul_t<s8, s8, s8, s32>)
        CPU_INSTANCE(ref_matmul_t<s8, s8, u8, s32>)
        CPU_INSTANCE(ref_matmul_t<u8, s8, f32, s32>)
        CPU_INSTANCE(ref_matmul_t<u8, s8, s32, s32>)
        CPU_INSTANCE(ref_matmul_t<u8, s8, s8, s32>)
        CPU_INSTANCE(ref_matmul_t<u8, s8, u8, s32>)
        /* eol */
        nullptr,
};
// clang-format on
} // namespace

const impl_list_item_t *get_matmul_impl_list(const matmul_desc_t *desc) {
    UNUSED(desc);
    return impl_list;
}

} // namespace cpu
} // namespace impl
} // namespace dnnl
