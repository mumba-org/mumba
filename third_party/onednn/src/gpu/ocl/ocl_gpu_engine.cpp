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

#include <CL/cl.h>

#include "gpu/ocl/ocl_gpu_engine.hpp"

#include "common/type_helpers.hpp"
#include "common/utils.hpp"
#include "gpu/compute/kernel_list.hpp"
#include "gpu/ocl/kernel_utils.hpp"
#include "gpu/ocl/ocl_gpu_device_info.hpp"
#include "gpu/ocl/ocl_gpu_engine.hpp"
#include "gpu/ocl/ocl_memory_storage.hpp"
#include "gpu/ocl/ocl_stream.hpp"
#include "gpu/ocl/ocl_utils.hpp"

namespace dnnl {
namespace impl {
namespace gpu {
namespace ocl {

status_t ocl_gpu_engine_t::init() {
    cl_int err = CL_SUCCESS;
    err = clRetainDevice(device_);
    if (err != CL_SUCCESS) {
        device_ = nullptr;
        context_ = nullptr;
    }

    OCL_CHECK(err);

    if (is_user_context_) {
        err = clRetainContext(context_);
        if (err != CL_SUCCESS) context_ = nullptr;
    } else {
        context_
                = clCreateContext(nullptr, 1, &device_, nullptr, nullptr, &err);
    }

    OCL_CHECK(err);

    CHECK(check_device(engine_kind::gpu, device_, context_));
    compute::compute_engine_t::init();

    return status::success;
}

status_t ocl_gpu_engine_t::create_memory_storage(
        memory_storage_t **storage, unsigned flags, size_t size, void *handle) {
    auto _storage = new ocl_memory_storage_t(this);
    if (_storage == nullptr) return status::out_of_memory;
    status_t status = _storage->init(flags, size, handle);
    if (status != status::success) {
        delete _storage;
        return status;
    }
    *storage = _storage;
    return status::success;
}

status_t ocl_gpu_engine_t::create_stream(stream_t **stream, unsigned flags) {
    return ocl_stream_t::create_stream(stream, this, flags);
}

status_t ocl_gpu_engine_t::create_stream(
        stream_t **stream, cl_command_queue queue) {
    return ocl_stream_t::create_stream(stream, this, queue);
}

cl_uint count_lines(const char **code) {
    cl_uint i = 0;
    while (*code) {
        i++;
        code++;
    }
    return i;
}

status_t ocl_gpu_engine_t::create_kernel(
        compute::kernel_t *kernel, jit::jit_generator_base &jitter) const {

    auto binary = jitter.get_binary(context(), device());
    auto kernel_name = jitter.kernel_name();

    ocl_wrapper_t<cl_kernel> ocl_kernel
            = jitter.get_kernel(context(), device());
    std::vector<gpu::compute::scalar_type_t> arg_types;
    CHECK(get_kernel_arg_types(ocl_kernel, &arg_types));

    auto shared_binary = std::make_shared<gpu::compute::binary_t>(binary);

    *kernel = compute::kernel_t(
            new ocl_gpu_kernel_t(shared_binary, kernel_name, arg_types));
    dump_kernel_binary(this, *kernel);

    return status::success;
}

status_t ocl_gpu_engine_t::create_kernels(
        std::vector<compute::kernel_t> *kernels,
        const std::vector<const char *> &kernel_names,
        const compute::kernel_ctx_t &kernel_ctx) const {

    *kernels = std::vector<compute::kernel_t>(kernel_names.size());
    compute::kernel_list_t kernel_list;
    for (size_t i = 0; i < kernels->size(); ++i) {
        if (kernel_names[i]) kernel_list.add(kernel_names[i], &(*kernels)[i]);
    }

    return ocl::create_kernels(this, kernel_list, kernel_ctx);
}

static status_t get_program_binaries(
        cl_program program, std::shared_ptr<compute::binary_t> &binary) {

    // Get the size of the program binary in bytes.
    size_t binary_size = 0;
    cl_int err = clGetProgramInfo(program, CL_PROGRAM_BINARY_SIZES,
            sizeof(binary_size), &binary_size, nullptr);
    OCL_CHECK(err);

    // Binary is not available for the device.
    if (binary_size == 0) return status::runtime_error;

    // Get program binary.
    binary = std::make_shared<compute::binary_t>(binary_size);
    unsigned char *binary_buffer = binary->data();
    err = clGetProgramInfo(
            program, CL_PROGRAM_BINARIES, binary_size, &binary_buffer, nullptr);
    OCL_CHECK(err);

    return status::success;
}

status_t ocl_gpu_engine_t::create_kernels_from_ocl_source(
        std::vector<compute::kernel_t> *kernels,
        const std::vector<const char *> &kernel_names,
        const char **code_strings,
        const compute::kernel_ctx_t &kernel_ctx) const {
    std::string options = kernel_ctx.options();

    // XXX: Update options by adding macros for OpenCL extensions that are not
    // handled properly by the OpenCL runtime
    auto *dev_info
            = utils::downcast<const ocl_gpu_device_info_t *>(device_info());
    options += " " + dev_info->get_cl_ext_options();

    cl_int err;
    cl_program program = clCreateProgramWithSource(
            context(), count_lines(code_strings), code_strings, nullptr, &err);
    OCL_CHECK(err);

    cl_device_id dev = device();
    err = clBuildProgram(program, 1, &dev, options.c_str(), nullptr, nullptr);
    if (err != CL_SUCCESS) {
        // Return error if verbose is not enabled.
        if (get_verbose() == 0) OCL_CHECK(err);

        size_t log_length = 0;
        err = clGetProgramBuildInfo(
                program, dev, CL_PROGRAM_BUILD_LOG, 0, nullptr, &log_length);
        assert(err == CL_SUCCESS);

        std::vector<char> log_buf(log_length);
        err = clGetProgramBuildInfo(program, dev, CL_PROGRAM_BUILD_LOG,
                log_length, log_buf.data(), nullptr);
        assert(err == CL_SUCCESS);
        printf("Error during the build of OpenCL program.\nBuild "
               "log:\n%s\n",
                log_buf.data());
        OCL_CHECK(err);
    }

    std::shared_ptr<compute::binary_t> shared_binary;
    CHECK(get_program_binaries(program, shared_binary));

    *kernels = std::vector<compute::kernel_t>(kernel_names.size());
    for (size_t i = 0; i < kernel_names.size(); ++i) {
        cl_int err;
        ocl_wrapper_t<cl_kernel> ocl_kernel
                = clCreateKernel(program, kernel_names[i], &err);
        OCL_CHECK(err);
        std::vector<gpu::compute::scalar_type_t> arg_types;
        CHECK(get_kernel_arg_types(ocl_kernel, &arg_types));

        (*kernels)[i] = compute::kernel_t(new ocl_gpu_kernel_t(
                shared_binary, kernel_names[i], arg_types));
        dump_kernel_binary(this, (*kernels)[i]);
    }

    OCL_CHECK(clReleaseProgram(program));
    return status::success;
}

std::function<void(void *)> ocl_gpu_engine_t::get_program_list_deleter() const {
    return [](void *p) {
        cl_int err = clReleaseProgram(reinterpret_cast<cl_program>(p));
        assert(err == 0);
        MAYBE_UNUSED(err);
    };
}

status_t ocl_gpu_engine_t::init_device_info() {
    device_info_ = std::make_shared<ocl_gpu_device_info_t>();
    CHECK(device_info_->init(this));
    return status::success;
}

} // namespace ocl
} // namespace gpu
} // namespace impl
} // namespace dnnl
