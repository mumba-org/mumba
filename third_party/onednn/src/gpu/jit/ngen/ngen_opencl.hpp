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

#ifndef NGEN_OPENCL_HPP
#define NGEN_OPENCL_HPP

#include <CL/cl.h>

#include <sstream>

#include "ngen_elf.hpp"
#include "ngen_interface.hpp"

#include "npack/neo_packager.hpp"

namespace ngen {


// Exceptions.
class unsupported_opencl_runtime : public std::runtime_error {
public:
    unsupported_opencl_runtime() : std::runtime_error("Unsupported OpenCL runtime.") {}
};
class opencl_error : public std::runtime_error {
public:
    opencl_error(cl_int status_ = 0) : std::runtime_error("An OpenCL error occurred."), status(status_) {}
protected:
    cl_int status;
};

// OpenCL program generator class.
template <HW hw>
class OpenCLCodeGenerator : public ELFCodeGenerator<hw>
{
public:
    inline std::vector<uint8_t> getBinary(cl_context context, cl_device_id device, const std::string &options = "-cl-std=CL2.0");
    inline cl_kernel getKernel(cl_context context, cl_device_id device, const std::string &options = "-cl-std=CL2.0");
    static inline HW detectHW(cl_context context, cl_device_id device);
};

#define NGEN_FORWARD_OPENCL(hw) NGEN_FORWARD_ELF(hw)

namespace detail {

static inline void handleCL(cl_int result)
{
    if (result != CL_SUCCESS)
        throw opencl_error{result};
}

static inline std::vector<uint8_t> getOpenCLCProgramBinary(cl_context context, cl_device_id device, const char *src, const char *options)
{
    cl_int status;

    auto program = clCreateProgramWithSource(context, 1, &src, nullptr, &status);

    detail::handleCL(status);
    if (program == nullptr)
        throw opencl_error();

    detail::handleCL(clBuildProgram(program, 1, &device, options, nullptr, nullptr));

    size_t binarySize;
    detail::handleCL(clGetProgramInfo(program, CL_PROGRAM_BINARY_SIZES, sizeof(binarySize), &binarySize, nullptr));

    std::vector<uint8_t> binary(binarySize);
    const auto *binaryPtr = binary.data();
    detail::handleCL(clGetProgramInfo(program, CL_PROGRAM_BINARIES, sizeof(binaryPtr), &binaryPtr, nullptr));

    detail::handleCL(clReleaseProgram(program));

    return binary;
}

inline bool tryZebin(cl_device_id device)
{
    // Zebin is not yet supported by the OpenCL RT.
    // Once it is, check driver version before attempting to pass in zebin.
    return false;
}

}; /* namespace detail */

template <HW hw>
std::vector<uint8_t> OpenCLCodeGenerator<hw>::getBinary(cl_context context, cl_device_id device, const std::string &options)
{
    using super = ELFCodeGenerator<hw>;
    std::ostringstream dummyCL;
    auto modOptions = options;

    super::interface_.generateDummyCL(dummyCL);
    auto dummyCLString = dummyCL.str();

    auto binary = detail::getOpenCLCProgramBinary(context, device, dummyCLString.c_str(), modOptions.c_str());

    npack::replaceKernel(binary, this->getCode());

    return binary;
}

template <HW hw>
cl_kernel OpenCLCodeGenerator<hw>::getKernel(cl_context context, cl_device_id device, const std::string &options)
{
    using super = ELFCodeGenerator<hw>;
    cl_int status = CL_SUCCESS;
    cl_program program = nullptr;
    bool good = false;

    for (bool legacy : {false, true}) {
        if (!legacy && !detail::tryZebin(device))
            continue;
        auto binary = legacy ? getBinary(context, device) : super::getBinary();

        const auto *binaryPtr = binary.data();
        size_t binarySize = binary.size();
        status = CL_SUCCESS;
        program = clCreateProgramWithBinary(context, 1, &device, &binarySize, &binaryPtr, nullptr, &status);

        if ((program == nullptr) || (status != CL_SUCCESS))
            continue;

        status = clBuildProgram(program, 1, &device, options.c_str(), nullptr, nullptr);

        good = (status == CL_SUCCESS);
        if (good)
            break;
        else
            detail::handleCL(clReleaseProgram(program));
    }

    if (!good)
        throw opencl_error(status);

    auto kernel = clCreateKernel(program, super::interface_.getExternalName().c_str(), &status);
    detail::handleCL(status);
    if (kernel == nullptr)
        throw opencl_error();

    detail::handleCL(clReleaseProgram(program));

    return kernel;
}

template <HW hw>
HW OpenCLCodeGenerator<hw>::detectHW(cl_context context, cl_device_id device)
{
    const char *dummyCL = "kernel void _(){}";
    const char *dummyOptions = "";

    auto binary = detail::getOpenCLCProgramBinary(context, device, dummyCL, dummyOptions);

    return ELFCodeGenerator<hw>::getBinaryArch(binary);
}

} /* namespace ngen */

#endif
