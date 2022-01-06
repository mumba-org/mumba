Inspecting JIT Code {#dev_guide_inspecting_jit}
===============================================

oneDNN uses just-in-time compilation (JIT) to generate optimal code
for some functions based on input parameters and instruction set supported
by the system. The library provides a mechanism to save the generated code
into a file for inspection.

This behavior can be enabled with `DNNL_JIT_DUMP` environment variable
or @ref dnnl_set_jit_dump function.

| Value           | Behavior
| :----           | :----
| **0**           | JIT dump is disabled (default)
| any other value | JIT dump is enabled

The function setting takes precedence over the environment variable.

# Example (CPU)

~~~sh
    $ DNNL_JIT_DUMP=1 ./cnn-inference-f32-cpp
~~~

This will produce the following output files if running on a CPU supporting
Intel(R) Advanced Vector Extensions 2 (Intel(R) AVX2):

~~~sh
    dnnl_dump_cpu_jit_avx2_conv_fwd_kernel_f32.1.bin
    ...
    dnnl_dump_cpu_jit_avx_gemv_t_f32_kern.30.bin
~~~

Use any disassembler to view the code. For example:
- `objdump -D -b binary -mi386:x86-64 file.bin`;
- `xed -64 -ir file.bin`

[XED](https://github.com/intelxed/xed) is a decoder tool available as part as
[Intel Software Development Emulator (Intel SDE)](https://software.intel.com/content/www/us/en/develop/articles/intel-software-development-emulator).

# Example (GPU)

~~~sh
    $ DNNL_JIT_DUMP=1 ./simple-net-cpp gpu
~~~

This will produce the following output files if running on Intel(R) Processor Graphics Gen9:

~~~sh
    dnnl_dump_gpu_simple_reorder.0.bin
    dnnl_dump_gpu_gen9_conv_fwd.1.bin
    ...
~~~

Use Intel GPU ISA disassembler to disassemble a kernel:

- `iga64 -d -p=9 file.bin` (usage: `-p=<PLATFORM>`)

Links:
- [Building an Intel GPU ISA Disassembler](https://github.com/intel/opencl-intercept-layer/blob/master/docs/kernel_isa_gpu.md#building-an-intel-gpu-isa-disassembler)
- [Introduction to GEN Assembly](https://software.intel.com/content/www/us/en/develop/articles/introduction-to-gen-assembly.html)
