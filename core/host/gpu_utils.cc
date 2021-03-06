// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/gpu_utils.h"

#include <string>

#include "base/command_line.h"
#include "base/single_thread_task_runner.h"
#include "base/strings/string_number_conversions.h"
#include "build/build_config.h"
#include "core/host/gpu/gpu_process_host.h"
#include "core/shared/common/content_features.h"
#include "core/shared/common/switches.h"
#include "gpu/config/gpu_switches.h"
#include "gpu/command_buffer/service/service_utils.h"
#include "media/media_buildflags.h"

namespace {

#if defined(OS_WIN)
bool GetUintFromSwitch(const base::CommandLine* command_line,
                       const base::StringPiece& switch_string,
                       uint32_t* value) {
  if (!command_line->HasSwitch(switch_string))
    return false;
  std::string switch_value(command_line->GetSwitchValueASCII(switch_string));
  return base::StringToUint(switch_value, value);
}
#endif  // defined(OS_WIN)

void RunTaskOnTaskRunner(
    scoped_refptr<base::SingleThreadTaskRunner> task_runner,
    const base::Closure& callback) {
  task_runner->PostTask(FROM_HERE, callback);
}

void StopGpuProcessImpl(const base::Closure& callback,
                        host::GpuProcessHost* host) {
  if (host)
    host->gpu_service()->Stop(callback);
  else
    callback.Run();
}

}  // namespace

namespace host {

const gpu::GpuPreferences GetGpuPreferencesFromCommandLine() {
  DCHECK(base::CommandLine::InitializedForCurrentProcess());
  const base::CommandLine* command_line =
      base::CommandLine::ForCurrentProcess();
  gpu::GpuPreferences gpu_preferences =
      gpu::gles2::ParseGpuPreferences(command_line);
  gpu_preferences.single_process =
      command_line->HasSwitch(switches::kSingleProcess);
  gpu_preferences.in_process_gpu =
      command_line->HasSwitch(switches::kInProcessGPU);
  gpu_preferences.disable_accelerated_video_decode =
      command_line->HasSwitch(switches::kDisableAcceleratedVideoDecode);
  gpu_preferences.disable_accelerated_video_encode =
      command_line->HasSwitch(switches::kDisableAcceleratedVideoEncode);
#if defined(OS_WIN)
  uint32_t enable_accelerated_vpx_decode_val =
      gpu::GpuPreferences::VPX_VENDOR_MICROSOFT;
  if (GetUintFromSwitch(command_line, switches::kEnableAcceleratedVpxDecode,
                        &enable_accelerated_vpx_decode_val)) {
    gpu_preferences.enable_accelerated_vpx_decode =
        static_cast<gpu::GpuPreferences::VpxDecodeVendors>(
            enable_accelerated_vpx_decode_val);
  }
  gpu_preferences.enable_low_latency_dxva =
      !command_line->HasSwitch(switches::kDisableLowLatencyDxva);
  gpu_preferences.enable_zero_copy_dxgi_video =
      !command_line->HasSwitch(switches::kDisableZeroCopyDxgiVideo);
  gpu_preferences.enable_nv12_dxgi_video =
      !command_line->HasSwitch(switches::kDisableNv12DxgiVideo);
#endif
  gpu_preferences.disable_software_rasterizer =
      command_line->HasSwitch(switches::kDisableSoftwareRasterizer);
  gpu_preferences.log_gpu_control_list_decisions =
      command_line->HasSwitch(switches::kLogGpuControlListDecisions);
  gpu_preferences.gpu_startup_dialog =
      command_line->HasSwitch(switches::kGpuStartupDialog);
  gpu_preferences.disable_gpu_watchdog =
      command_line->HasSwitch(switches::kDisableGpuWatchdog) ||
      (gpu_preferences.single_process || gpu_preferences.in_process_gpu);
  gpu_preferences.gpu_sandbox_start_early =
      command_line->HasSwitch(switches::kGpuSandboxStartEarly);
  // Some of these preferences are set or adjusted in
  // GpuDataManagerImplPrivate::AppendGpuCommandLine.
  return gpu_preferences;
}

void StopGpuProcess(const base::Closure& callback) {
  GpuProcessHost::CallOnIO(
      GpuProcessHost::GPU_PROCESS_KIND_SANDBOXED,
      false /* force_create */,
      base::Bind(&StopGpuProcessImpl,
                 base::Bind(RunTaskOnTaskRunner,
                            base::ThreadTaskRunnerHandle::Get(), callback)));
}

}  // namespace host
