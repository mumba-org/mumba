// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/path_service.h"
#include "base/posix/global_descriptors.h"
#include "build/build_config.h"
#include "core/shared/common/paths.h"
#include "core/host/child_process_launcher.h"
#include "core/host/child_process_launcher_helper.h"
#include "core/host/child_process_launcher_helper_posix.h"
#include "core/host/sandbox_host_linux.h"
#include "core/host/zygote_host/zygote_communication_linux.h"
#include "core/host/zygote_host/zygote_host_impl_linux.h"
#include "core/host/child_process_launcher_utils.h"
//#include "core/host/host_client.h"
#include "core/shared/common/common_sandbox_support_linux.h"
#include "core/shared/common/client.h"
#include "core/shared/common/switches.h"
#include "core/common/result_codes.h"
#include "core/common/sandboxed_process_launcher_delegate.h"
#include "core/common/zygote_handle.h"
#include "gpu/config/gpu_switches.h"
#include "sandbox/linux/services/credentials.h"
#include "sandbox/linux/services/namespace_sandbox.h"
#include "sandbox/linux/suid/client/setuid_sandbox_host.h"
#include "sandbox/linux/suid/common/sandbox.h"
#include "services/service_manager/sandbox/linux/sandbox_linux.h"
#include "services/service_manager/sandbox/switches.h"


namespace host {
namespace internal {


base::Process LaunchApplicationProcess(const base::CommandLine& cmdline,
                                       const base::LaunchOptions& options) {
  base::FilePath home_dir;
  DCHECK(base::PathService::Get(common::DIR_PROFILE, &home_dir));
  std::string uuid_string = cmdline.GetSwitchValueASCII(switches::kDomainUUID);
  base::FilePath chroot = base::FilePath(home_dir.AppendASCII("default").AppendASCII("apps").AppendASCII(uuid_string).value() + "/");
  DLOG(INFO) << "LaunchApplicationProcess: setting up namespace and chroot at " << chroot;
  base::LaunchOptions new_options = options;
  //new_options.current_directory = base::FilePath("/");
  new_options.chroot_directory = chroot;
  return sandbox::NamespaceSandbox::LaunchProcess(cmdline, new_options);//, chroot);
}

mojo::ScopedPlatformHandle
ChildProcessLauncherHelper::PrepareMojoPipeHandlesOnClientThread() {
  DCHECK_CURRENTLY_ON(client_thread_id_);
  return mojo::ScopedPlatformHandle();
}

void ChildProcessLauncherHelper::BeforeLaunchOnClientThread() {
  DCHECK_CURRENTLY_ON(client_thread_id_);
}

std::unique_ptr<FileMappedForLaunch>
ChildProcessLauncherHelper::GetFilesToMap() {
  DCHECK(CurrentlyOnProcessLauncherTaskRunner());
  return CreateDefaultPosixFilesToMap(child_process_id(), mojo_client_handle(),
                                      true /* include_service_required_files */,
                                      GetProcessType(), command_line());
}

bool ChildProcessLauncherHelper::BeforeLaunchOnLauncherThread(
    bool named_pipe,
    const PosixFileDescriptorInfo& files_to_register,
    base::LaunchOptions* options) {
  if (!named_pipe) {
    // Convert FD mapping to FileHandleMappingVector
    options->fds_to_remap = files_to_register.GetMappingWithIDAdjustment(
        base::GlobalDescriptors::kBaseDescriptor);

    if ((GetProcessType() == switches::kGpuProcess &&
        base::CommandLine::ForCurrentProcess()->HasSwitch(
            switches::kEnableOOPRasterization))) {
      const int sandbox_fd = SandboxHostLinux::GetInstance()->GetChildSocket();
      options->fds_to_remap.push_back(std::make_pair(sandbox_fd, common::GetSandboxFD()));
    }

    if (GetProcessType() == switches::kDomainProcess ||
        GetProcessType() == switches::kApplicationProcess) {
      const int sandbox_fd = SandboxHostLinux::GetInstance()->GetChildSocket();
      options->fds_to_remap.push_back(std::make_pair(sandbox_fd, common::GetSandboxFD()));
    }
  }

  options->environ = delegate_->GetEnvironment();

  return true;
}

ChildProcessLauncherHelper::Process
ChildProcessLauncherHelper::LaunchProcessOnLauncherThread(
    const base::LaunchOptions& options,
    std::unique_ptr<FileMappedForLaunch> files_to_register,
    bool* is_synchronous_launch,
    int* launch_result) {
  *is_synchronous_launch = true;

  // MUMBA: we are disabling zygote, as it does not make sense for shells
  // giving they are not as alike as the renderer process is to each other 

//   common::ZygoteHandle zygote_handle =
//        base::CommandLine::ForCurrentProcess()->HasSwitch(switches::kNoZygote)
//            ? nullptr
//            : delegate_->GetZygote();
  
//   if (zygote_handle) {
//     // TODO(crbug.com/569191): If chrome supported multiple zygotes they could
//     // be created lazily here, or in the delegate GetZygote() implementations.
//     // Additionally, the delegate could provide a UseGenericZygote() method.
   
//     base::ProcessHandle handle = zygote_handle->ForkRequest(
//         command_line()->argv(), files_to_register->GetMapping(),
//         GetProcessType());
//     *launch_result = LAUNCH_RESULT_SUCCESS;

// #if !defined(OS_OPENBSD)
//     if (handle) {
//       // This is just a starting score for a renderer or extension (the
//       // only types of processes that will be started this way).  It will
//       // get adjusted as time goes on.  (This is the same value as
//       // chrome::kLowestRendererOomScore in chrome/chrome_constants.h, but
//       // that's not something we can include here.)
//       const int kLowestRendererOomScore = 300;
//       ZygoteHostImpl::GetInstance()->AdjustRendererOOMScore(
//           handle, kLowestRendererOomScore);
//     }
// #endif // #if !defined(OS_OPENBSD)

//     Process process;
//     process.process = base::Process(handle);
//     process.zygote = zygote_handle;
//     return process;
//   }

  Process process;  
  // the shell process is namespaced on Linux
  // so we need a different path
  if ((command_line()->HasSwitch(switches::kDomainProcess) || 
       command_line()->HasSwitch(switches::kApplicationProcess)) && 
       !base::CommandLine::ForCurrentProcess()->HasSwitch(switches::kNoSandbox))  {
     process.process = LaunchApplicationProcess(*command_line(), options);
     *launch_result = process.process.IsValid() ? LAUNCH_RESULT_SUCCESS
                                              : LAUNCH_RESULT_FAILURE;
     return process;
   } else {
    process.process = base::LaunchProcess(*command_line(), options);
    *launch_result = process.process.IsValid() ? LAUNCH_RESULT_SUCCESS
                                             : LAUNCH_RESULT_FAILURE;
    return process;
  }
  return process;
}

void ChildProcessLauncherHelper::AfterLaunchOnLauncherThread(
    const ChildProcessLauncherHelper::Process& process,
    const base::LaunchOptions& options) {
}

ChildProcessTerminationInfo ChildProcessLauncherHelper::GetTerminationInfo(
    const ChildProcessLauncherHelper::Process& process,
    bool known_dead) {
  ChildProcessTerminationInfo info;
  if (process.zygote) {
    info.status = process.zygote->GetTerminationStatus(
        process.process.Handle(), known_dead, &info.exit_code);
  } else if (known_dead) {
    info.status = base::GetKnownDeadTerminationStatus(process.process.Handle(),
                                                      &info.exit_code);
  } else {
    info.status =
        base::GetTerminationStatus(process.process.Handle(), &info.exit_code);
  }
  return info;
}

// static
bool ChildProcessLauncherHelper::TerminateProcess(const base::Process& process,
                                                  int exit_code) {
  // TODO(https://crbug.com/818244): Determine whether we should also call
  // EnsureProcessTerminated() to make sure of process-exit, and reap it.
  return process.Terminate(exit_code, false);
}

// static
void ChildProcessLauncherHelper::ForceNormalProcessTerminationSync(
    ChildProcessLauncherHelper::Process process) {
  DCHECK(CurrentlyOnProcessLauncherTaskRunner());
  process.process.Terminate(common::RESULT_CODE_NORMAL_EXIT, false);
  // On POSIX, we must additionally reap the child.
  if (process.zygote) {
    // If the renderer was created via a zygote, we have to proxy the reaping
    // through the zygote process.
    process.zygote->EnsureProcessTerminated(process.process.Handle());
  } else {
    base::EnsureProcessTerminated(std::move(process.process));
  }
}

void ChildProcessLauncherHelper::SetProcessPriorityOnLauncherThread(
    base::Process process,
    const ChildProcessLauncherPriority& priority) {
  DCHECK(CurrentlyOnProcessLauncherTaskRunner());
  if (process.CanBackgroundProcesses())
    process.SetProcessBackgrounded(priority.background);
}

// static
void ChildProcessLauncherHelper::SetRegisteredFilesForService(
    const std::string& service_name,
    catalog::RequiredFileMap required_files) {
  SetFilesToShareForServicePosix(service_name, std::move(required_files));
}

// static
void ChildProcessLauncherHelper::ResetRegisteredFilesForTesting() {
  ResetFilesToShareForTestingPosix();
}

// static
base::File OpenFileToShare(const base::FilePath& path,
                           base::MemoryMappedFile::Region* region) {
  base::FilePath exe_dir;
  bool result = base::PathService::Get(base::BasePathKey::DIR_EXE, &exe_dir);
  DCHECK(result);
  base::File file(exe_dir.Append(path),
                  base::File::FLAG_OPEN | base::File::FLAG_READ);
  *region = base::MemoryMappedFile::Region::kWholeFile;
  return file;
}

}  // namespace internal
}  // namespace host
