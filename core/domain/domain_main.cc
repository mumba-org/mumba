// Copyright 2017 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/domain/domain_main.h"

#include "base/at_exit.h"
#include "base/template_util.h"
#include "base/command_line.h"
#include "base/path_service.h"
#include "base/files/file_path.h"
#include "base/files/file_enumerator.h"
#include "base/logging.h"
#include "base/message_loop/message_loop.h"
#include "base/threading/thread_task_runner_handle.h"
#include "base/threading/thread_restrictions.h"
#include "base/strings/string_number_conversions.h"
#include "core/common/main_params.h"
#include "core/shared/common/switches.h"
#include "core/shared/common/paths.h"
#include "core/domain/domain_process.h"
#include "core/domain/domain_main_thread.h"
#include "core/domain/domain_main_platform_delegate.h"
#include "third_party/blink/public/platform/scheduler/web_main_thread_scheduler.h"

#if defined(OS_LINUX)
#include "core/shared/common/common_sandbox_support_linux.h"
#include "services/service_manager/sandbox/linux/sandbox_linux.h"
#include "sandbox/linux/bpf_dsl/policy.h"
#include "sandbox/linux/services/credentials.h"
#include "sandbox/linux/syscall_broker/broker_command.h"
#include "sandbox/linux/syscall_broker/broker_file_permission.h"
#include "sandbox/linux/syscall_broker/broker_process.h"
#include "sandbox/linux/services/namespace_sandbox.h"
#include "services/service_manager/embedder/set_process_title.h"
#include "services/service_manager/sandbox/linux/bpf_cros_amd_gpu_policy_linux.h"
#include "services/service_manager/sandbox/linux/bpf_cros_arm_gpu_policy_linux.h"
#include "services/service_manager/sandbox/linux/bpf_gpu_policy_linux.h"
#include "services/service_manager/sandbox/linux/sandbox_linux.h"
#include "sandbox/linux/services/proc_util.h"

using sandbox::bpf_dsl::Policy;
using sandbox::syscall_broker::BrokerFilePermission;
using sandbox::syscall_broker::BrokerProcess;
#endif

#if defined(OS_WIN)
#include "sandbox/win/src/target_services.h"
#include "services/service_manager/sandbox/win/sandbox_win.h"
#endif

namespace domain {

namespace {

#if defined(OS_LINUX)

void AddApplicationDirectoriesAndFiles(
    const base::FilePath& root_dir,
    std::vector<BrokerFilePermission>* permissions,
    const service_manager::SandboxSeccompBPF::Options& options) {
  // if (options.accelerated_video_decode_enabled) {
  //   // Device nodes for V4L2 video decode accelerator drivers.
  //   static const base::FilePath::CharType kDevicePath[] =
  //       FILE_PATH_LITERAL("/dev/");
  //   static const base::FilePath::CharType kVideoDecPattern[] = "video-dec[0-9]";
  //   base::FileEnumerator enumerator(base::FilePath(kDevicePath), false,
  //                                   base::FileEnumerator::FILES,
  //                                   base::FilePath(kVideoDecPattern).value());
  //   for (base::FilePath name = enumerator.Next(); !name.empty();
  //        name = enumerator.Next())
  //     permissions->push_back(BrokerFilePermission::ReadWrite(name.value()));
  // }

  // if (options.accelerated_video_encode_enabled) {
  //   // Device node for V4L2 video encode accelerator drivers.
  //   static const char kDevVideoEncPath[] = "/dev/video-enc";
  //   permissions->push_back(BrokerFilePermission::ReadWrite(kDevVideoEncPath));
  // }

  // Device node for V4L2 JPEG decode accelerator drivers.
  //static const char kDevJpegDecPath[] = "/dev/jpeg-dec";
  //permissions->push_back(BrokerFilePermission::ReadWrite(kDevJpegDecPath));
  permissions->push_back(BrokerFilePermission::ReadWriteCreateRecursive(root_dir.value()));
}

std::vector<BrokerFilePermission> FilePermissionsForDomain(
  const base::FilePath& root_dir,
  const service_manager::SandboxSeccompBPF::Options& options) {
  std::vector<BrokerFilePermission> permissions;
  AddApplicationDirectoriesAndFiles(root_dir, &permissions, options);
  return permissions;
}

bool LoadLibrariesForDomain(
    const service_manager::SandboxSeccompBPF::Options& options) {
  // if (IsChromeOS()) {
  //   if (UseV4L2Codec())
  //     LoadV4L2Libraries(options);
  //   if (IsArchitectureArm()) {
  //     LoadArmGpuLibraries();
  //     return true;
  //   }
  //   if (options.use_amd_specific_policies)
  //     return LoadAmdGpuLibraries();
  // }
  return true;
}

bool BrokerProcessPreSandboxHook(
    service_manager::SandboxLinux::Options options) {
  // Oddly enough, we call back into gpu to invoke this service manager
  // method, since it is part of the embedder component, and the service
  // mananger's sandbox component is a lower layer that can't depend on it.
  service_manager::SetProcessTitleFromCommandLine(nullptr);
  return true;
}

sandbox::syscall_broker::BrokerCommandSet CommandSetForDomain(
    const service_manager::SandboxLinux::Options& options) {
  sandbox::syscall_broker::BrokerCommandSet command_set;
  command_set.set(sandbox::syscall_broker::COMMAND_ACCESS);
  command_set.set(sandbox::syscall_broker::COMMAND_OPEN);
  command_set.set(sandbox::syscall_broker::COMMAND_STAT);
  //if (IsChromeOS() && options.use_amd_specific_policies) {
    command_set.set(sandbox::syscall_broker::COMMAND_READLINK);
  //}
  return command_set;
}


bool DomainProcessPreSandboxHook(const base::FilePath& root_dir, service_manager::SandboxLinux::Options options) {
  service_manager::SandboxLinux::GetInstance()->StartBrokerProcess(
      CommandSetForDomain(options), FilePermissionsForDomain(root_dir, options),
      base::BindOnce(BrokerProcessPreSandboxHook), options);

  if (!LoadLibrariesForDomain(options))
    return false;

  // TODO(tsepez): enable namspace sandbox here once crashes are understood.

  errno = 0;
  return true;
}

bool StartSandboxLinux(const base::FilePath& root_dir) {
  TRACE_EVENT0("domain,startup", "Initialize sandbox");
  
  // SandboxLinux::InitializeSandbox() must always be called
  // with only one thread.
  service_manager::SandboxLinux::Options sandbox_options;
  
  // the launcher process (host) should already set us in a namespace sandbox
  //sandbox_options.engage_namespace_sandbox = true;
  //DLOG(INFO) << "domain::StartSandboxLinux: InitializeSandbox()";
  bool res = service_manager::SandboxLinux::GetInstance()->InitializeSandbox(
      service_manager::SandboxTypeFromCommandLine(
          *base::CommandLine::ForCurrentProcess()),
      base::BindOnce(DomainProcessPreSandboxHook, root_dir), sandbox_options);

  base::Process proc = base::Process::Current();
  //DLOG(INFO) << "\n\n pid = " << proc.Handle();
  CHECK(proc.Handle() == 1);

  base::ScopedFD proc_self_exe(HANDLE_EINTR(open("/proc/self/exe", O_RDONLY)));
  //DLOG(INFO) << "access to /proc/self/exe ? " << (proc_self_exe.is_valid() ? "true" : "false");

  base::ScopedFD proc_root(HANDLE_EINTR(open("/", O_RDONLY)));
  //DLOG(INFO) << "access to / ? " << (proc_root.is_valid() ? "true" : "false");

   base::ScopedFD self_task(HANDLE_EINTR(open("/proc/self/task/", O_RDONLY)));
  //DLOG(INFO) << "access to /proc/self/task ? " << (self_task.is_valid() ? "true" : "false");

  base::ScopedFD resources(HANDLE_EINTR(open("/resources/", O_RDONLY)));
  //DLOG(INFO) << "access to /resources/ ? " << (resources.is_valid() ? "true" : "false");

  base::FileEnumerator files(root_dir, false, base::FileEnumerator::DIRECTORIES);
  for (base::FilePath file = files.Next(); !file.empty(); file = files.Next()) {
    //DLOG(INFO) << file;
  }

  //DLOG(INFO) << " InNewUserNamespace? " << sandbox::NamespaceSandbox::InNewUserNamespace();
  //DLOG(INFO) << " InNewPidNamespace? " << sandbox::NamespaceSandbox::InNewPidNamespace();
  //DLOG(INFO) << " InNewNetNamespace? " << sandbox::NamespaceSandbox::InNewNetNamespace();

  //std::vector<sandbox::Credentials::Capability> caps;
  //caps.push_back(sandbox::Credentials::Capability::SYS_CHROOT);
  // the new process will be the 1/init process in its new namespace
  // so theres no problem with this
  //caps.push_back(sandbox::Credentials::Capability::SYS_ADMIN);
  //base::ScopedFD proc_fd(sandbox::ProcUtil::OpenProc());

  //CHECK(sandbox::Credentials::SetCapabilitiesOnCurrentThread(proc_fd.get(), caps));
  //CHECK(sandbox::Credentials::SetCapabilities(proc.Handle(), caps));
  //CHECK(sandbox::Credentials::SetCapabilitiesOnCurrentThread(caps));
  
  //if (!sandbox::Credentials::ChrootTo(proc.Handle(), root_dir)) {
  //if (!sandbox::Credentials::ChrootTo(proc_fd.get(), root_dir)) {
  //  return false;
  //}

  //bool chroot_ok = sandbox::Credentials::ChrootTo(proc.Handle(), root_dir);
  //DLOG(INFO) << "chroot_ok ? " << chroot_ok;

  return res;
}
#endif  // defined(OS_LINUX)

#if defined(OS_WIN)
bool StartSandboxWindows(const sandbox::SandboxInterfaceInfo* sandbox_info) {
  TRACE_EVENT0("gpu,startup", "Lower token");

  // For Windows, if the target_services interface is not zero, the process
  // is sandboxed and we must call LowerToken() before rendering untrusted
  // content.
  sandbox::TargetServices* target_services = sandbox_info->target_services;
  if (target_services) {
    target_services->LowerToken();
    return true;
  }

  return false;
}
#endif  // defined(OS_WIN)

}  // namespace.

int Main(const common::MainParams& params) {
 base::ScopedAllowBlockingForTesting allow_blocking;
 base::FilePath home_dir;

 common::RegisterPathProvider();
 
 if(!base::PathService::Get(common::DIR_PROFILE, &home_dir)) {
    LOG(ERROR) << "domain fatal: failed to get the users home directory";
    return 1;
 }

 DomainMainPlatformDelegate platform(params);

 base::CommandLine* cmd = base::CommandLine::ForCurrentProcess();

 if (!cmd->HasSwitch(switches::kWorkspaceId)) {
   LOG(ERROR) << "app host fatal: no workspace id provided. we cant go on.";
   return 1;
 }

 if (!cmd->HasSwitch(switches::kDomainUUID)) {
   LOG(ERROR) << "app host fatal: no app host id provided. we cant go on.";
   return 1;
 }

 if (!cmd->HasSwitch(switches::kDomainName)) {
   LOG(ERROR) << "app host fatal: no app host name provided. we cant go on.";
   return 1;
 }

 bool no_sandbox = base::CommandLine::ForCurrentProcess()->HasSwitch(switches::kNoSandbox);
 
 std::unique_ptr<base::MessageLoop> main_message_loop(new base::MessageLoop());
 base::PlatformThread::SetName("DomainMain");

 std::string workspace_id = cmd->GetSwitchValueASCII(switches::kWorkspaceId); 
 std::string uuid_string = cmd->GetSwitchValueASCII(switches::kDomainUUID);
 std::string domain_name = cmd->GetSwitchValueASCII(switches::kDomainName);
 std::string bundle_path = cmd->GetSwitchValueASCII("bundle-path");

 int domain_process_id = -1;
 DCHECK(base::StringToInt(cmd->GetSwitchValueASCII("domain-process-id"), &domain_process_id));

 bool convertion_ok = false;
 base::UUID domain_id = base::UUID::from_string(uuid_string, &convertion_ok);
 if (!convertion_ok) {
  LOG(ERROR) << "app host fatal: failed to turn " << uuid_string << " into the app host uuid";
  return 1;
 }

 base::FilePath domain_root = base::FilePath(
   home_dir.Append(FILE_PATH_LITERAL(workspace_id))
    .Append(FILE_PATH_LITERAL("apps"))
#if defined(OS_WIN)
    .AppendASCII(uuid_string).value() + L"/")
#else
    .AppendASCII(uuid_string).value() + "/")
#endif
    .AppendASCII(bundle_path);
 platform.PlatformInitialize(domain_root);

 if (!no_sandbox) {
#if defined(OS_LINUX)
  StartSandboxLinux(domain_root);
#endif
#if defined(OS_WIN)
  // TODO: IMPLEMENT!
  sandbox::SandboxInterfaceInfo info;
  memset(&info, 0, sizeof(sandbox::SandboxInterfaceInfo));
  StartSandboxWindows(&info);
#endif
 }
 

 // if (!cmd->HasSwitch(switches::kNoSandbox)) {
 //   //DLOG(INFO) << "shell: enabling sandbox";
 //   platform.EnableSandbox();
 // }

 auto domain_process = DomainProcess::Create();

 std::unique_ptr<blink::scheduler::WebMainThreadScheduler>
      main_thread_scheduler(blink::scheduler::WebMainThreadScheduler::Create(
          base::Optional<base::Time>()));

 DomainMainThread::Create(
    std::move(main_message_loop),
    std::move(main_thread_scheduler),
    params.command_line,
    domain_root,
    domain_id,
    domain_name,
    bundle_path,
    domain_process_id);

 base::RunLoop().Run();
 domain_process.reset();

 platform.PlatformUninitialize();
 
 return 0;
}

}