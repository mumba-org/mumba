// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/domain/domain_main_platform_delegate.h"

#include <errno.h>
#include <sys/stat.h>
#include <limits.h>
#include <sched.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "base/command_line.h"
#include "base/files/file_util.h"
#include "base/logging.h"
#include "core/shared/common/content_features.h"
#include "core/shared/common/switches.h"
#include "core/common/sandbox_init.h"
#include "services/service_manager/sandbox/sandbox.h"
#include "sandbox/linux/services/syscall_wrappers.h"
#include "sandbox/linux/services/credentials.h"

namespace domain {

// namespace {

// void ChrootTo(const base::FilePath& dir) {
//   // This function can be run from a vforked child, so it should not write to
//   // any memory other than the stack or errno. Reads from TLS may be different
//   // from in the parent process.
//   RAW_CHECK(sandbox::sys_chroot(dir.value().c_str()) == 0);
  
//   // CWD is essentially an implicit file descriptor, so be careful to not
//   // leave it behind.
//   RAW_CHECK(chdir("/") == 0);
// }

// }

DomainMainPlatformDelegate::DomainMainPlatformDelegate(
    const common::MainParams& parameters) {}

DomainMainPlatformDelegate::~DomainMainPlatformDelegate() {
}

void DomainMainPlatformDelegate::PlatformInitialize(const base::FilePath& root) {
  root_dir_ = root;
  //ChrootTo(root_dir_);
}

void DomainMainPlatformDelegate::PlatformUninitialize() {
}

bool DomainMainPlatformDelegate::EnableSandbox() {
  // the reminescent from 'layer 1' sandbox
  
  // DEPRECATED: we are doing this now on LaunchProcess
  // callback hook for the launched child process(this process) 'LaunchOptions::PreExecDelegate'
  // see sandbox/linux/services/namespace_sandbox.cc

  //CHECK(sandbox::Credentials::MoveToNewUserNS());
  // if (unshare(CLONE_NEWUSER) != 0) {
  //   int err = errno;
  //   LOG(ERROR) << "unshare failed with errorno: " << err;
  //   return false;
  // }
  
  service_manager::SandboxLinux::Options options;
  //options.chroot_dir = base::FilePath("/home/fabiok/rootfs/");
  service_manager::Sandbox::Initialize(
      service_manager::SandboxTypeFromCommandLine(
          *base::CommandLine::ForCurrentProcess()),
      service_manager::SandboxLinux::PreSandboxHook(), options);

  // about:sandbox uses a value returned from SandboxLinux::GetStatus() before
  // any shell has been started.
  // Here, we test that the status of SeccompBpf in the shell is consistent
  // with what SandboxLinux::GetStatus() said we would do.
  auto* linux_sandbox = service_manager::SandboxLinux::GetInstance();
  if (linux_sandbox->GetStatus() & service_manager::SandboxLinux::kSeccompBPF) {
    CHECK(linux_sandbox->seccomp_bpf_started());
  }

  // Under the setuid sandbox, we should not be able to open any file via the
  // filesystem.
  if (linux_sandbox->GetStatus() & service_manager::SandboxLinux::kSUID) {
    CHECK(!base::PathExists(base::FilePath("/proc/cpuinfo")));
  }

#if defined(__x86_64__)
  // Limit this test to architectures where seccomp BPF is active in shells.
  if (linux_sandbox->seccomp_bpf_started()) {
    errno = 0;
    // This should normally return EBADF since the first argument is bogus,
    // but we know that under the seccomp-bpf sandbox, this should return EPERM.
    CHECK_EQ(fchmod(-1, 07777), -1);
    CHECK_EQ(errno, EPERM);
  }
#endif  // __x86_64__

  return true;
}

}  // namespace domain
