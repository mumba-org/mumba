// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/domain/domain_main_platform_delegate.h"

#include "base/android/build_info.h"
#include "base/metrics/histogram_macros.h"
#include "base/trace_event/trace_event.h"
#include "core/domain/seccomp_sandbox_status_android.h"
#include "sandbox/linux/seccomp-bpf-helpers/seccomp_starter_android.h"
#include "sandbox/sandbox_buildflags.h"

#if BUILDFLAG(USE_SECCOMP_BPF)
#include "sandbox/linux/seccomp-bpf-helpers/baseline_policy_android.h"
#endif

namespace domain {

DomainMainPlatformDelegate::DomainMainPlatformDelegate(
    const common::MainParams& parameters) {}

DomainMainPlatformDelegate::~DomainMainPlatformDelegate() {
}

void DomainMainPlatformDelegate::PlatformInitialize() {
}

void DomainMainPlatformDelegate::PlatformUninitialize() {
}

bool DomainMainPlatformDelegate::EnableSandbox() {
  TRACE_EVENT0("startup", "DomainMainPlatformDelegate::EnableSandbox");
  auto* info = base::android::BuildInfo::GetInstance();
  sandbox::SeccompStarterAndroid starter(info->sdk_int(), info->device());
  // The policy compiler is only available if USE_SECCOMP_BPF is enabled.
#if BUILDFLAG(USE_SECCOMP_BPF)
  starter.set_policy(std::make_unique<sandbox::BaselinePolicyAndroid>());
#endif
  starter.StartSandbox();

  SetSeccompSandboxStatus(starter.status());
  UMA_HISTOGRAM_ENUMERATION("Android.SeccompStatus.DomainSandbox",
                            starter.status(),
                            sandbox::SeccompSandboxStatus::STATUS_MAX);

  return true;
}

}  // namespace domain
