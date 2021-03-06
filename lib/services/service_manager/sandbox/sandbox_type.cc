// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "services/service_manager/sandbox/sandbox_type.h"

#include <string>

#include "services/service_manager/sandbox/switches.h"

namespace service_manager {

bool IsUnsandboxedSandboxType(SandboxType sandbox_type) {
  return
#if defined(OS_WIN)
      sandbox_type == SANDBOX_TYPE_NO_SANDBOX_AND_ELEVATED_PRIVILEGES ||
#endif
#if !defined(OS_LINUX)
      // TODO(tsepez): Sandbox network process beyond linux.
      sandbox_type == SANDBOX_TYPE_NETWORK ||
#endif
      sandbox_type == SANDBOX_TYPE_NO_SANDBOX;
}

void SetCommandLineFlagsForSandboxType(base::CommandLine* command_line,
                                       SandboxType sandbox_type) {
  switch (sandbox_type) {
    case SANDBOX_TYPE_NO_SANDBOX:
      command_line->AppendSwitch(switches::kNoSandbox);
      break;
#if defined(OS_WIN)
    case SANDBOX_TYPE_NO_SANDBOX_AND_ELEVATED_PRIVILEGES:
      command_line->AppendSwitch(switches::kNoSandboxAndElevatedPrivileges);
      break;
#endif
    case SANDBOX_TYPE_APPLICATION:
      DCHECK(command_line->HasSwitch(switches::kApplicationProcess));
      break;
    case SANDBOX_TYPE_SHELL:
      DCHECK(command_line->HasSwitch(switches::kShellProcess));
      break;  
    case SANDBOX_TYPE_GPU:
      DCHECK(command_line->HasSwitch(switches::kGpuProcess));
      break;
    case SANDBOX_TYPE_UTILITY:
    case SANDBOX_TYPE_NETWORK:
    //case SANDBOX_TYPE_PDF_COMPOSITOR:
    case SANDBOX_TYPE_PROFILING:
      DCHECK(command_line->HasSwitch(switches::kUtilityProcess));
      DCHECK(!command_line->HasSwitch(switches::kServiceSandboxType));
      command_line->AppendSwitchASCII(
          switches::kServiceSandboxType,
          StringFromUtilitySandboxType(sandbox_type));
      break;
    default:
      break;
  }
}

SandboxType SandboxTypeFromCommandLine(const base::CommandLine& command_line) {
  if (command_line.HasSwitch(switches::kNoSandbox))
    return SANDBOX_TYPE_NO_SANDBOX;

#if defined(OS_WIN)
  if (command_line.HasSwitch(switches::kNoSandboxAndElevatedPrivileges))
    return SANDBOX_TYPE_NO_SANDBOX_AND_ELEVATED_PRIVILEGES;
#endif

  if (command_line.HasSwitch(switches::kApplicationProcess))
    return SANDBOX_TYPE_APPLICATION;

  if (command_line.HasSwitch(switches::kShellProcess))
    return SANDBOX_TYPE_SHELL;

  if (command_line.HasSwitch(switches::kUtilityProcess)) {
    return UtilitySandboxTypeFromString(
        command_line.GetSwitchValueASCII(switches::kServiceSandboxType));
  }
  if (command_line.HasSwitch(switches::kGpuProcess)) {
    if (command_line.HasSwitch(switches::kDisableGpuSandbox))
      return SANDBOX_TYPE_NO_SANDBOX;
    return SANDBOX_TYPE_GPU;
  }

  // shell process
  return SANDBOX_TYPE_NO_SANDBOX;
}

std::string StringFromUtilitySandboxType(SandboxType sandbox_type) {
  switch (sandbox_type) {
    case SANDBOX_TYPE_NO_SANDBOX:
      return switches::kNoneSandbox;
    case SANDBOX_TYPE_NETWORK:
      return switches::kNetworkSandbox;
   // case SANDBOX_TYPE_PDF_COMPOSITOR:
   //   return switches::kPdfCompositorSandbox;
    case SANDBOX_TYPE_PROFILING:
      return switches::kProfilingSandbox;
    case SANDBOX_TYPE_UTILITY:
      return switches::kUtilitySandbox;
    default:
      NOTREACHED();
      return std::string();
  }
}

SandboxType UtilitySandboxTypeFromString(const std::string& sandbox_string) {
  if (sandbox_string == switches::kNoneSandbox)
    return SANDBOX_TYPE_NO_SANDBOX;
  if (sandbox_string == switches::kNoneSandboxAndElevatedPrivileges) {
#if defined(OS_WIN)
    return SANDBOX_TYPE_NO_SANDBOX_AND_ELEVATED_PRIVILEGES;
#else
    return SANDBOX_TYPE_NO_SANDBOX;
#endif
  }
  if (sandbox_string == switches::kNetworkSandbox)
    return SANDBOX_TYPE_NETWORK;
  //if (sandbox_string == switches::kPdfCompositorSandbox)
  //  return SANDBOX_TYPE_PDF_COMPOSITOR;
  if (sandbox_string == switches::kProfilingSandbox)
    return SANDBOX_TYPE_PROFILING;
  return SANDBOX_TYPE_UTILITY;
}

}  // namespace service_manager
