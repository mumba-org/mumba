// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef COMMON_MAIN_PARAMS_H__
#define COMMON_MAIN_PARAMS_H__

#include "base/callback_forward.h"
#include "base/command_line.h"
#include "build/build_config.h"

#if defined(OS_WIN)
namespace sandbox {
struct SandboxInterfaceInfo;
}
#elif defined(OS_MACOSX)
namespace base {
namespace mac {
class ScopedNSAutoreleasePool;
}
}
#endif

namespace common {

struct MainParams {
 explicit MainParams(const base::CommandLine& cl)
  : command_line(cl),
  ui_task(NULL) {
 }

 const base::CommandLine& command_line;
#if defined(OS_WIN)
 sandbox::SandboxInterfaceInfo* sandbox_info = nullptr;
#elif defined(OS_MACOSX)
 base::mac::ScopedNSAutoreleasePool* autorelease_pool = nullptr;
#elif defined(OS_POSIX) && !defined(OS_ANDROID)
 bool zygote_child = false;
#endif

 base::Closure* ui_task = nullptr;
};

}

#endif
