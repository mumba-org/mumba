// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/host_main.h"

#include "core/common/main_params.h"
#include "core/host/host_main_runner.h"

namespace host {

int Main(const common::MainParams& params) {
 HostMainRunner main_runner;

 int exit_code = main_runner.Initialize(params);
 
 if (exit_code >= 0)
  return exit_code;

 exit_code = main_runner.Run();

 main_runner.Shutdown();
 
 return exit_code;
}

}
