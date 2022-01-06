// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/common/process_launcher_delegate.h"

namespace common {

bool ProcessLauncherDelegate::ShouldSandbox() { 
  return false; 
}

base::EnvironmentMap ProcessLauncherDelegate::GetEnvironment() { 
  return base::EnvironmentMap();
}

}