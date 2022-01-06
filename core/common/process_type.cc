// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/common/process_type.h"

#include "base/logging.h"

namespace common {

std::string GetProcessTypeName(int type) {

 switch (type) {
 case PROCESS_TYPE_HOST:
  return "HOST";
 case PROCESS_TYPE_APPLICATION:
  return "APPLICATION";
 case PROCESS_TYPE_DOMAIN:
  return "DOMAIN"; 
 case PROCESS_TYPE_GPU:
  return "GPU";
 case PROCESS_TYPE_UTILITY:
  return "UTILITY";
 case PROCESS_TYPE_TOOLS:
  return "TOOLS";  
 case PROCESS_TYPE_SANDBOX_HELPER: 
  return "SANDBOX HELPER";
 case PROCESS_TYPE_ZYGOTE:
  return "ZYGOTE";
 case PROCESS_TYPE_UNKNOWN:
  DCHECK(false) << "Unknown child process type!";
  return "Unknown";
 }

 return "Unknown";
}

} // namespace common
