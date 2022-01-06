// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef COMMON_PROCESS_TYPE_H__
#define COMMON_PROCESS_TYPE_H__

#include <string>

namespace common {

enum ProcessType {
 PROCESS_TYPE_UNKNOWN = 1,
 PROCESS_TYPE_HOST,
 PROCESS_TYPE_DOMAIN,
 PROCESS_TYPE_GPU,
 PROCESS_TYPE_APPLICATION,
 PROCESS_TYPE_UTILITY,
 PROCESS_TYPE_TOOLS,
 PROCESS_TYPE_ZYGOTE,
 PROCESS_TYPE_SANDBOX_HELPER,
 PROCESS_TYPE_END,
 PROCESS_TYPE_MAX = PROCESS_TYPE_END,
};

std::string GetProcessTypeName(int type);

}

#endif