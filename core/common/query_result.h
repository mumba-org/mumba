// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef COMMON_QUERY_RESULT_H_
#define COMMON_QUERY_RESULT_H_

#include "core/common/query_code.h"

namespace common {

struct QueryResult {
 QueryCode code;
 std::string format;
 std::string data;
 std::string message;
 bool is_insert;
};

}

#endif