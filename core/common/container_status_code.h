// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef COMMON_SHELL_STATUS_CODE_H_
#define COMMON_SHELL_STATUS_CODE_H_

namespace common {

enum ShellStatusCode {
 SHELL_UNDEFINED = -99,
 SHELL_ERROR = -1, // generic error: should fix and enumerate all possible errors
 SHELL_OK = 0,
 SHELL_LAST = SHELL_OK,
};

}

#endif
