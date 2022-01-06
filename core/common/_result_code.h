// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef COMMON_RESULT_CODE_H_
#define COMMON_RESULT_CODE_H_

namespace common {

enum ResultCode {
	RESULT_CODE_NORMAL_EXIT,
	RESULT_CODE_NORMAL_EXIT_PROCESS_NOTIFIED,
	RESULT_CODE_PROFILE_IN_USE,
	RESULT_CODE_MISSING_DATA,
  RESULT_CODE_KILLED,
	RESULT_CODE_KILLED_BAD_MESSAGE,
  RESULT_CODE_HUNG,
  RESULT_CODE_LAST_CODE,
};

}

#endif
