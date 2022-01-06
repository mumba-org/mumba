// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef COMMON_STATUS_H__
#define COMMON_STATUS_H__

namespace status {

enum Code {
  Undefined = -1,
  Ok = 0,
  NotRunning = 1,
  NotFound = 2,
};

}

#endif