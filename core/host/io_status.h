// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_WORLD_IO_STATUS_H_
#define MUMBA_HOST_WORLD_IO_STATUS_H_

#include <string>

namespace host {

enum class IOStatus {
 Ok,
 IOError,
 Corrupt,
 NotFound,
};

const char* IOStatusToString(IOStatus st);

}

#endif
