// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_MAIN_H__
#define MUMBA_HOST_MAIN_H__

#include "core/shared/common/content_export.h"

namespace common {
struct MainParams;
}

namespace host {

int CONTENT_EXPORT Main(const common::MainParams& params);

}

#endif
