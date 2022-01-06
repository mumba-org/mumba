// Copyright 2017 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_DOMAIN_MAIN_H_
#define MUMBA_DOMAIN_DOMAIN_MAIN_H_

#include "core/shared/common/content_export.h"

namespace common {
struct MainParams;
}

namespace domain {

int CONTENT_EXPORT Main(const common::MainParams& params);

}

#endif