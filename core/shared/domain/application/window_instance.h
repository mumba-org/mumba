// Copyright 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_APPLICATION_WINDOW_INSTANCE_H_
#define MUMBA_DOMAIN_APPLICATION_WINDOW_INSTANCE_H_

#include "base/macros.h"
#include "core/shared/common/content_export.h"

namespace domain {
class Application;

struct CONTENT_EXPORT WindowInstance {
  int id = -1;
};

enum CONTENT_EXPORT class WindowMode : int {
  UNDEFINED = 0,
  WINDOW = 1,
  TABBED = 2
};

}

#endif