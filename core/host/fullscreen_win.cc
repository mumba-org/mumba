// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/fullscreen.h"

#include "ui/base/fullscreen_win.h"

namespace host {

bool IsFullScreenMode() {
  return ui::IsFullScreenMode();
}

}