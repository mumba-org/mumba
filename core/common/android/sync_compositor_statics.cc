// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/common/android/sync_compositor_statics.h"

#include "base/command_line.h"
#include "core/common/content_switches.h"

namespace common {

static SkCanvas* g_canvas = nullptr;

void SynchronousCompositorSetSkCanvas(SkCanvas* canvas) {
  DCHECK(base::CommandLine::ForCurrentProcess()->HasSwitch(
      switches::kSingleProcess));
  DCHECK_NE(!!canvas, !!g_canvas);
  g_canvas = canvas;
}

SkCanvas* SynchronousCompositorGetSkCanvas() {
  return g_canvas;
}

}  // namespace common
