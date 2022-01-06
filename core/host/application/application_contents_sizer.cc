// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/application/application_contents_sizer.h"

#include "build/build_config.h"
#include "core/host/application/application_contents.h"

#if defined(USE_AURA)
#include "ui/aura/window.h"
#elif defined(OS_ANDROID)
#include "core/host/application/application_window_host_view.h"
#endif

namespace host {

void ResizeApplicationContents(ApplicationContents* app_contents,
                               const gfx::Rect& new_bounds) {
#if defined(USE_AURA)
  aura::Window* window = app_contents->GetNativeView();
  window->SetBounds(gfx::Rect(window->bounds().origin(), new_bounds.size()));
#elif defined(OS_ANDROID)
  ApplicationWindowHostView* view = app_contents->GetApplicationWindowHostView();
  if (view)
    view->SetBounds(new_bounds);
#endif
}

}