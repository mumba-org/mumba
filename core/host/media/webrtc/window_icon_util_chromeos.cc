// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/media/webrtc/window_icon_util.h"

#include "core/host/media/desktop_media_id.h"
#include "ui/aura/client/aura_constants.h"
#include "ui/aura/window.h"

namespace host {

gfx::ImageSkia GetWindowIcon(DesktopMediaID id) {
  DCHECK_EQ(DesktopMediaID::TYPE_WINDOW, id.type);
  aura::Window* window = DesktopMediaID::GetAuraWindowById(id);
  if (!window)
    return gfx::ImageSkia();

  gfx::ImageSkia* image = window->GetProperty(aura::client::kWindowIconKey);
  if (!image)
    image = window->GetProperty(aura::client::kAppIconKey);
  return image ? *image : gfx::ImageSkia();
}

}