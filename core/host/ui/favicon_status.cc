// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/ui/favicon_status.h"

#include "core/host/host_client.h"
#include "ui/gfx/image/image_skia.h"

namespace host {

FaviconStatus::FaviconStatus() : valid(false) {
  image = gfx::Image(*common::GetClient()->host()->GetDefaultFavicon());
}

}  // namespace host
