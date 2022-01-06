// Copyright (c) 2011 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/common/favicon_url.h"

namespace common {

FaviconURL::FaviconURL() : icon_type(IconType::kInvalid) {}

FaviconURL::FaviconURL(const GURL& url,
                       IconType type,
                       const std::vector<gfx::Size>& sizes)
    : icon_url(url), icon_type(type), icon_sizes(sizes) {}

FaviconURL::FaviconURL(const FaviconURL& other) = default;

FaviconURL::~FaviconURL() {
}

} // namespace content
