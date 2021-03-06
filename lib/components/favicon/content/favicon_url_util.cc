// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "components/favicon/content/favicon_url_util.h"

#include <algorithm>
#include <iterator>

#include "components/favicon/core/favicon_url.h"
#include "components/favicon_base/favicon_types.h"
#include "core/shared/common/favicon_url.h"

namespace favicon {
namespace {

favicon_base::IconType IconTypeFromContentIconType(
    common::FaviconURL::IconType icon_type) {
  switch (icon_type) {
    case common::FaviconURL::IconType::kFavicon:
      return favicon_base::IconType::kFavicon;
    case common::FaviconURL::IconType::kTouchIcon:
      return favicon_base::IconType::kTouchIcon;
    case common::FaviconURL::IconType::kTouchPrecomposedIcon:
      return favicon_base::IconType::kTouchPrecomposedIcon;
    case common::FaviconURL::IconType::kInvalid:
      return favicon_base::IconType::kInvalid;
  }
  NOTREACHED();
  return favicon_base::IconType::kInvalid;
}

}  // namespace

FaviconURL FaviconURLFromContentFaviconURL(
    const common::FaviconURL& favicon_url) {
  return FaviconURL(favicon_url.icon_url,
                    IconTypeFromContentIconType(favicon_url.icon_type),
                    favicon_url.icon_sizes);
}

std::vector<FaviconURL> FaviconURLsFromContentFaviconURLs(
    const std::vector<common::FaviconURL>& favicon_urls) {
  std::vector<FaviconURL> result;
  result.reserve(favicon_urls.size());
  std::transform(favicon_urls.begin(), favicon_urls.end(),
                 std::back_inserter(result), FaviconURLFromContentFaviconURL);
  return result;
}

}  // namespace favicon
