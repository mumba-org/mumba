// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_PUBLIC_COMMON_RESOURCE_USAGE_REPORTER_TYPE_CONVERTERS_H_
#define CONTENT_PUBLIC_COMMON_RESOURCE_USAGE_REPORTER_TYPE_CONVERTERS_H_

#include "core/shared/common/content_export.h"
#include "core/shared/common/resource_usage_reporter.mojom.h"
#include "mojo/public/cpp/bindings/type_converter.h"
#include "third_party/blink/public/platform/web_cache.h"

namespace mojo {

template <>
struct CONTENT_EXPORT TypeConverter<common::mojom::ResourceTypeStatsPtr,
                                    blink::WebCache::ResourceTypeStats> {
  static common::mojom::ResourceTypeStatsPtr Convert(
      const blink::WebCache::ResourceTypeStats& obj);
};

template <>
struct CONTENT_EXPORT TypeConverter<blink::WebCache::ResourceTypeStats,
                                    common::mojom::ResourceTypeStats> {
  static blink::WebCache::ResourceTypeStats Convert(
      const common::mojom::ResourceTypeStats& obj);
};

}  // namespace mojo

#endif  // CONTENT_PUBLIC_COMMON_RESOURCE_USAGE_REPORTER_TYPE_CONVERTERS_H_
