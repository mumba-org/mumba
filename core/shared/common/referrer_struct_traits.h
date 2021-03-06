// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_PUBLIC_COMMON_REFERRER_STRUCT_TRAITS_H_
#define CONTENT_PUBLIC_COMMON_REFERRER_STRUCT_TRAITS_H_

#include "core/shared/common/content_export.h"
#include "core/shared/common/referrer.h"
#include "third_party/blink/public/platform/referrer.mojom.h"
#include "third_party/blink/public/platform/referrer_policy_enum_traits.h"

namespace mojo {

template <>
struct CONTENT_EXPORT
    StructTraits<::blink::mojom::ReferrerDataView, common::Referrer> {
  static const GURL& url(const common::Referrer& r) {
    return r.url;
  }

  static ::blink::WebReferrerPolicy policy(const common::Referrer& r) {
    return r.policy;
  }

  static bool Read(::blink::mojom::ReferrerDataView data,
                   common::Referrer* out);
};

}

#endif  // CONTENT_PUBLIC_COMMON_REFERRER_STRUCT_TRAITS_H_
