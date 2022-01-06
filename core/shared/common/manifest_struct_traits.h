// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_PUBLIC_COMMON_MANIFEST_STRUCT_TRAITS_H_
#define CONTENT_PUBLIC_COMMON_MANIFEST_STRUCT_TRAITS_H_

#include "core/shared/common/manifest.h"

#include "mojo/public/cpp/bindings/struct_traits.h"
#include "third_party/blink/public/platform/modules/manifest/manifest.mojom-shared.h"

namespace mojo {
namespace internal {

inline base::StringPiece16 TruncateString16(const base::string16& string) {
  return base::StringPiece16(string).substr(
      0, common::Manifest::kMaxIPCStringLength);
}

inline base::Optional<base::StringPiece16> TruncateNullableString16(
    const base::NullableString16& string) {
  if (string.is_null())
    return base::nullopt;

  return TruncateString16(string.string());
}

}  // namespace internal

template <>
struct StructTraits<blink::mojom::ManifestDataView, common::Manifest> {
  static bool IsNull(const common::Manifest& m) { return m.IsEmpty(); }

  static void SetToNull(common::Manifest* m) { *m = common::Manifest(); }

  static base::Optional<base::StringPiece16> name(const common::Manifest& m) {
    return internal::TruncateNullableString16(m.name);
  }

  static base::Optional<base::StringPiece16> short_name(
      const common::Manifest& m) {
    return internal::TruncateNullableString16(m.short_name);
  }

  static base::Optional<base::StringPiece16> gcm_sender_id(
      const common::Manifest& m) {
    return internal::TruncateNullableString16(m.gcm_sender_id);
  }

  static const GURL& start_url(const common::Manifest& m) {
    return m.start_url;
  }

  static const GURL& scope(const common::Manifest& m) { return m.scope; }

  static blink::WebDisplayMode display(const common::Manifest& m) {
    return m.display;
  }

  static blink::WebScreenOrientationLockType orientation(
      const common::Manifest& m) {
    return m.orientation;
  }

  static int64_t theme_color(const common::Manifest& m) {
    return m.theme_color;
  }

  static int64_t background_color(const common::Manifest& m) {
    return m.background_color;
  }

  static const GURL& splash_screen_url(const common::Manifest& m) {
    return m.splash_screen_url;
  }

  static const std::vector<common::Manifest::Icon>& icons(
      const common::Manifest& m) {
    return m.icons;
  }

  static const base::Optional<common::Manifest::ShareTarget>& share_target(
      const common::Manifest& m) {
    return m.share_target;
  }

  static const std::vector<common::Manifest::RelatedApplication>&
  related_applications(const common::Manifest& m) {
    return m.related_applications;
  }

  static bool prefer_related_applications(const common::Manifest& m) {
    return m.prefer_related_applications;
  }

  static bool Read(blink::mojom::ManifestDataView data, common::Manifest* out);
};

template <>
struct StructTraits<blink::mojom::ManifestIconDataView,
                    common::Manifest::Icon> {
  static const GURL& src(const common::Manifest::Icon& m) { return m.src; }

  static base::StringPiece16 type(const common::Manifest::Icon& m) {
    return internal::TruncateString16(m.type);
  }
  static const std::vector<gfx::Size>& sizes(const common::Manifest::Icon& m) {
    return m.sizes;
  }

  static const std::vector<common::Manifest::Icon::IconPurpose>& purpose(
      const common::Manifest::Icon& m) {
    return m.purpose;
  }

  static bool Read(blink::mojom::ManifestIconDataView data,
                   common::Manifest::Icon* out);
};

template <>
struct StructTraits<blink::mojom::ManifestRelatedApplicationDataView,
                    common::Manifest::RelatedApplication> {
  static base::Optional<base::StringPiece16> platform(
      const common::Manifest::RelatedApplication& m) {
    return internal::TruncateNullableString16(m.platform);
  }

  static const GURL& url(const common::Manifest::RelatedApplication& m) {
    return m.url;
  }

  static base::Optional<base::StringPiece16> id(
      const common::Manifest::RelatedApplication& m) {
    return internal::TruncateNullableString16(m.id);
  }

  static bool Read(blink::mojom::ManifestRelatedApplicationDataView data,
                   common::Manifest::RelatedApplication* out);
};

template <>
struct StructTraits<blink::mojom::ManifestShareTargetDataView,
                    common::Manifest::ShareTarget> {
  static const GURL& url_template(const common::Manifest::ShareTarget& m) {
    return m.url_template;
  }
  static bool Read(blink::mojom::ManifestShareTargetDataView data,
                   common::Manifest::ShareTarget* out);
};

template <>
struct EnumTraits<blink::mojom::ManifestIcon_Purpose,
                  common::Manifest::Icon::IconPurpose> {
  static blink::mojom::ManifestIcon_Purpose ToMojom(
      common::Manifest::Icon::IconPurpose purpose) {
    switch (purpose) {
      case common::Manifest::Icon::ANY:
        return blink::mojom::ManifestIcon_Purpose::ANY;
      case common::Manifest::Icon::BADGE:
        return blink::mojom::ManifestIcon_Purpose::BADGE;
    }
    NOTREACHED();
    return blink::mojom::ManifestIcon_Purpose::ANY;
  }
  static bool FromMojom(blink::mojom::ManifestIcon_Purpose input,
                        common::Manifest::Icon::IconPurpose* out) {
    switch (input) {
      case blink::mojom::ManifestIcon_Purpose::ANY:
        *out = common::Manifest::Icon::ANY;
        return true;
      case blink::mojom::ManifestIcon_Purpose::BADGE:
        *out = common::Manifest::Icon::BADGE;
        return true;
    }

    return false;
  }
};

}  // namespace mojo

#endif  // CONTENT_PUBLIC_COMMON_MANIFEST_STRUCT_TRAITS_H_
