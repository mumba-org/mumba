// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_COMMON_NOTIFICATIONS_NOTIFICATION_STRUCT_TRAITS_H_
#define CONTENT_COMMON_NOTIFICATIONS_NOTIFICATION_STRUCT_TRAITS_H_

#include "base/containers/span.h"
#include "base/strings/string16.h"
#include "core/shared/common/content_export.h"
#include "core/shared/common/platform_notification_data.h"
#include "mojo/public/cpp/base/string16_mojom_traits.h"
#include "mojo/public/cpp/bindings/struct_traits.h"
#include "skia/public/interfaces/bitmap_skbitmap_struct_traits.h"
#include "third_party/blink/public/platform/modules/notifications/notification.mojom.h"
#include "url/gurl.h"
#include "url/mojom/url_gurl_mojom_traits.h"

namespace mojo {

template <>
struct CONTENT_EXPORT EnumTraits<blink::mojom::NotificationDirection,
                                 common::PlatformNotificationData::Direction> {
  static blink::mojom::NotificationDirection ToMojom(
      common::PlatformNotificationData::Direction input);

  static bool FromMojom(blink::mojom::NotificationDirection input,
                        common::PlatformNotificationData::Direction* out);
};

template <>
struct CONTENT_EXPORT EnumTraits<blink::mojom::NotificationActionType,
                                 common::PlatformNotificationActionType> {
  static blink::mojom::NotificationActionType ToMojom(
      common::PlatformNotificationActionType input);

  static bool FromMojom(blink::mojom::NotificationActionType input,
                        common::PlatformNotificationActionType* out);
};

template <>
struct CONTENT_EXPORT StructTraits<blink::mojom::NotificationActionDataView,
                                   common::PlatformNotificationAction> {
  static common::PlatformNotificationActionType type(
      const common::PlatformNotificationAction& action) {
    return action.type;
  }

  static const std::string& action(
      const common::PlatformNotificationAction& action) {
    return action.action;
  }

  static const base::string16& title(
      const common::PlatformNotificationAction& action) {
    return action.title;
  }

  static const GURL& icon(const common::PlatformNotificationAction& action) {
    return action.icon;
  }

  static const base::Optional<base::string16>& placeholder(
      const common::PlatformNotificationAction& action) {
    return action.placeholder.as_optional_string16();
  }

  static bool Read(
      blink::mojom::NotificationActionDataView notification_action,
      common::PlatformNotificationAction* platform_notification_action);
};

template <>
struct CONTENT_EXPORT StructTraits<blink::mojom::NotificationDataDataView,
                                   common::PlatformNotificationData> {
  static const base::string16& title(
      const common::PlatformNotificationData& data) {
    return data.title;
  }

  static common::PlatformNotificationData::Direction direction(
      const common::PlatformNotificationData& data) {
    return data.direction;
  }

  static const std::string& lang(
      const common::PlatformNotificationData& data) {
    return data.lang;
  }

  static const base::string16& body(
      const common::PlatformNotificationData& data) {
    return data.body;
  }

  static const std::string& tag(const common::PlatformNotificationData& data) {
    return data.tag;
  }

  static const GURL& image(const common::PlatformNotificationData& data) {
    return data.image;
  }

  static const GURL& icon(const common::PlatformNotificationData& data) {
    return data.icon;
  }

  static const GURL& badge(const common::PlatformNotificationData& data) {
    return data.badge;
  }

  static const base::span<const int32_t> vibration_pattern(
      const common::PlatformNotificationData& data) {
    // TODO(https://crbug.com/798466): Store as int32s to avoid this cast.
    return base::make_span(
        reinterpret_cast<const int32_t*>(data.vibration_pattern.data()),
        data.vibration_pattern.size());
  }

  static double timestamp(const common::PlatformNotificationData& data) {
    return data.timestamp.ToJsTime();
  }

  static bool renotify(const common::PlatformNotificationData& data) {
    return data.renotify;
  }

  static bool silent(const common::PlatformNotificationData& data) {
    return data.silent;
  }

  static bool require_interaction(
      const common::PlatformNotificationData& data) {
    return data.require_interaction;
  }

  static const base::span<const int8_t> data(
      const common::PlatformNotificationData& data) {
    // TODO(https://crbug.com/798466): Align data types to avoid this cast.
    return base::make_span(reinterpret_cast<const int8_t*>(data.data.data()),
                           data.data.size());
  }

  static const std::vector<common::PlatformNotificationAction>& actions(
      const common::PlatformNotificationData& data) {
    return data.actions;
  }

  static bool Read(
      blink::mojom::NotificationDataDataView notification_data,
      common::PlatformNotificationData* platform_notification_data);
};

template <>
struct CONTENT_EXPORT StructTraits<blink::mojom::NotificationResourcesDataView,
                                   common::NotificationResources> {
  static const SkBitmap& image(
      const common::NotificationResources& resources) {
    return resources.image;
  }

  static const SkBitmap& icon(const common::NotificationResources& resources) {
    return resources.notification_icon;
  }

  static const SkBitmap& badge(
      const common::NotificationResources& resources) {
    return resources.badge;
  }

  static const std::vector<SkBitmap>& action_icons(
      const common::NotificationResources& resources) {
    return resources.action_icons;
  }

  static bool Read(blink::mojom::NotificationResourcesDataView in,
                   common::NotificationResources* out);
};

}  // namespace mojo

#endif  // CONTENT_BROWSER_NOTIFICATIONS_NOTIFICATION_STRUCT_TRAITS_H_
