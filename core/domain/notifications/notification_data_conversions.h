// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CORE_DOMAIN_NOTIFICATIONS_NOTIFICATION_DATA_CONVERSIONS_H_
#define CORE_DOMAIN_NOTIFICATIONS_NOTIFICATION_DATA_CONVERSIONS_H_

#include "core/shared/common/content_export.h"
#include "core/shared/common/platform_notification_data.h"
#include "third_party/blink/public/platform/modules/notifications/web_notification_data.h"

namespace domain {

// Converts Blink WebNotificationData to PlatformNotificationData.
CONTENT_EXPORT common::PlatformNotificationData
ToPlatformNotificationData(const blink::WebNotificationData& web_data);

// Converts PlatformNotificationData to Blink WebNotificationData.
CONTENT_EXPORT blink::WebNotificationData ToWebNotificationData(
    const common::PlatformNotificationData& platform_data);

}  // namespace content

#endif  // CORE_DOMAIN_NOTIFICATIONS_NOTIFICATION_DATA_CONVERSIONS_H_
