// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/notifications/desktop_notification_profile_util.h"

//#include "core/host/content_settings/host_content_settings_map_factory.h"
#include "core/host/application/domain.h"
//#include "components/content_settings/core/browser/host_content_settings_map.h"
//#include "components/content_settings/core/common/content_settings_pattern.h"

namespace host {

void DesktopNotificationProfileUtil::ResetToDefaultContentSetting(
    Domain* domain) {
//   HostContentSettingsMapFactory::GetForProfile(domain)
//       ->SetDefaultContentSetting(CONTENT_SETTINGS_TYPE_NOTIFICATIONS,
//                                  CONTENT_SETTING_DEFAULT);
}

// Clears the notifications setting for the given pattern.
void DesktopNotificationProfileUtil::ClearSetting(Domain* domain,
                                                  const GURL& origin) {
//   HostContentSettingsMapFactory::GetForProfile(domain)
//       ->SetContentSettingDefaultScope(
//           origin, GURL(), CONTENT_SETTINGS_TYPE_NOTIFICATIONS,
//           content_settings::ResourceIdentifier(), CONTENT_SETTING_DEFAULT);
}

// Methods to setup and modify permission preferences.
void DesktopNotificationProfileUtil::GrantPermission(
    Domain* domain, const GURL& origin) {
//   HostContentSettingsMapFactory::GetForProfile(domain)
//       ->SetContentSettingDefaultScope(
//           origin, GURL(), CONTENT_SETTINGS_TYPE_NOTIFICATIONS,
//           content_settings::ResourceIdentifier(), CONTENT_SETTING_ALLOW);
}

void DesktopNotificationProfileUtil::DenyPermission(
    Domain* domain, const GURL& origin) {
//   HostContentSettingsMapFactory::GetForProfile(domain)
//       ->SetContentSettingDefaultScope(
//           origin, GURL(), CONTENT_SETTINGS_TYPE_NOTIFICATIONS,
//           content_settings::ResourceIdentifier(), CONTENT_SETTING_BLOCK);
}

void DesktopNotificationProfileUtil::GetNotificationsSettings(
    Domain* domain, ContentSettingsForOneType* settings) {
//   HostContentSettingsMapFactory::GetForProfile(domain)
//       ->GetSettingsForOneType(CONTENT_SETTINGS_TYPE_NOTIFICATIONS,
//                               content_settings::ResourceIdentifier(),
//                               settings);
}

}