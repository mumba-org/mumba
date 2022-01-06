// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_NOTIFICATIONS_DESKTOP_NOTIFICATION_PROFILE_UTIL_H_
#define CHROME_BROWSER_NOTIFICATIONS_DESKTOP_NOTIFICATION_PROFILE_UTIL_H_

#include "base/macros.h"
#include "components/content_settings/core/common/content_settings.h"

namespace host {
class Domain;

// A series of common operations to interact with the domain's Desktop
// Notification settings.
class DesktopNotificationProfileUtil {
 public:
  // NOTE: This should only be called on the UI thread.
  static void ResetToDefaultContentSetting(Domain* domain);

  // Clears the notifications setting for the given url.
  static void ClearSetting(Domain* domain, const GURL& origin);

  // Methods to setup and modify permission preferences.
  static void GrantPermission(Domain* domain, const GURL& origin);
  static void DenyPermission(Domain* domain, const GURL& origin);
  static void GetNotificationsSettings(
      Domain* domain, ContentSettingsForOneType* settings);

 private:
  DISALLOW_IMPLICIT_CONSTRUCTORS(DesktopNotificationProfileUtil);
};

}

#endif  // CHROME_BROWSER_NOTIFICATIONS_DESKTOP_NOTIFICATION_PROFILE_UTIL_H_
