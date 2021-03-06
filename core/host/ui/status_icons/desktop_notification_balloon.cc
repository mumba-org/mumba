// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/ui/status_icons/desktop_notification_balloon.h"

#include <stddef.h>

#include "base/strings/string_number_conversions.h"
#include "base/threading/thread_restrictions.h"
//#include "core/host/notifications/notification_display_service.h"
//#include "core/host/profiles/profile_manager.h"
#include "ui/gfx/image/image_skia.h"
//#include "ui/message_center/public/cpp/notification.h"
//#include "ui/message_center/public/cpp/notification_delegate.h"
//#include "ui/message_center/public/cpp/notification_types.h"
//#include "ui/message_center/public/cpp/notifier_id.h"

namespace host {

// namespace {

// // Prefix added to the notification ids.
// const char kDesktopNotificationPrefix[] = "desktop_notification_balloon.";

// }  // anonymous namespace

int DesktopNotificationBalloon::id_count_ = 1;

DesktopNotificationBalloon::DesktopNotificationBalloon() {}

DesktopNotificationBalloon::~DesktopNotificationBalloon() {}

void DesktopNotificationBalloon::DisplayBalloon(
    const gfx::ImageSkia& icon,
    const base::string16& title,
    const base::string16& contents,
    const message_center::NotifierId& notifier_id) {
  // Allowing IO access is required here to cover the corner case where
  // there is no last used profile and the default one is loaded.
  // IO access won't be required for normal uses.
  // Profile* profile;
  // {
  //   base::ThreadRestrictions::ScopedAllowIO allow_io;
  //   profile = ProfileManager::GetLastUsedProfile();
  // }

  // const std::string notification_id =
  //     kDesktopNotificationPrefix + base::IntToString(id_count_++);
  // message_center::Notification notification(
  //     message_center::NOTIFICATION_TYPE_SIMPLE, notification_id, title,
  //     contents, gfx::Image(icon), base::string16(), GURL(), notifier_id, {},
  //     new message_center::NotificationDelegate());

  // NotificationDisplayService::GetForProfile(profile)->Display(
  //     NotificationHandler::Type::TRANSIENT, notification);
  DCHECK(false);
}

}