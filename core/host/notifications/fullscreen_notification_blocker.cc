// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/notifications/fullscreen_notification_blocker.h"

#include "base/metrics/histogram_macros.h"
#include "base/time/time.h"
#include "core/host/notification_types.h"
#include "core/host/fullscreen.h"
#include "core/host/notification_service.h"
#include "ui/message_center/public/cpp/notifier_id.h"

using message_center::NotifierId;

namespace host {

FullscreenNotificationBlocker::FullscreenNotificationBlocker(
    message_center::MessageCenter* message_center)
    : NotificationBlocker(message_center),
      is_fullscreen_mode_(false) {
  registrar_.Add(this, NOTIFICATION_FULLSCREEN_CHANGED,
                 NotificationService::AllSources());
}

FullscreenNotificationBlocker::~FullscreenNotificationBlocker() {
}

void FullscreenNotificationBlocker::CheckState() {
  bool was_fullscreen_mode = is_fullscreen_mode_;
  is_fullscreen_mode_ = IsFullScreenMode();
  if (is_fullscreen_mode_ != was_fullscreen_mode)
    NotifyBlockingStateChanged();
}

bool FullscreenNotificationBlocker::ShouldShowNotificationAsPopup(
    const message_center::Notification& notification) const {
  bool enabled =
      !is_fullscreen_mode_ || (notification.fullscreen_visibility() !=
                               message_center::FullscreenVisibility::NONE);

  if (enabled && !is_fullscreen_mode_) {
    UMA_HISTOGRAM_ENUMERATION("Notifications.Display_Windowed",
                              notification.notifier_id().type,
                              NotifierId::SIZE);
  }

  return enabled;
}

void FullscreenNotificationBlocker::Observe(
    int type,
    const NotificationSource& source,
    const NotificationDetails& details) {
  DCHECK_EQ(NOTIFICATION_FULLSCREEN_CHANGED, type);
  CheckState();
}

}