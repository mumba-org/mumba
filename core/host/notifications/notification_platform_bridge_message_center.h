// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_NOTIFICATIONS_NOTIFICATION_PLATFORM_BRIDGE_MESSAGE_CENTER_H_
#define CHROME_BROWSER_NOTIFICATIONS_NOTIFICATION_PLATFORM_BRIDGE_MESSAGE_CENTER_H_

#include "base/macros.h"
#include "core/host/notifications/notification_platform_bridge.h"

namespace host {
class Domain;

// Implementation of the platform bridge that enables delivering notifications
// through Chrome's Message Center. Default bridge for Windows, fallback bridge
// for mac OS and Linux.
//
// Different from the other platform bridges, which are global to the process,
// the Message Center bridge will be created on demand by the notification
// display service and is thereby associated with a particular domain.
class NotificationPlatformBridgeMessageCenter
    : public NotificationPlatformBridge {
 public:
  explicit NotificationPlatformBridgeMessageCenter(Domain* domain);
  ~NotificationPlatformBridgeMessageCenter() override;

  // NotificationPlatformBridge implementation:
  void Display(NotificationHandler::Type notification_type,
               Domain* domain,
               const message_center::Notification& notification,
               std::unique_ptr<NotificationCommon::Metadata> metadata) override;
  void Close(Domain* domain, const std::string& notification_id) override;
  void GetDisplayed(Domain* domain,
                    GetDisplayedNotificationsCallback callback) const override;
  void SetReadyCallback(NotificationBridgeReadyCallback callback) override;

 private:
  Domain* profile_;

  DISALLOW_COPY_AND_ASSIGN(NotificationPlatformBridgeMessageCenter);
};

}

#endif  // CHROME_BROWSER_NOTIFICATIONS_NOTIFICATION_PLATFORM_BRIDGE_MESSAGE_CENTER_H_
