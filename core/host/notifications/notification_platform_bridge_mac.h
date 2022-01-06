// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_NOTIFICATIONS_NOTIFICATION_PLATFORM_BRIDGE_MAC_H_
#define CHROME_BROWSER_NOTIFICATIONS_NOTIFICATION_PLATFORM_BRIDGE_MAC_H_

#include <set>
#include <string>

#include "base/compiler_specific.h"
#include "base/mac/scoped_nsobject.h"
#include "base/macros.h"
#include "core/host/notifications/alert_dispatcher_mac.h"
#include "core/host/notifications/notification_common.h"
#include "core/host/notifications/notification_platform_bridge.h"

@class NotificationCenterDelegate;
@class NSDictionary;
@class NSUserNotificationCenter;
@class NSXPCConnection;

namespace message_cener {
class Notification;
}

namespace host {
// This class is an implementation of NotificationPlatformBridge that will
// send platform notifications to the the MacOSX notification center.
class NotificationPlatformBridgeMac : public NotificationPlatformBridge {
 public:
  NotificationPlatformBridgeMac(NSUserNotificationCenter* notification_center,
                                id<AlertDispatcher> alert_dispatcher);

  ~NotificationPlatformBridgeMac() override;

  // NotificationPlatformBridge implementation.
  void Display(NotificationHandler::Type notification_type,
               Domain* domain,
               const message_center::Notification& notification,
               std::unique_ptr<NotificationCommon::Metadata> metadata) override;

  void Close(Domain* domain, const std::string& notification_id) override;
  void GetDisplayed(Domain* domain,
                    GetDisplayedNotificationsCallback callback) const override;
  void SetReadyCallback(NotificationBridgeReadyCallback callback) override;

  // Processes a notification response generated from a user action
  // (click close, etc.).
  static void ProcessNotificationResponse(NSDictionary* response);

  // Validates contents of the |response| dictionary as received from the system
  // when a notification gets activated.
  static bool VerifyNotificationData(NSDictionary* response) WARN_UNUSED_RESULT;

 private:
  // Cocoa class that receives callbacks from the NSUserNotificationCenter.
  base::scoped_nsobject<NotificationCenterDelegate> delegate_;

  // The notification center to use for local banner notifications,
  // this can be overriden in tests.
  base::scoped_nsobject<NSUserNotificationCenter> notification_center_;

  // The object in charge of dispatching remote notifications.
  base::scoped_nsprotocol<id<AlertDispatcher>> alert_dispatcher_;

  DISALLOW_COPY_AND_ASSIGN(NotificationPlatformBridgeMac);
};

}

#endif  // CHROME_BROWSER_NOTIFICATIONS_NOTIFICATION_PLATFORM_BRIDGE_MAC_H_
