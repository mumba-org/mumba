// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_NOTIFICATIONS_PROFILE_NOTIFICATION_H_
#define CHROME_BROWSER_NOTIFICATIONS_PROFILE_NOTIFICATION_H_

#include <string>

#include "core/host/notifications/notification_common.h"
#include "core/host/notifications/notification_ui_manager.h"
#include "ui/message_center/public/cpp/notification.h"

namespace host {
class ScopedKeepAlive;

// This class keeps a Notification object and its corresponding Domain. It
// permutes the notification's ID to include a domain identifier so that two
// notifications with identical IDs and different source Profiles can be
// distinguished. This is necessary because the MessageCenter as well as native
// notification services have no notion of the domain.
class WorkspaceNotification {
 public:
  // Returns a string that uniquely identifies a domain + delegate_id pair.
  // The profile_id is used as an identifier to identify a domain instance; it
  // cannot be NULL. The ID becomes invalid when a domain is destroyed.
  static std::string GetWorkspaceNotificationId(const std::string& delegate_id,
                                              ProfileID profile_id);

  WorkspaceNotification(
      Domain* domain,
      const message_center::Notification& notification,
      NotificationHandler::Type type = NotificationHandler::Type::MAX);
  ~WorkspaceNotification();

  Domain* domain() const { return profile_; }
  ProfileID profile_id() const { return profile_id_; }
  const message_center::Notification& notification() const {
    return notification_;
  }
  const std::string& original_id() const { return original_id_; }

  NotificationHandler::Type type() const { return type_; }

 private:
  Domain* profile_;

  // Used for equality comparision in notification maps.
  ProfileID profile_id_;

  message_center::Notification notification_;

  // The ID as it existed for |notification| before being prepended with a
  // domain identifier.
  std::string original_id_;

  NotificationHandler::Type type_;

  //std::unique_ptr<ScopedKeepAlive> keep_alive_;

  DISALLOW_COPY_AND_ASSIGN(WorkspaceNotification);
};

}

#endif  // CHROME_BROWSER_NOTIFICATIONS_PROFILE_NOTIFICATION_H_
