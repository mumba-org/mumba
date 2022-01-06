// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_NOTIFICATIONS_SYSTEM_NOTIFICATION_HELPER_H_
#define CHROME_BROWSER_NOTIFICATIONS_SYSTEM_NOTIFICATION_HELPER_H_

#include "base/files/file_path.h"
#include "base/memory/singleton.h"
#include "base/memory/weak_ptr.h"
#include "core/host/application/domain.h"
#include "ui/message_center/public/cpp/notification.h"

namespace host {
// This class assists in displaying notifications that do not have an associated
// Domain. It uses a system domain which may not be loaded. Thus, Display() is
// not always synchronous.
class SystemNotificationHelper {
 public:
  // Returns the singleton instance.
  static SystemNotificationHelper* GetInstance();

  // Displays a notification which isn't tied to a normal user domain. The
  // notification will be displayed asynchronously if the generic domain has
  // not yet been loaded.
  void Display(const message_center::Notification& notification);

  // Closes a notification which isn't tied to a normal user domain.
  void Close(const std::string& notification_id);

  // Loads the domain used for the domain-agnostic NotificationDisplayService.
  static Domain* GetProfileForTesting();

 private:
  friend struct base::DefaultSingletonTraits<SystemNotificationHelper>;

  SystemNotificationHelper();
  ~SystemNotificationHelper();

  void DoDisplayNotification(const std::string& notification_id,
                             Domain* domain);//,
                             //Domain::CreateStatus status);

  // Returns the path for a non-user-specific domain. This will be used for
  // system notifications which aren't tied to a particular normal domain.
  static base::FilePath GetProfilePath();

  // Notifications are added to this queue when the system domain has not yet
  // been loaded. They are removed in Close() if it's called before the domain
  // loads, or after the notification is displayed if that happens first.
  std::map<std::string, message_center::Notification> pending_notifications_;

  base::WeakPtrFactory<SystemNotificationHelper> weak_factory_{this};

  DISALLOW_COPY_AND_ASSIGN(SystemNotificationHelper);
};

}

#endif  // CHROME_BROWSER_NOTIFICATIONS_SYSTEM_NOTIFICATION_HELPER_H_
