// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_NOTIFICATIONS_NOTIFICATION_SYSTEM_OBSERVER_H_
#define CHROME_BROWSER_NOTIFICATIONS_NOTIFICATION_SYSTEM_OBSERVER_H_

#include "base/macros.h"
#include "base/scoped_observer.h"
#include "core/host/notification_observer.h"
#include "core/host/notification_registrar.h"

namespace host {
class NotificationUIManager;

// The NotificationObserver observes system status change and sends
// events to NotificationUIManager. NOTE: NotificationUIManager is deprecated,
// to be replaced by NotificationDisplayService, so this class should go away.
class NotificationSystemObserver : public NotificationObserver {
 public:
  explicit NotificationSystemObserver(NotificationUIManager* ui_manager);
  ~NotificationSystemObserver() override;

 protected:
  // NotificationObserver override.
  void Observe(int type,
               const NotificationSource& source,
               const NotificationDetails& details) override;

  
 private:
  // Registrar for the other kind of notifications (event signaling).
  NotificationRegistrar registrar_;
  NotificationUIManager* ui_manager_;

  DISALLOW_COPY_AND_ASSIGN(NotificationSystemObserver);
};
}

#endif  // CHROME_BROWSER_NOTIFICATIONS_NOTIFICATION_SYSTEM_OBSERVER_H_
