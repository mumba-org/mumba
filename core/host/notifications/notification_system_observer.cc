// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/notifications/notification_system_observer.h"

#include "base/logging.h"
#include "core/host/host.h"
#include "core/host/notification_types.h"
#include "core/host/notifications/notification_ui_manager.h"
#include "core/host/application/domain.h"
#include "core/host/notification_service.h"

namespace host {

NotificationSystemObserver::NotificationSystemObserver(
    NotificationUIManager* ui_manager)
    : ui_manager_(ui_manager) {
  DCHECK(ui_manager_);
  registrar_.Add(this, NOTIFICATION_APP_TERMINATING,
                 NotificationService::AllSources());
}

NotificationSystemObserver::~NotificationSystemObserver() {
}

void NotificationSystemObserver::Observe(
    int type,
    const NotificationSource& source,
    const NotificationDetails& details) {
  switch (type) {
    case NOTIFICATION_APP_TERMINATING:
      ui_manager_->StartShutdown();
      break;
    default:
      NOTREACHED();
  }
}


}