// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/ui/load_complete_listener.h"

//#include "base/check_op.h"
#include "base/logging.h"
#include "core/host/notification_service.h"
#include "core/host/notification_types.h"

namespace host {

LoadCompleteListener::LoadCompleteListener(Delegate* delegate)
    : delegate_(delegate) {
  DCHECK(delegate);
  // Register for notification of when initial page load is complete to ensure
  // that we wait until start-up is complete before calling the callback.
  registrar_.Add(this, NOTIFICATION_LOAD_COMPLETED_MAIN_FRAME,
                 NotificationService::AllSources());
}

LoadCompleteListener::~LoadCompleteListener() {
  if (registrar_.IsRegistered(this,
      NOTIFICATION_LOAD_COMPLETED_MAIN_FRAME,
      NotificationService::AllSources())) {
    registrar_.Remove(this, NOTIFICATION_LOAD_COMPLETED_MAIN_FRAME,
                      NotificationService::AllSources());
  }
}

void LoadCompleteListener::Observe(
    int type,
    const NotificationSource& source,
    const NotificationDetails& details) {
  DCHECK_EQ(NOTIFICATION_LOAD_COMPLETED_MAIN_FRAME, type);

  delegate_->OnLoadCompleted();
  registrar_.Remove(this, NOTIFICATION_LOAD_COMPLETED_MAIN_FRAME,
                    NotificationService::AllSources());
}

}