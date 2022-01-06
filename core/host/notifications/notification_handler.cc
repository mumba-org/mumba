// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/notifications/notification_handler.h"

#include "base/callback.h"

namespace host {

NotificationHandler::~NotificationHandler() = default;

void NotificationHandler::OnShow(Domain* domain,
                                 const std::string& notification_id) {}

void NotificationHandler::OnClose(Domain* domain,
                                  const GURL& origin,
                                  const std::string& notification_id,
                                  bool by_user,
                                  base::OnceClosure completed_closure) {
  std::move(completed_closure).Run();
}

void NotificationHandler::OnClick(Domain* domain,
                                  const GURL& origin,
                                  const std::string& notification_id,
                                  const base::Optional<int>& action_index,
                                  const base::Optional<base::string16>& reply,
                                  base::OnceClosure completed_closure) {
  std::move(completed_closure).Run();
}

void NotificationHandler::DisableNotifications(Domain* domain,
                                               const GURL& origin) {
  NOTREACHED();
}

void NotificationHandler::OpenSettings(Domain* domain, const GURL& origin) {
  // Notification types that display a settings button must override this method
  // to handle user interaction with it.
  NOTREACHED();
}

}