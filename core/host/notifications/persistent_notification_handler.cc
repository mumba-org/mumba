// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/notifications/persistent_notification_handler.h"

#include "base/callback.h"
#include "base/logging.h"
#include "core/host/notifications/desktop_notification_profile_util.h"
#include "core/host/notifications/platform_notification_service_impl.h"
#include "core/host/application/domain.h"

namespace host {

PersistentNotificationHandler::PersistentNotificationHandler() = default;
PersistentNotificationHandler::~PersistentNotificationHandler() = default;

void PersistentNotificationHandler::OnClose(
    Domain* domain,
    const GURL& origin,
    const std::string& notification_id,
    bool by_user,
    base::OnceClosure completed_closure) {
  if (!by_user) {
    std::move(completed_closure).Run();
    return;  // no need to propagate back programmatic close events
  }

  DCHECK(origin.is_valid());

  PlatformNotificationServiceImpl::GetInstance()->OnPersistentNotificationClose(
      domain, notification_id, origin, by_user, std::move(completed_closure));
}

void PersistentNotificationHandler::OnClick(
    Domain* domain,
    const GURL& origin,
    const std::string& notification_id,
    const base::Optional<int>& action_index,
    const base::Optional<base::string16>& reply,
    base::OnceClosure completed_closure) {
  DCHECK(origin.is_valid());

  PlatformNotificationServiceImpl::GetInstance()->OnPersistentNotificationClick(
      domain, notification_id, origin, action_index, reply,
      std::move(completed_closure));
}

void PersistentNotificationHandler::DisableNotifications(Domain* domain,
                                                         const GURL& origin) {
  DesktopNotificationProfileUtil::DenyPermission(domain, origin);
}

void PersistentNotificationHandler::OpenSettings(Domain* domain,
                                                 const GURL& origin) {
  NotificationCommon::OpenNotificationSettings(domain, origin);
}

}