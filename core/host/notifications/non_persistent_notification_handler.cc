// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/notifications/non_persistent_notification_handler.h"

#include "base/callback.h"
#include "base/strings/nullable_string16.h"
#include "core/host/notifications/desktop_notification_profile_util.h"
#include "core/host/notifications/platform_notification_service_impl.h"
#include "core/host/notification_event_dispatcher.h"

namespace host {

NonPersistentNotificationHandler::NonPersistentNotificationHandler() = default;
NonPersistentNotificationHandler::~NonPersistentNotificationHandler() = default;

void NonPersistentNotificationHandler::OnShow(
    Domain* domain,
    const std::string& notification_id) {
  NotificationEventDispatcher::GetInstance()
      ->DispatchNonPersistentShowEvent(notification_id);
}

void NonPersistentNotificationHandler::OnClose(
    Domain* domain,
    const GURL& origin,
    const std::string& notification_id,
    bool by_user,
    base::OnceClosure completed_closure) {
  NotificationEventDispatcher::GetInstance()
      ->DispatchNonPersistentCloseEvent(notification_id);

  // TODO(crbug.com/787459): Implement event acknowledgements once
  // non-persistent notifications have updated to use Mojo instead of IPC.
  std::move(completed_closure).Run();
}

void NonPersistentNotificationHandler::OnClick(
    Domain* domain,
    const GURL& origin,
    const std::string& notification_id,
    const base::Optional<int>& action_index,
    const base::Optional<base::string16>& reply,
    base::OnceClosure completed_closure) {
  // Non persistent notifications don't allow buttons or replies.
  // https://notifications.spec.whatwg.org/#create-a-notification
  DCHECK(!action_index.has_value());
  DCHECK(!reply.has_value());

  NotificationEventDispatcher::GetInstance()
      ->DispatchNonPersistentClickEvent(notification_id);

  // TODO(crbug.com/787459): Implement event acknowledgements once
  // non-persistent notifications have updated to use Mojo instead of IPC.
  std::move(completed_closure).Run();
}

void NonPersistentNotificationHandler::DisableNotifications(
    Domain* domain,
    const GURL& origin) {
  DesktopNotificationProfileUtil::DenyPermission(domain, origin);
}

void NonPersistentNotificationHandler::OpenSettings(Domain* domain,
                                                    const GURL& origin) {
  NotificationCommon::OpenNotificationSettings(domain, origin);
}

}