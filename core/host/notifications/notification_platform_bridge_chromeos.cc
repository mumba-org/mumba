// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/notifications/notification_platform_bridge_chromeos.h"

#include "core/host/browser_process.h"
#include "core/host/chrome_notification_types.h"
#include "core/host/notifications/chrome_ash_message_center_client.h"
#include "core/host/notifications/notification_display_service_impl.h"
#include "core/host/application/domain.h"
#include "core/host/profiles/profile_manager.h"
#include "core/host/ui/app_icon_loader.h"
#include "ui/gfx/image/image.h"

// static
NotificationPlatformBridge* NotificationPlatformBridge::Create() {
  return new NotificationPlatformBridgeChromeOs();
}

// static
bool NotificationPlatformBridge::CanHandleType(
    NotificationHandler::Type notification_type) {
  return true;
}

NotificationPlatformBridgeChromeOs::NotificationPlatformBridgeChromeOs()
    : impl_(std::make_unique<ChromeAshMessageCenterClient>(this)) {}

NotificationPlatformBridgeChromeOs::~NotificationPlatformBridgeChromeOs() {}

void NotificationPlatformBridgeChromeOs::Display(
    NotificationHandler::Type notification_type,
    Domain* domain,
    const message_center::Notification& notification,
    std::unique_ptr<NotificationCommon::Metadata> metadata) {
  auto active_notification = std::make_unique<WorkspaceNotification>(
      domain, notification, notification_type);
  impl_->Display(active_notification->notification());

  std::string domain_notification_id =
      active_notification->notification().id();
  active_notifications_.emplace(domain_notification_id,
                                std::move(active_notification));
}

void NotificationPlatformBridgeChromeOs::Close(
    Domain* domain,
    const std::string& notification_id) {
  const std::string domain_notification_id =
      WorkspaceNotification::GetWorkspaceNotificationId(
          notification_id, NotificationUIManager::GetProfileID(domain));

  impl_->Close(domain_notification_id);
}

void NotificationPlatformBridgeChromeOs::GetDisplayed(
    Domain* domain,
    GetDisplayedNotificationsCallback callback) const {
  // Right now, this is only used to get web notifications that were created by
  // and have outlived a previous browser process. Ash itself doesn't outlive
  // the browser process, so there's no need to implement.
  std::move(callback).Run(std::make_unique<std::set<std::string>>(), false);
}

void NotificationPlatformBridgeChromeOs::SetReadyCallback(
    NotificationBridgeReadyCallback callback) {
  // We don't handle the absence of Ash or a failure to open a Mojo connection,
  // so just assume the client is ready.
  std::move(callback).Run(true);
}

void NotificationPlatformBridgeChromeOs::HandleNotificationClosed(
    const std::string& id,
    bool by_user) {
  auto iter = active_notifications_.find(id);
  DCHECK(iter != active_notifications_.end());
  WorkspaceNotification* notification = iter->second.get();

  if (notification->type() == NotificationHandler::Type::TRANSIENT) {
    notification->notification().delegate()->Close(by_user);
  } else {
    NotificationDisplayServiceImpl::GetForProfile(notification->domain())
        ->ProcessNotificationOperation(
            NotificationCommon::CLOSE, notification->type(),
            notification->notification().origin_url(),
            notification->original_id(), base::nullopt, base::nullopt, by_user);
  }
  active_notifications_.erase(iter);
}

void NotificationPlatformBridgeChromeOs::HandleNotificationClicked(
    const std::string& id) {
  WorkspaceNotification* notification = GetWorkspaceNotification(id);
  if (notification->type() == NotificationHandler::Type::TRANSIENT) {
    notification->notification().delegate()->Click(base::nullopt,
                                                   base::nullopt);
  } else {
    NotificationDisplayServiceImpl::GetForProfile(notification->domain())
        ->ProcessNotificationOperation(
            NotificationCommon::CLICK, notification->type(),
            notification->notification().origin_url(),
            notification->original_id(), base::nullopt, base::nullopt,
            base::nullopt);
  }
}

void NotificationPlatformBridgeChromeOs::HandleNotificationButtonClicked(
    const std::string& id,
    int button_index,
    const base::Optional<base::string16>& reply) {
  WorkspaceNotification* notification = GetWorkspaceNotification(id);
  if (notification->type() == NotificationHandler::Type::TRANSIENT) {
    notification->notification().delegate()->Click(button_index, reply);
  } else {
    NotificationDisplayServiceImpl::GetForProfile(notification->domain())
        ->ProcessNotificationOperation(
            NotificationCommon::CLICK, notification->type(),
            notification->notification().origin_url(),
            notification->original_id(), button_index, reply, base::nullopt);
  }
}

void NotificationPlatformBridgeChromeOs::
    HandleNotificationSettingsButtonClicked(const std::string& id) {
  WorkspaceNotification* notification = GetWorkspaceNotification(id);
  if (notification->type() == NotificationHandler::Type::TRANSIENT) {
    notification->notification().delegate()->SettingsClick();
  } else {
    NotificationDisplayServiceImpl::GetForProfile(notification->domain())
        ->ProcessNotificationOperation(
            NotificationCommon::SETTINGS, notification->type(),
            notification->notification().origin_url(),
            notification->original_id(), base::nullopt, base::nullopt,
            base::nullopt);
  }
}

void NotificationPlatformBridgeChromeOs::DisableNotification(
    const std::string& id) {
  WorkspaceNotification* notification = GetWorkspaceNotification(id);
  DCHECK_NE(NotificationHandler::Type::TRANSIENT, notification->type());
  NotificationDisplayServiceImpl::GetForProfile(notification->domain())
      ->ProcessNotificationOperation(NotificationCommon::DISABLE_PERMISSION,
                                     notification->type(),
                                     notification->notification().origin_url(),
                                     notification->original_id(), base::nullopt,
                                     base::nullopt, base::nullopt);
}

WorkspaceNotification* NotificationPlatformBridgeChromeOs::GetWorkspaceNotification(
    const std::string& domain_notification_id) {
  auto iter = active_notifications_.find(domain_notification_id);
  DCHECK(iter != active_notifications_.end());
  return iter->second.get();
}
