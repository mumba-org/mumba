// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/notifications/message_center_notification_manager.h"

#include <memory>
#include <utility>

#include "base/logging.h"
#include "build/build_config.h"
#include "core/host/notifications/workspace_notification.h"
#include "core/host/application/domain.h"
#include "core/host/host_thread.h"
#include "core/host/application/application_contents.h"
#include "core/shared/common/url_constants.h"
#include "ui/gfx/image/image_skia.h"
#include "ui/message_center/message_center.h"
#include "ui/message_center/message_center_types.h"
#include "ui/message_center/public/cpp/message_center_constants.h"
#include "ui/message_center/public/cpp/notification.h"
#include "ui/message_center/public/cpp/notifier_id.h"
#include "ui/message_center/ui_controller.h"

#if !defined(OS_CHROMEOS)
#include "core/host/notifications/fullscreen_notification_blocker.h"
#include "core/host/notifications/screen_lock_notification_blocker.h"
#endif

using message_center::MessageCenter;
using message_center::NotifierId;

namespace host {

MessageCenterNotificationManager::MessageCenterNotificationManager()
    : system_observer_(this) {
  auto* message_center = MessageCenter::Get();
  message_center->AddObserver(this);

#if !defined(OS_CHROMEOS)
  blockers_.push_back(
      std::make_unique<ScreenLockNotificationBlocker>(message_center));
  blockers_.push_back(
      std::make_unique<FullscreenNotificationBlocker>(message_center));
#endif

#if defined(OS_WIN) || defined(OS_MACOSX) \
  || (defined(OS_LINUX) && !defined(OS_CHROMEOS))
  // On Windows, Linux and Mac, the notification manager owns the tray icon and
  // views.Other platforms have global ownership and Create will return NULL.
  tray_.reset(CreateUiDelegate());
#endif
}

MessageCenterNotificationManager::~MessageCenterNotificationManager() {
  // The message center may have already been shut down (on Chrome OS).
  if (MessageCenter::Get())
    MessageCenter::Get()->RemoveObserver(this);

  domain_notifications_.clear();
}

////////////////////////////////////////////////////////////////////////////////
// NotificationUIManager

void MessageCenterNotificationManager::Add(
    const message_center::Notification& notification,
    Domain* domain) {
  // We won't have time to process and act on this notification.
  if (is_shutdown_started_)
    return;

  if (Update(notification, domain))
    return;

  auto domain_notification_ptr =
      std::make_unique<WorkspaceNotification>(domain, notification);
  WorkspaceNotification* domain_notification = domain_notification_ptr.get();

  // WARNING: You MUST use AddWorkspaceNotification or update the message center
  // via the notification within a WorkspaceNotification object or the domain ID
  // will not be correctly set for ChromeOS.
  // Takes ownership of domain_notification.
  AddWorkspaceNotification(std::move(domain_notification_ptr));

  MessageCenter::Get()->AddNotification(
      std::make_unique<message_center::Notification>(
          domain_notification->notification()));
}

bool MessageCenterNotificationManager::Update(
    const message_center::Notification& notification,
    Domain* domain) {
  const std::string profile_id = WorkspaceNotification::GetWorkspaceNotificationId(
      notification.id(), NotificationUIManager::GetProfileID(domain));
  for (auto iter = domain_notifications_.begin();
       iter != domain_notifications_.end(); ++iter) {
    WorkspaceNotification* old_notification = (*iter).second.get();
    if (old_notification->notification().id() != profile_id)
      continue;

    // The ID should uniquely identify the notification, but as a sanity check
    // make sure we got the right origin URL and domain.
    DCHECK_EQ(old_notification->notification().origin_url(),
              notification.origin_url());
    DCHECK_EQ(old_notification->profile_id(),
              NotificationUIManager::GetProfileID(domain));

    // Changing the type from non-progress to progress does not count towards
    // the immediate update allowed in the message center.
    std::string old_id = old_notification->notification().id();

    // Add/remove notification in the local list but just update the same
    // one in MessageCenter.
    auto new_notification =
        std::make_unique<WorkspaceNotification>(domain, notification);
    const message_center::Notification& notification =
        new_notification->notification();
    // Delete the old one after the new one is created to ensure we don't run
    // out of KeepAlives.
    domain_notifications_.erase(old_id);
    domain_notifications_[notification.id()] = std::move(new_notification);

    // TODO(liyanhou): Add routing updated notifications to alternative
    // providers.

    // WARNING: You MUST use AddWorkspaceNotification or update the message
    // center via the notification within a WorkspaceNotification object or the
    // domain ID will not be correctly set for ChromeOS.
    MessageCenter::Get()->UpdateNotification(
        old_id, std::make_unique<message_center::Notification>(notification));
    return true;
  }

  return false;
}

const message_center::Notification* MessageCenterNotificationManager::FindById(
    const std::string& id,
    ProfileID profile_id) const {
  std::string domain_notification_id =
      WorkspaceNotification::GetWorkspaceNotificationId(id, profile_id);
  auto iter = domain_notifications_.find(domain_notification_id);
  if (iter == domain_notifications_.end())
    return nullptr;
  return &(iter->second->notification());
}

bool MessageCenterNotificationManager::CancelById(const std::string& id,
                                                  ProfileID profile_id) {
  std::string domain_notification_id =
      WorkspaceNotification::GetWorkspaceNotificationId(id, profile_id);
  // See if this ID hasn't been shown yet.
  // If it has been shown, remove it.
  auto iter = domain_notifications_.find(domain_notification_id);
  if (iter == domain_notifications_.end())
    return false;

  RemoveWorkspaceNotification(iter->first);
  MessageCenter::Get()->RemoveNotification(domain_notification_id,
                                           /* by_user */ false);
  return true;
}

std::set<std::string> MessageCenterNotificationManager::GetAllIdsByProfile(
    ProfileID profile_id) {
  std::set<std::string> original_ids;
  for (const auto& pair : domain_notifications_) {
    if (pair.second->profile_id() == profile_id)
      original_ids.insert(pair.second->original_id());
  }

  return original_ids;
}

bool MessageCenterNotificationManager::CancelAllBySourceOrigin(
    const GURL& source) {
  // Same pattern as CancelById, but more complicated than the above
  // because there may be multiple notifications from the same source.
  bool removed = false;

  for (auto loopiter = domain_notifications_.begin();
       loopiter != domain_notifications_.end();) {
    auto curiter = loopiter++;
    if ((*curiter).second->notification().origin_url() == source) {
      const std::string id = curiter->first;
      RemoveWorkspaceNotification(id);
      MessageCenter::Get()->RemoveNotification(id, /* by_user */ false);
      removed = true;
    }
  }
  return removed;
}

bool MessageCenterNotificationManager::CancelAllByProfile(
    ProfileID profile_id) {
  // Same pattern as CancelAllBySourceOrigin.
  bool removed = false;

  for (auto loopiter = domain_notifications_.begin();
       loopiter != domain_notifications_.end();) {
    auto curiter = loopiter++;
    if (profile_id == (*curiter).second->profile_id()) {
      const std::string id = curiter->first;
      RemoveWorkspaceNotification(id);
      MessageCenter::Get()->RemoveNotification(id, /* by_user */ false);
      removed = true;
    }
  }
  return removed;
}

void MessageCenterNotificationManager::CancelAll() {
  MessageCenter::Get()->RemoveAllNotifications(
      false /* by_user */, message_center::MessageCenter::RemoveType::ALL);
}

void MessageCenterNotificationManager::StartShutdown() {
  is_shutdown_started_ = true;
  CancelAll();
}

////////////////////////////////////////////////////////////////////////////////
// MessageCenter::Observer
void MessageCenterNotificationManager::OnNotificationRemoved(
    const std::string& id,
    bool by_user) {
  RemoveWorkspaceNotification(id);
}

void MessageCenterNotificationManager::SetUiDelegateForTest(
    message_center::UiDelegate* delegate) {
  tray_.reset(delegate);
}

std::string
MessageCenterNotificationManager::GetMessageCenterNotificationIdForTest(
    const std::string& id,
    Domain* domain) {
  return WorkspaceNotification::GetWorkspaceNotificationId(id,
                                                       GetProfileID(domain));
}

////////////////////////////////////////////////////////////////////////////////
// private

void MessageCenterNotificationManager::AddWorkspaceNotification(
    std::unique_ptr<WorkspaceNotification> domain_notification) {
  const message_center::Notification& notification =
      domain_notification->notification();
  std::string id = notification.id();
  // Notification ids should be unique.
  DCHECK(domain_notifications_.find(id) == domain_notifications_.end());
  domain_notifications_[id] = std::move(domain_notification);
}

void MessageCenterNotificationManager::RemoveWorkspaceNotification(
    const std::string& notification_id) {
  auto it = domain_notifications_.find(notification_id);
  if (it == domain_notifications_.end())
    return;

  // Delay destruction of the WorkspaceNotification until current task is
  // completed. This must be done because this WorkspaceNotification might have
  // the one ScopedKeepAlive object that was keeping the browser alive, and
  // destroying it would result in:
  // a) A reentrant call to this class. Because every method in this class
  //   touches |domain_notifications_|, |domain_notifications_| must always
  //   be in a self-consistent state in moments where re-entrance might happen.
  // b) A crash like https://crbug.com/649971 because it can trigger
  //    shutdown process while we're still inside the call stack from UI
  //    framework.
  HostThread::DeleteSoon(HostThread::UI, FROM_HERE,
                                     it->second.release());
  domain_notifications_.erase(it);
}

WorkspaceNotification* MessageCenterNotificationManager::FindWorkspaceNotification(
    const std::string& id) const {
  auto iter = domain_notifications_.find(id);
  if (iter == domain_notifications_.end())
    return nullptr;

  return (*iter).second.get();
}

}