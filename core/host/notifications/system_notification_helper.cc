// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/notifications/system_notification_helper.h"

#include "core/host/host.h"
#include "core/host/notifications/notification_display_service.h"
//#include "core/host/profiles/profile_manager.h"

//#if defined(OS_CHROMEOS)
//#include "core/host/chromeos/profiles/profile_helper.h"
//#endif

namespace host {

SystemNotificationHelper* SystemNotificationHelper::GetInstance() {
  return base::Singleton<SystemNotificationHelper>::get();
}

SystemNotificationHelper::SystemNotificationHelper() = default;
SystemNotificationHelper::~SystemNotificationHelper() = default;

void SystemNotificationHelper::Display(
    const message_center::Notification& notification) {
  pending_notifications_[notification.id()] = notification;
  // g_browser_process->profile_manager()->CreateProfileAsync(
  //     GetProfilePath(),
  //     base::AdaptCallbackForRepeating(
  //         base::BindOnce(&SystemNotificationHelper::DoDisplayNotification,
  //                        weak_factory_.GetWeakPtr(), notification.id())),
  //     base::string16(), std::string(), std::string());
}

void SystemNotificationHelper::Close(const std::string& notification_id) {
  //size_t erased = pending_notifications_.erase(notification_id);
  DLOG(INFO) << "SystemNotificationHelper::Close: not working. dont have access to (a global) Domain from here. FIX";
  // Domain* domain = Domain::GetCurrent();
  // //     //g_browser_process->profile_manager()->GetProfileByPath(GetProfilePath());
  // if (!domain)
  //    return;

  // // If the domain has finished loading, we should have already removed the
  // // notification from the pending list in DoDisplayNotification().
  // DCHECK_EQ(0u, erased);
  // NotificationDisplayService::GetForDomain(domain)
  //     ->Close(NotificationHandler::Type::TRANSIENT, notification_id);
}

void SystemNotificationHelper::DoDisplayNotification(
    const std::string& notification_id,
    Domain* domain) {//,
 //   Domain::CreateStatus status) {
  auto iter = pending_notifications_.find(notification_id);
  if (iter == pending_notifications_.end())
    return;

  if (domain) {
    // We use the incognito domain both to match
    // ProfileHelper::GetSigninProfile() and to be sure we don't store anything
    // about it across program restarts.
    NotificationDisplayService::GetForProfile(domain)
        ->Display(NotificationHandler::Type::TRANSIENT, iter->second);
  }
  pending_notifications_.erase(iter);
}

// static
Domain* SystemNotificationHelper::GetProfileForTesting() {
  // return g_browser_process->profile_manager()
  //     ->GetProfile(GetProfilePath())
  //     ->GetOffTheRecordProfile();
  return nullptr;
}

// static
base::FilePath SystemNotificationHelper::GetProfilePath() {
// #if defined(OS_CHROMEOS)
//   // System notifications (such as those for network state) aren't tied to a
//   // particular user and can show up before any user is logged in, so use the
//   // signin domain, which is guaranteed to already exist.
//   return chromeos::ProfileHelper::GetSigninProfileDir();
// #else
//   // The "system domain" probably hasn't been loaded yet.
//   return g_browser_process->profile_manager()->GetSystemProfilePath();
// #endif
 scoped_refptr<Workspace> workspace = Workspace::GetCurrent();
 return workspace->root_path();
}

}