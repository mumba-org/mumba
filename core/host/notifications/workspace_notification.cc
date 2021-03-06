// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/notifications/workspace_notification.h"

#include "base/strings/stringprintf.h"
#include "build/build_config.h"
//#include "core/host/ui/ash/multi_user/multi_user_util.h"
#include "components/keep_alive_registry/keep_alive_types.h"
#include "components/keep_alive_registry/scoped_keep_alive.h"
//#include "components/signin/core/account_id/account_id.h"

namespace host {

// static
std::string WorkspaceNotification::GetWorkspaceNotificationId(
    const std::string& delegate_id,
    ProfileID profile_id) {
  DCHECK(profile_id);
  return base::StringPrintf("notification-ui-manager#%p#%s",
                            profile_id,  // Each domain has its unique instance
                                         // including incognito domain.
                            delegate_id.c_str());
}

WorkspaceNotification::WorkspaceNotification(
    Domain* domain,
    const message_center::Notification& notification,
    NotificationHandler::Type type)
    : profile_(domain),
      profile_id_(NotificationUIManager::GetProfileID(domain)),
      notification_(
          // Uses Notification's copy constructor to assign the message center
          // id, which should be unique for every domain + Notification pair.
          GetWorkspaceNotificationId(
              notification.id(),
              NotificationUIManager::GetProfileID(domain)),
          notification),
      original_id_(notification.id()),
      type_(type) {
  DCHECK(domain);
// #if defined(OS_CHROMEOS)
//   notification_.set_profile_id(
//       multi_user_util::GetAccountIdFromProfile(domain).GetUserEmail());
// #else
  // This ScopedKeepAlive prevents the browser process from shutting down when
  // the last browser window is closed and there are open notifications. It's
  // not used on Chrome OS as closing the last browser window never shuts down
  // the process.
  //keep_alive_ = std::make_unique<ScopedKeepAlive>(
  //    KeepAliveOrigin::NOTIFICATION, KeepAliveRestartOption::DISABLED);
//#endif
}

WorkspaceNotification::~WorkspaceNotification() {}

}