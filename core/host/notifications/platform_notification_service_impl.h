// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_NOTIFICATIONS_PLATFORM_NOTIFICATION_SERVICE_IMPL_H_
#define CHROME_BROWSER_NOTIFICATIONS_PLATFORM_NOTIFICATION_SERVICE_IMPL_H_

#include <stdint.h>

#include <map>
#include <memory>
#include <set>
#include <string>
#include <unordered_set>

#include "base/callback_forward.h"
#include "base/gtest_prod_util.h"
#include "base/macros.h"
#include "base/memory/singleton.h"
#include "base/optional.h"
#include "base/strings/string16.h"
#include "core/host/notifications/notification_common.h"
#include "core/host/application/domain.h"
//#include "core/common/buildflags.h"
#include "core/host/platform_notification_service.h"
#include "core/shared/common/persistent_notification_status.h"
#include "third_party/blink/public/platform/modules/permissions/permission_status.mojom.h"
#include "ui/message_center/public/cpp/notification.h"

namespace host {
class Domain;
struct NotificationResources;
class NotificationDelegate;
class ScopedKeepAlive;
// The platform notification service is the domain-agnostic entry point through
// which Web Notifications can be controlled.
class PlatformNotificationServiceImpl
    : public PlatformNotificationService {
 public:
  // Returns the active instance of the service in the browser process. Safe to
  // be called from any thread.
  static PlatformNotificationServiceImpl* GetInstance();

  // To be called when a persistent notification has been clicked on. The
  // Service Worker associated with the registration will be started if
  // needed, on which the event will be fired. Must be called on the UI thread.
  void OnPersistentNotificationClick(
      Domain* domain,
      const std::string& notification_id,
      const GURL& origin,
      const base::Optional<int>& action_index,
      const base::Optional<base::string16>& reply,
      base::OnceClosure completed_closure);

  // To be called when a persistent notification has been closed. The data
  // associated with the notification has to be pruned from the database in this
  // case, to make sure that it continues to be in sync. Must be called on the
  // UI thread.
  void OnPersistentNotificationClose(Domain* domain,
                                     const std::string& notification_id,
                                     const GURL& origin,
                                     bool by_user,
                                     base::OnceClosure completed_closure);

  // PlatformNotificationService implementation.
  blink::mojom::PermissionStatus CheckPermissionOnUIThread(
      Domain* domain,
      const GURL& origin,
      int render_process_id) override;
  blink::mojom::PermissionStatus CheckPermissionOnIOThread(
      ResourceContext* resource_context,
      const GURL& origin,
      int render_process_id) override;
  void DisplayNotification(
      Domain* domain,
      const std::string& notification_id,
      const GURL& origin,
      const common::PlatformNotificationData& notification_data,
      const common::NotificationResources& notification_resources) override;
  void DisplayPersistentNotification(
      Domain* domain,
      const std::string& notification_id,
      const GURL& service_worker_scope,
      const GURL& origin,
      const common::PlatformNotificationData& notification_data,
      const common::NotificationResources& notification_resources) override;
  void CloseNotification(Domain* domain,
                         const std::string& notification_id) override;
  void ClosePersistentNotification(Domain* domain,
                                   const std::string& notification_id) override;
  void GetDisplayedNotifications(
      Domain* domain,
      const DisplayedNotificationsCallback& callback) override;

 private:
  friend struct base::DefaultSingletonTraits<PlatformNotificationServiceImpl>;
  friend class PlatformNotificationServiceBrowserTest;
  friend class PlatformNotificationServiceTest;
  friend class PushMessagingBrowserTest;
  FRIEND_TEST_ALL_PREFIXES(PlatformNotificationServiceTest,
                           CreateNotificationFromData);
  FRIEND_TEST_ALL_PREFIXES(PlatformNotificationServiceTest,
                           DisplayNameForContextMessage);

  PlatformNotificationServiceImpl();
  ~PlatformNotificationServiceImpl() override;

  void OnClickEventDispatchComplete(
      base::OnceClosure completed_closure,
      common::PersistentNotificationStatus status);
  void OnCloseEventDispatchComplete(
      base::OnceClosure completed_closure,
      common::PersistentNotificationStatus status);

  // Creates a new Web Notification-based Notification object. Should only be
  // called when the notification is first shown.
  // TODO(peter): |delegate| can be a scoped_refptr, but properly passing this
  // through requires changing a whole lot of Notification constructor calls.
  message_center::Notification CreateNotificationFromData(
      Domain* domain,
      const GURL& origin,
      const std::string& notification_id,
      const common::PlatformNotificationData& notification_data,
      const common::NotificationResources& notification_resources,
      scoped_refptr<message_center::NotificationDelegate> delegate) const;

  // Returns a display name for an origin, to be used in the context message
  base::string16 DisplayNameForContextMessage(Domain* domain,
                                              const GURL& origin) const;

  void RecordSiteEngagement(Domain* domain,
                            const GURL& origin);

//#if BUILDFLAG(ENABLE_BACKGROUND_MODE)
  // Makes sure we keep the browser alive while the event in being processed.
  // As we have no control on the click handling, the notification could be
  // closed before a browser is brought up, thus terminating Chrome if it was
  // the last KeepAlive. (see https://crbug.com/612815)
  //::unique_ptr<ScopedKeepAlive> click_dispatch_keep_alive_;

  //int pending_click_dispatch_events_;
//#endif

  // Tracks the id of persistent notifications that have been closed
  // programmatically to avoid dispatching close events for them.
  std::unordered_set<std::string> closed_notifications_;

  DISALLOW_COPY_AND_ASSIGN(PlatformNotificationServiceImpl);
};

}

#endif  // CHROME_BROWSER_NOTIFICATIONS_PLATFORM_NOTIFICATION_SERVICE_IMPL_H_
