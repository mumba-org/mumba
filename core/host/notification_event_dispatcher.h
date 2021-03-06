// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_PUBLIC_BROWSER_NOTIFICATION_EVENT_DISPATCHER_H_
#define CONTENT_PUBLIC_BROWSER_NOTIFICATION_EVENT_DISPATCHER_H_

#include <string>

#include "base/callback_forward.h"
#include "base/optional.h"
#include "base/strings/string16.h"
#include "core/shared/common/content_export.h"
#include "core/shared/common/persistent_notification_status.h"

class GURL;

namespace host {

class Domain;

// This is the dispatcher to be used for firing events related to notifications.
// This class is a singleton, the instance of which can be retrieved using the
// static GetInstance() method. All methods must be called on the UI thread.
class CONTENT_EXPORT NotificationEventDispatcher {
 public:
  static NotificationEventDispatcher* GetInstance();

  using NotificationDispatchCompleteCallback =
      base::OnceCallback<void(common::PersistentNotificationStatus)>;

  // Dispatch methods for persistent (SW backed) notifications.
  // TODO(miguelg) consider merging them with the non persistent ones below.

  // Dispatches the "notificationclick" event on the Service Worker associated
  // with |notification_id| belonging to |origin|. The |callback| will be
  // invoked when it's known whether the event successfully executed.
  virtual void DispatchNotificationClickEvent(
      Domain* domain,
      const std::string& notification_id,
      const GURL& origin,
      const base::Optional<int>& action_index,
      const base::Optional<base::string16>& reply,
      NotificationDispatchCompleteCallback dispatch_complete_callback) = 0;

  // Dispatches the "notificationclose" event on the Service Worker associated
  // with |notification_id| belonging to |origin|. The
  // |dispatch_complete_callback| will be invoked when it's known whether the
  // event successfully executed.
  virtual void DispatchNotificationCloseEvent(
      Domain* domain,
      const std::string& notification_id,
      const GURL& origin,
      bool by_user,
      NotificationDispatchCompleteCallback dispatch_complete_callback) = 0;

  // Dispatch methods for the different non persistent (not backed by a service
  // worker) notification events.
  virtual void DispatchNonPersistentShowEvent(
      const std::string& notification_id) = 0;
  virtual void DispatchNonPersistentClickEvent(
      const std::string& notification_id) = 0;
  virtual void DispatchNonPersistentCloseEvent(
      const std::string& notification_id) = 0;

 protected:
  virtual ~NotificationEventDispatcher() {}
};

}  // namespace content

#endif  // CONTENT_PUBLIC_BROWSER_NOTIFICATION_EVENT_DISPATCHER_H_
