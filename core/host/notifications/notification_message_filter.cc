// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/notifications/notification_message_filter.h"

#include <utility>

#include "base/callback.h"
#include "base/command_line.h"
#include "base/feature_list.h"
#include "core/host/bad_message.h"
#include "core/host/notifications/notification_event_dispatcher_impl.h"
#include "core/host/notifications/notification_id_generator.h"
#include "core/host/notifications/platform_notification_context_impl.h"
#include "core/host/service_worker/service_worker_context_wrapper.h"
#include "core/shared/common/platform_notification_messages.h"
#include "core/host/application/domain.h"
#include "core/host/host_thread.h"
#include "core/host/host.h"
#include "core/host/host_client.h"
#include "core/host/notification_database_data.h"
#include "core/host/platform_notification_service.h"
#include "core/host/application/application_process_host.h"
#include "core/shared/common/client.h"
#include "core/shared/common/content_features.h"
#include "core/shared/common/switches.h"
#include "third_party/blink/public/platform/modules/notifications/web_notification_constants.h"

namespace host {

namespace {

const int kMinimumVibrationDurationMs = 1;      // 1 millisecond
const int kMaximumVibrationDurationMs = 10000;  // 10 seconds

common::PlatformNotificationData SanitizeNotificationData(
    const common::PlatformNotificationData& notification_data) {
  common::PlatformNotificationData sanitized_data = notification_data;

  // Make sure that the vibration values are within reasonable bounds.
  for (int& pattern : sanitized_data.vibration_pattern) {
    pattern = std::min(kMaximumVibrationDurationMs,
                       std::max(kMinimumVibrationDurationMs, pattern));
  }

  // Ensure there aren't more actions than supported.
  if (sanitized_data.actions.size() > blink::kWebNotificationMaxActions)
    sanitized_data.actions.resize(blink::kWebNotificationMaxActions);

  return sanitized_data;
}

// Returns true when |resources| looks ok, false otherwise.
bool ValidateNotificationResources(const common::NotificationResources& resources) {
  if (!resources.image.drawsNothing() &&
      !base::FeatureList::IsEnabled(features::kNotificationContentImage)) {
    return false;
  }
  if (resources.image.width() > blink::kWebNotificationMaxImageWidthPx ||
      resources.image.height() > blink::kWebNotificationMaxImageHeightPx) {
    return false;
  }
  if (resources.notification_icon.width() >
          blink::kWebNotificationMaxIconSizePx ||
      resources.notification_icon.height() >
          blink::kWebNotificationMaxIconSizePx) {
    return false;
  }
  if (resources.badge.width() > blink::kWebNotificationMaxBadgeSizePx ||
      resources.badge.height() > blink::kWebNotificationMaxBadgeSizePx) {
    return false;
  }
  for (const auto& action_icon : resources.action_icons) {
    if (action_icon.width() > blink::kWebNotificationMaxActionIconSizePx ||
        action_icon.height() > blink::kWebNotificationMaxActionIconSizePx) {
      return false;
    }
  }
  return true;
}

}  // namespace

NotificationMessageFilter::NotificationMessageFilter(
    int process_id,
    PlatformNotificationContextImpl* notification_context,
    ResourceContext* resource_context,
    const scoped_refptr<ServiceWorkerContextWrapper>& service_worker_context,
    //BrowserContext* browser_context)
    Domain* domain)
    : HostMessageFilter(PlatformNotificationMsgStart),
      process_id_(process_id),
      notification_context_(notification_context),
      resource_context_(resource_context),
      service_worker_context_(service_worker_context),
      //browser_context_(browser_context),
      domain_(domain),
      weak_factory_io_(this) {}

NotificationMessageFilter::~NotificationMessageFilter() = default;

void NotificationMessageFilter::OnDestruct() const {
  HostThread::DeleteOnIOThread::Destruct(this);
}

bool NotificationMessageFilter::OnMessageReceived(const IPC::Message& message) {
  bool handled = true;
  IPC_BEGIN_MESSAGE_MAP(NotificationMessageFilter, message)
    IPC_MESSAGE_HANDLER(PlatformNotificationHostMsg_ShowPersistent,
                        OnShowPersistentNotification)
    IPC_MESSAGE_HANDLER(PlatformNotificationHostMsg_GetNotifications,
                        OnGetNotifications)
    IPC_MESSAGE_HANDLER(PlatformNotificationHostMsg_ClosePersistent,
                        OnClosePersistentNotification)
    IPC_MESSAGE_UNHANDLED(handled = false)
  IPC_END_MESSAGE_MAP()

  return handled;
}

void NotificationMessageFilter::OnShowPersistentNotification(
    int request_id,
    int64_t service_worker_registration_id,
    const GURL& origin,
    const common::PlatformNotificationData& notification_data,
    const common::NotificationResources& notification_resources) {
  DCHECK_CURRENTLY_ON(HostThread::IO);
  if (GetPermissionForOriginOnIO(origin) !=
      blink::mojom::PermissionStatus::GRANTED) {
    // We can't assume that the renderer is compromised at this point because
    // it's possible for the user to revoke an origin's permission between the
    // time where a website requests the notification to be shown and the call
    // arriving in the message filter.
    return;
  }

  if (!ValidateNotificationResources(notification_resources)) {
    bad_message::ReceivedBadMessage(this, bad_message::NMF_INVALID_ARGUMENT);
    return;
  }

  NotificationDatabaseData database_data;
  database_data.origin = origin;
  database_data.service_worker_registration_id = service_worker_registration_id;

  common::PlatformNotificationData sanitized_notification_data =
      SanitizeNotificationData(notification_data);
  database_data.notification_data = sanitized_notification_data;

  notification_context_->WriteNotificationData(
      origin, database_data,
      base::Bind(&NotificationMessageFilter::DidWritePersistentNotificationData,
                 weak_factory_io_.GetWeakPtr(), request_id,
                 service_worker_registration_id, origin,
                 sanitized_notification_data, notification_resources));
}

void NotificationMessageFilter::DidWritePersistentNotificationData(
    int request_id,
    int64_t service_worker_registration_id,
    const GURL& origin,
    const common::PlatformNotificationData& notification_data,
    const common::NotificationResources& notification_resources,
    bool success,
    const std::string& notification_id) {
  DCHECK_CURRENTLY_ON(HostThread::IO);

  if (!success) {
    Send(new PlatformNotificationMsg_DidShowPersistent(request_id, false));
    return;
  }

  // Get the service worker scope.
  service_worker_context_->FindReadyRegistrationForId(
      service_worker_registration_id, origin,
      base::BindOnce(
          &NotificationMessageFilter::DidFindServiceWorkerRegistration,
          weak_factory_io_.GetWeakPtr(), request_id, origin, notification_data,
          notification_resources, notification_id));
}

void NotificationMessageFilter::DidFindServiceWorkerRegistration(
    int request_id,
    const GURL& origin,
    const common::PlatformNotificationData& notification_data,
    const common::NotificationResources& notification_resources,
    const std::string& notification_id,
    common::ServiceWorkerStatusCode service_worker_status,
    scoped_refptr<ServiceWorkerRegistration> registration) {
  DCHECK_CURRENTLY_ON(HostThread::IO);

  if (service_worker_status != common::SERVICE_WORKER_OK) {
    Send(new PlatformNotificationMsg_DidShowPersistent(request_id, false));
    LOG(ERROR) << "Registration not found for " << origin.spec();
    // TODO(peter): Add UMA to track how often this occurs.
    return;
  }

  PlatformNotificationService* service = Host::Instance()->GetPlatformNotificationService();
      //GetContentClient()->browser()->GetPlatformNotificationService();
  DCHECK(service);

  HostThread::PostTask(
      HostThread::UI, FROM_HERE,
      base::BindOnce(
          &PlatformNotificationService::DisplayPersistentNotification,
          base::Unretained(service),  // The service is a singleton.
          domain_, notification_id, registration->pattern(), origin,
          notification_data, notification_resources));

  Send(new PlatformNotificationMsg_DidShowPersistent(request_id, true));
}

void NotificationMessageFilter::OnGetNotifications(
    int request_id,
    int64_t service_worker_registration_id,
    const GURL& origin,
    const std::string& filter_tag) {
  DCHECK_CURRENTLY_ON(HostThread::IO);
  if (GetPermissionForOriginOnIO(origin) !=
      blink::mojom::PermissionStatus::GRANTED) {
    // No permission has been granted for the given origin. It is harmless to
    // try to get notifications without permission, so return an empty vector
    // indicating that no (accessible) notifications exist at this time.
    Send(new PlatformNotificationMsg_DidGetNotifications(
        request_id, std::vector<PersistentNotificationInfo>()));
    return;
  }

  notification_context_->ReadAllNotificationDataForServiceWorkerRegistration(
      origin, service_worker_registration_id,
      base::Bind(&NotificationMessageFilter::DidGetNotifications,
                 weak_factory_io_.GetWeakPtr(), request_id, filter_tag));
}

void NotificationMessageFilter::DidGetNotifications(
    int request_id,
    const std::string& filter_tag,
    bool success,
    const std::vector<NotificationDatabaseData>& notifications) {
  std::vector<PersistentNotificationInfo> persistent_notifications;
  for (const NotificationDatabaseData& database_data : notifications) {
    if (!filter_tag.empty()) {
      const std::string& tag = database_data.notification_data.tag;
      if (tag != filter_tag)
        continue;
    }

    persistent_notifications.push_back(std::make_pair(
        database_data.notification_id, database_data.notification_data));
  }

  Send(new PlatformNotificationMsg_DidGetNotifications(
      request_id, persistent_notifications));
}

void NotificationMessageFilter::OnClosePersistentNotification(
    const GURL& origin,
    const std::string& tag,
    const std::string& notification_id) {
  DCHECK_CURRENTLY_ON(HostThread::IO);
  if (GetPermissionForOriginOnIO(origin) !=
      blink::mojom::PermissionStatus::GRANTED) {
    return;
  }

  PlatformNotificationService* service =
      Host::Instance()->GetPlatformNotificationService();
  DCHECK(service);

  // There's no point in waiting until the database data has been removed before
  // closing the notification presented to the user. Post that task immediately.
  HostThread::PostTask(
      HostThread::UI, FROM_HERE,
      base::BindOnce(&PlatformNotificationService::ClosePersistentNotification,
                     base::Unretained(service),  // The service is a singleton.
                     domain_, notification_id));

  notification_context_->DeleteNotificationData(
      notification_id, origin,
      base::Bind(
          &NotificationMessageFilter::DidDeletePersistentNotificationData,
          weak_factory_io_.GetWeakPtr()));
}

void NotificationMessageFilter::DidDeletePersistentNotificationData(
    bool success) {
  DCHECK_CURRENTLY_ON(HostThread::IO);
  // TODO(peter): Consider feeding back to the renderer that the notification
  // has been closed.
}

blink::mojom::PermissionStatus
NotificationMessageFilter::GetPermissionForOriginOnIO(
    const GURL& origin) const {
  DCHECK_CURRENTLY_ON(HostThread::IO);

  PlatformNotificationService* service = Host::Instance()->GetPlatformNotificationService();
     // GetContentClient()->browser()->GetPlatformNotificationService();
  if (!service)
    return blink::mojom::PermissionStatus::DENIED;

  return service->CheckPermissionOnIOThread(resource_context_, origin,
                                            process_id_);
}

bool NotificationMessageFilter::VerifyNotificationPermissionGranted(
    PlatformNotificationService* service,
    const GURL& origin) {
  DCHECK_CURRENTLY_ON(HostThread::UI);

  // blink::mojom::PermissionStatus permission_status =
  //     service->CheckPermissionOnUIThread(browser_context_, origin, process_id_);

  // We can't assume that the renderer is compromised at this point because
  // it's possible for the user to revoke an origin's permission between the
  // time where a website requests the notification to be shown and the call
  // arriving in the message filter.

  return true;// permission_status == blink::mojom::PermissionStatus::GRANTED;
}

NotificationIdGenerator* NotificationMessageFilter::GetNotificationIdGenerator()
    const {
  return notification_context_->notification_id_generator();
}

}  // namespace content
