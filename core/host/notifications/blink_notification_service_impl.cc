// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/notifications/blink_notification_service_impl.h"

#include "base/bind.h"
#include "base/bind_helpers.h"
#include "base/callback_helpers.h"
#include "base/logging.h"
#include "base/strings/string16.h"
#include "core/host/notifications/notification_event_dispatcher_impl.h"
#include "core/host/notifications/platform_notification_context_impl.h"
#include "core/shared/common/service_worker/service_worker_status_code.h"
#include "core/host/host_thread.h"
#include "core/host/host_client.h"
#include "core/host/host_controller.h"
#include "core/host/host.h"
#include "core/host/notification_database_data.h"
#include "core/host/platform_notification_service.h"
#include "core/shared/common/client.h"
#include "core/shared/common/notification_resources.h"
#include "core/shared/common/platform_notification_data.h"
#include "third_party/blink/public/platform/modules/permissions/permission_status.mojom.h"
#include "url/gurl.h"

namespace host {

namespace {

// Returns the implementation of the PlatformNotificationService. May be NULL.
PlatformNotificationService* Service() {
  scoped_refptr<HostController> controller = HostController::Instance();
  return controller->host()->GetPlatformNotificationService();
  //return GetContentClient()->browser()->GetPlatformNotificationService();
}

}  // namespace

BlinkNotificationServiceImpl::BlinkNotificationServiceImpl(
    PlatformNotificationContextImpl* notification_context,
    //BrowserContext* domain,
    Domain* domain,
    ResourceContext* resource_context,
    scoped_refptr<ServiceWorkerContextWrapper> service_worker_context,
    int render_process_id,
    const url::Origin& origin,
    mojo::InterfaceRequest<blink::mojom::NotificationService> request)
    : notification_context_(notification_context),
      //domain_(domain),
      domain_(domain),
      resource_context_(resource_context),
      service_worker_context_(std::move(service_worker_context)),
      render_process_id_(render_process_id),
      origin_(origin),
      binding_(this, std::move(request)),
      weak_ptr_factory_(this) {
  DCHECK_CURRENTLY_ON(HostThread::IO);
  DCHECK(notification_context_);
  DCHECK(domain_);
  DCHECK(resource_context_);

  binding_.set_connection_error_handler(base::BindOnce(
      &BlinkNotificationServiceImpl::OnConnectionError,
      base::Unretained(this) /* the channel is owned by |this| */));
}

BlinkNotificationServiceImpl::~BlinkNotificationServiceImpl() {
  DCHECK_CURRENTLY_ON(HostThread::IO);
}

void BlinkNotificationServiceImpl::GetPermissionStatus(
    GetPermissionStatusCallback callback) {
  DCHECK_CURRENTLY_ON(HostThread::IO);
  if (!Service()) {
    std::move(callback).Run(blink::mojom::PermissionStatus::DENIED);
    return;
  }

  blink::mojom::PermissionStatus permission_status = CheckPermissionStatus();

  std::move(callback).Run(permission_status);
}

void BlinkNotificationServiceImpl::OnConnectionError() {
  notification_context_->RemoveService(this);
  // |this| has now been deleted.
}

void BlinkNotificationServiceImpl::DisplayNonPersistentNotification(
    const std::string& token,
    const common::PlatformNotificationData& platform_notification_data,
    const common::NotificationResources& notification_resources,
    blink::mojom::NonPersistentNotificationListenerPtr event_listener_ptr) {
  DCHECK_CURRENTLY_ON(HostThread::IO);
  if (!Service())
    return;
  if (CheckPermissionStatus() != blink::mojom::PermissionStatus::GRANTED)
    return;

  std::string notification_id =
      notification_context_->notification_id_generator()
          ->GenerateForNonPersistentNotification(origin_, token);

  HostThread::PostTask(
      HostThread::UI, FROM_HERE,
      base::BindOnce(&BlinkNotificationServiceImpl::
                         DisplayNonPersistentNotificationOnUIThread,
                     weak_ptr_factory_.GetWeakPtr(), notification_id,
                     origin_.GetURL(), platform_notification_data,
                     notification_resources,
                     event_listener_ptr.PassInterface()));
}

void BlinkNotificationServiceImpl::DisplayNonPersistentNotificationOnUIThread(
    const std::string& notification_id,
    const GURL& origin,
    const common::PlatformNotificationData& notification_data,
    const common::NotificationResources& notification_resources,
    blink::mojom::NonPersistentNotificationListenerPtrInfo listener_ptr_info) {
  NotificationEventDispatcherImpl* event_dispatcher =
      NotificationEventDispatcherImpl::GetInstance();
  event_dispatcher->RegisterNonPersistentNotificationListener(
      notification_id, std::move(listener_ptr_info));

  Service()->DisplayNotification(domain_, notification_id, origin,
                                 notification_data, notification_resources);
}

void BlinkNotificationServiceImpl::CloseNonPersistentNotification(
    const std::string& token) {
  DCHECK_CURRENTLY_ON(HostThread::IO);
  if (!Service())
    return;

  std::string notification_id =
      notification_context_->notification_id_generator()
          ->GenerateForNonPersistentNotification(origin_, token);

  HostThread::PostTask(
      HostThread::UI, FROM_HERE,
      base::BindOnce(&BlinkNotificationServiceImpl::
                         CloseNonPersistentNotificationOnUIThread,
                     weak_ptr_factory_.GetWeakPtr(), notification_id));
}

void BlinkNotificationServiceImpl::CloseNonPersistentNotificationOnUIThread(
    const std::string& notification_id) {
  Service()->CloseNotification(domain_, notification_id);

  NotificationEventDispatcherImpl::GetInstance()
      ->DispatchNonPersistentCloseEvent(notification_id);
}

blink::mojom::PermissionStatus
BlinkNotificationServiceImpl::CheckPermissionStatus() {
  return Service()->CheckPermissionOnIOThread(
      resource_context_, origin_.GetURL(), render_process_id_);
}

void BlinkNotificationServiceImpl::DisplayPersistentNotification(
    int64_t service_worker_registration_id,
    const common::PlatformNotificationData& platform_notification_data,
    const common::NotificationResources& notification_resources,
    DisplayPersistentNotificationCallback callback) {
  DCHECK_CURRENTLY_ON(HostThread::IO);
  if (!Service()) {
    std::move(callback).Run(
        blink::mojom::PersistentNotificationError::INTERNAL_ERROR);
    return;
  }
  if (CheckPermissionStatus() != blink::mojom::PermissionStatus::GRANTED) {
    std::move(callback).Run(
        blink::mojom::PersistentNotificationError::PERMISSION_DENIED);
    return;
  }

  // TODO(awdf): Necessary to validate resources here?

  NotificationDatabaseData database_data;
  database_data.origin = origin_.GetURL();
  database_data.service_worker_registration_id = service_worker_registration_id;
  database_data.notification_data = platform_notification_data;

  notification_context_->WriteNotificationData(
      origin_.GetURL(), database_data,
      base::AdaptCallbackForRepeating(base::BindOnce(
          &BlinkNotificationServiceImpl::DisplayPersistentNotificationWithId,
          weak_ptr_factory_.GetWeakPtr(), service_worker_registration_id,
          platform_notification_data, notification_resources,
          std::move(callback))));
}

void BlinkNotificationServiceImpl::DisplayPersistentNotificationWithId(
    int64_t service_worker_registration_id,
    const common::PlatformNotificationData& platform_notification_data,
    const common::NotificationResources& notification_resources,
    DisplayPersistentNotificationCallback callback,
    bool success,
    const std::string& notification_id) {
  DCHECK_CURRENTLY_ON(HostThread::IO);

  if (!success) {
    std::move(callback).Run(
        blink::mojom::PersistentNotificationError::INTERNAL_ERROR);
    return;
  }

  service_worker_context_->FindReadyRegistrationForId(
      service_worker_registration_id, origin_.GetURL(),
      base::BindOnce(&BlinkNotificationServiceImpl::
                         DisplayPersistentNotificationWithIdForServiceWorker,
                     weak_ptr_factory_.GetWeakPtr(), notification_id,
                     platform_notification_data, notification_resources,
                     std::move(callback)));
}

void BlinkNotificationServiceImpl::
    DisplayPersistentNotificationWithIdForServiceWorker(
        const std::string& notification_id,
        const common::PlatformNotificationData& platform_notification_data,
        const common::NotificationResources& notification_resources,
        DisplayPersistentNotificationCallback callback,
        common::ServiceWorkerStatusCode service_worker_status,
        scoped_refptr<ServiceWorkerRegistration> registration) {
  DCHECK_CURRENTLY_ON(HostThread::IO);

  if (service_worker_status != common::SERVICE_WORKER_OK) {
    std::move(callback).Run(
        blink::mojom::PersistentNotificationError::INTERNAL_ERROR);
    LOG(ERROR) << "Registration not found for " << origin_.GetURL().spec();
    // TODO(peter): Add UMA to track how often this occurs.
    return;
  }

  if (registration->pattern().GetOrigin() != origin_.GetURL()) {
    // Bail out, something's wrong.
    std::move(callback).Run(
        blink::mojom::PersistentNotificationError::INTERNAL_ERROR);
    return;
  }

  // Using base::Unretained here is safe because Service() returns a singleton.
  HostThread::PostTask(
      HostThread::UI, FROM_HERE,
      base::BindOnce(
          &PlatformNotificationService::DisplayPersistentNotification,
          base::Unretained(Service()), domain_, notification_id,
          registration->pattern(), origin_.GetURL(), platform_notification_data,
          notification_resources));

  std::move(callback).Run(blink::mojom::PersistentNotificationError::NONE);
}

void BlinkNotificationServiceImpl::ClosePersistentNotification(
    const std::string& notification_id) {
  DCHECK_CURRENTLY_ON(HostThread::IO);

  if (CheckPermissionStatus() != blink::mojom::PermissionStatus::GRANTED)
    return;

  // Using base::Unretained here is safe because Service() returns a singleton.
  HostThread::PostTask(
      HostThread::UI, FROM_HERE,
      base::BindOnce(&PlatformNotificationService::ClosePersistentNotification,
                     base::Unretained(Service()), domain_,
                     notification_id));

  notification_context_->DeleteNotificationData(
      notification_id, origin_.GetURL(), base::DoNothing());
}

void BlinkNotificationServiceImpl::GetNotifications(
    int64_t service_worker_registration_id,
    const std::string& filter_tag,
    GetNotificationsCallback callback) {
  DCHECK_CURRENTLY_ON(HostThread::IO);

  if (CheckPermissionStatus() != blink::mojom::PermissionStatus::GRANTED) {
    // No permission has been granted for the given origin. It is harmless to
    // try to get notifications without permission, so return empty vectors
    // indicating that no (accessible) notifications exist at this time.
    std::move(callback).Run(std::vector<std::string>(),
                            std::vector<common::PlatformNotificationData>());
    return;
  }

  notification_context_->ReadAllNotificationDataForServiceWorkerRegistration(
      origin_.GetURL(), service_worker_registration_id,
      base::AdaptCallbackForRepeating(base::BindOnce(
          &BlinkNotificationServiceImpl::DidGetNotifications,
          weak_ptr_factory_.GetWeakPtr(), filter_tag, std::move(callback))));
}

void BlinkNotificationServiceImpl::DidGetNotifications(
    const std::string& filter_tag,
    GetNotificationsCallback callback,
    bool success,
    const std::vector<NotificationDatabaseData>& notifications) {
  std::vector<std::string> ids;
  std::vector<common::PlatformNotificationData> datas;

  for (const NotificationDatabaseData& database_data : notifications) {
    // An empty filter tag matches all, else we need an exact match.
    if (filter_tag.empty() ||
        filter_tag == database_data.notification_data.tag) {
      ids.push_back(database_data.notification_id);
      datas.push_back(database_data.notification_data);
    }
  }

  std::move(callback).Run(ids, datas);
}

}  // namespace content
