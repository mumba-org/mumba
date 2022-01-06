// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/service_worker/service_worker_dispatcher_host.h"

#include <utility>

#include "base/logging.h"
#include "base/macros.h"
#include "base/memory/ptr_util.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/utf_string_conversions.h"
#include "base/threading/thread_task_runner_handle.h"
#include "base/trace_event/trace_event.h"
#include "core/host/bad_message.h"
#include "core/host/service_worker/embedded_worker_status.h"
#include "core/host/service_worker/service_worker_context_core.h"
#include "core/host/service_worker/service_worker_context_wrapper.h"
#include "core/host/service_worker/service_worker_handle.h"
#include "core/host/service_worker/service_worker_navigation_handle_core.h"
#include "core/host/service_worker/service_worker_registration.h"
#include "core/shared/common/service_worker/service_worker_messages.h"
#include "core/shared/common/service_worker/service_worker_utils.h"
#include "core/host/host_thread.h"
#include "core/host/host_client.h"
#include "core/host/application/application_window_host.h"
#include "core/host/application/application_contents.h"
//#include "core/shared/common/browser_side_navigation_policy.h"
#include "core/shared/common/child_process_host.h"
#include "core/shared/common/client.h"
#include "core/shared/common/origin_util.h"
#include "ipc/ipc_message_macros.h"
#include "third_party/blink/public/mojom/service_worker/service_worker_error_type.mojom.h"
#include "third_party/blink/public/mojom/service_worker/service_worker_object.mojom.h"
#include "third_party/blink/public/mojom/service_worker/service_worker_provider_type.mojom.h"
#include "third_party/blink/public/platform/modules/serviceworker/web_service_worker_error.h"
#include "url/gurl.h"

using blink::MessagePortChannel;
using blink::WebServiceWorkerError;

namespace host {

namespace {

const uint32_t kServiceWorkerFilteredMessageClasses[] = {
    ServiceWorkerMsgStart,
};

}  // namespace

ServiceWorkerDispatcherHost::ServiceWorkerDispatcherHost(
    ServiceWorkerProcessType process_type,
    int process_id,
    ResourceContext* resource_context)
    : HostMessageFilter(kServiceWorkerFilteredMessageClasses,
                           arraysize(kServiceWorkerFilteredMessageClasses)),
      HostAssociatedInterface<common::mojom::ServiceWorkerDispatcherHost>(this,
                                                                     this),
      process_type_(process_type),
      process_id_(process_id),
      resource_context_(resource_context),
      weak_ptr_factory_(this) {
    // DLOG(INFO) << "ServiceWorkerDispatcherHost(): process_id = " << process_id;
}

ServiceWorkerDispatcherHost::~ServiceWorkerDispatcherHost() {
  DCHECK(HostThread::CurrentlyOn(HostThread::IO));
  if (GetContext() && phase_ == Phase::kAddedToContext)
    GetContext()->RemoveDispatcherHost(process_id_);
}

void ServiceWorkerDispatcherHost::Init(
    ServiceWorkerContextWrapper* context_wrapper) {
  // DLOG(INFO) << "ServiceWorkerDispatcherHost::Init";
  if (!HostThread::CurrentlyOn(HostThread::IO)) {
    HostThread::PostTask(
        HostThread::IO, FROM_HERE,
        base::BindOnce(&ServiceWorkerDispatcherHost::Init, this,
                       base::RetainedRef(context_wrapper)));
    return;
  }

  // Just speculating that maybe we were destructed before Init() was called on
  // the IO thread in order to try to fix https://crbug.com/750267.
  if (phase_ != Phase::kInitial)
    return;

  context_wrapper_ = context_wrapper;
  if (!GetContext())
    return;
  if (process_type_ == kPROCESS_TYPE_SERVICE) {
    ServiceWorkerDispatcherHost* dispatcher_host = GetContext()->GetDispatcherHost(process_id_);
    if (!dispatcher_host) {
      GetContext()->AddDispatcherHost(process_id_, this);
    }
  } else {
    GetContext()->AddDispatcherHost(process_id_, this);
  }
  phase_ = Phase::kAddedToContext;
}

void ServiceWorkerDispatcherHost::OnFilterRemoved() {
  DCHECK(HostThread::CurrentlyOn(HostThread::IO));
  // Don't wait until the destructor to teardown since a new dispatcher host
  // for this process might be created before then.
  if (GetContext() && phase_ == Phase::kAddedToContext) {
    GetContext()->RemoveDispatcherHost(process_id_);
    weak_ptr_factory_.InvalidateWeakPtrs();
  }
  phase_ = Phase::kRemovedFromContext;
  context_wrapper_ = nullptr;
}

void ServiceWorkerDispatcherHost::OnDestruct() const {
  // Destruct on the IO thread since |context_wrapper_| should only be accessed
  // on the IO thread.
  HostThread::DeleteOnIOThread::Destruct(this);
}

bool ServiceWorkerDispatcherHost::OnMessageReceived(
    const IPC::Message& message) {
  return false;
}

base::WeakPtr<ServiceWorkerDispatcherHost>
ServiceWorkerDispatcherHost::AsWeakPtr() {
  return weak_ptr_factory_.GetWeakPtr();
}

void ServiceWorkerDispatcherHost::OnProviderCreated(
    common::ServiceWorkerProviderHostInfo info) {
  // DLOG(INFO) << "\n\nhost::ServiceWorkerDispatcherHost::OnProviderCreated: provider_id = " << info.provider_id << "\n\n";
  TRACE_EVENT0("ServiceWorker",
               "ServiceWorkerDispatcherHost::OnProviderCreated");
  if (!GetContext()) {
    // DLOG(ERROR) << "host::ServiceWorkerDispatcherHost::OnProviderCreated: GetContext() is null. cancelling";
    return;
  }
  if (GetContext()->GetProviderHost(process_id_, info.provider_id)) {
    bad_message::ReceivedBadMessage(
        this, bad_message::SWDH_PROVIDER_CREATED_DUPLICATE_ID);
    // DLOG(ERROR) << "host::ServiceWorkerDispatcherHost::OnProviderCreated: " << info.provider_id << " is duplicated";
    return;
  }

  // Provider hosts for navigations are precreated on the browser process with a
  // browser-assigned id. The renderer process calls OnProviderCreated once it
  // creates the provider.
  if (common::ServiceWorkerUtils::IsBrowserAssignedProviderId(info.provider_id)) {
    // DLOG(INFO) << "common::ServiceWorkerUtils::IsBrowserAssignedProviderId = TRUE. info.provider_id = " << info.provider_id;
  // FIXME
  //if (true) {
    if (info.type != blink::mojom::ServiceWorkerProviderType::kForWindow) {
      bad_message::ReceivedBadMessage(
          this, bad_message::SWDH_PROVIDER_CREATED_ILLEGAL_TYPE_NOT_WINDOW);
      // DLOG(ERROR) << "host::ServiceWorkerDispatcherHost::OnProviderCreated: " << bad_message::SWDH_PROVIDER_CREATED_ILLEGAL_TYPE_NOT_WINDOW;
      return;
    }

    // Retrieve the provider host previously created for navigation requests.
    std::unique_ptr<ServiceWorkerProviderHost> provider_host;
    ServiceWorkerNavigationHandleCore* navigation_handle_core =
        GetContext()->GetNavigationHandleCore(info.provider_id);
    if (navigation_handle_core != nullptr) {
       // DLOG(INFO) << "host::ServiceWorkerDispatcherHost::OnProviderCreated: navigation_handle_core->RetrievePreCreatedHost()";
      provider_host = navigation_handle_core->RetrievePreCreatedHost();
    }

    // If no host is found, create one.
    // TODO(crbug.com/789111#c14): This is probably not right, see bug.
    if (!provider_host) {
      // DLOG(ERROR) << "host::ServiceWorkerDispatcherHost::OnProviderCreated: provider_host not found. creating one and leaving?";
      GetContext()->AddProviderHost(ServiceWorkerProviderHost::Create(
          process_type_, process_id_, std::move(info), GetContext()->AsWeakPtr(),
          AsWeakPtr()));
      return;
    }

    // Otherwise, complete initialization of the pre-created host.
    provider_host->CompleteNavigationInitialized(process_id_,
                                                 std::move(info), AsWeakPtr());
    GetContext()->AddProviderHost(std::move(provider_host));
    return;
  }

  // Provider hosts for service workers don't call OnProviderCreated. They are
  // precreated and ServiceWorkerProviderHost::CompleteStartWorkerPreparation is
  // called during the startup sequence once a process is allocated.
  if (info.type == blink::mojom::ServiceWorkerProviderType::kForServiceWorker) {
    bad_message::ReceivedBadMessage(
        this, bad_message::SWDH_PROVIDER_CREATED_ILLEGAL_TYPE_SERVICE_WORKER);
    return;
  }

  // DLOG(INFO) << "ServiceWorkerDispatcherHost::OnProviderCreated: application_process_id = " << process_id_;
  std::unique_ptr<ServiceWorkerProviderHost> provider_host = ServiceWorkerProviderHost::Create(
      process_type_,
      process_id_, 
      std::move(info), 
      GetContext()->AsWeakPtr(),
      AsWeakPtr());
  GetContext()->AddProviderHost(std::move(provider_host));
}

ServiceWorkerContextCore* ServiceWorkerDispatcherHost::GetContext() {
  DCHECK(HostThread::CurrentlyOn(HostThread::IO));
  if (!context_wrapper_.get())
    return nullptr;
  return context_wrapper_->context();
}

}  // namespace host
