// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/service_worker/service_worker_request_handler.h"

#include <string>
#include <utility>

#include "base/command_line.h"
#include "base/macros.h"
#include "core/host/loader/navigation_loader_interceptor.h"
#include "core/host/service_worker/service_worker_context_core.h"
#include "core/host/service_worker/service_worker_context_wrapper.h"
#include "core/host/service_worker/service_worker_navigation_handle_core.h"
#include "core/host/service_worker/service_worker_provider_host.h"
#include "core/host/service_worker/service_worker_registration.h"
#include "core/host/service_worker/service_worker_url_request_job.h"
#include "core/shared/common/service_worker/service_worker_types.h"
#include "core/shared/common/service_worker/service_worker_utils.h"
#include "core/host/application/resource_context.h"
//#include "core/shared/common/browser_side_navigation_policy.h"
#include "core/shared/common/child_process_host.h"
#include "core/shared/common/content_features.h"
#include "core/shared/common/switches.h"
#include "core/shared/common/origin_util.h"
#include "core/shared/common/url_constants.h"
#include "ipc/ipc_message.h"
#include "net/base/url_util.h"
#include "net/url_request/url_request.h"
#include "net/url_request/url_request_interceptor.h"
#include "services/network/public/cpp/resource_request_body.h"
#include "storage/host/blob/blob_storage_context.h"

namespace host {

namespace {

class ServiceWorkerRequestInterceptor
    : public net::URLRequestInterceptor {
 public:
  explicit ServiceWorkerRequestInterceptor(ResourceContext* resource_context)
      : resource_context_(resource_context) {}
  ~ServiceWorkerRequestInterceptor() override {}
  net::URLRequestJob* MaybeInterceptRequest(
      net::URLRequest* request,
      net::NetworkDelegate* network_delegate) const override {
    ServiceWorkerRequestHandler* handler =
        ServiceWorkerRequestHandler::GetHandler(request);
    if (!handler)
      return nullptr;
    return handler->MaybeCreateJob(
        request, network_delegate, resource_context_);
  }

 private:
  ResourceContext* resource_context_;
  DISALLOW_COPY_AND_ASSIGN(ServiceWorkerRequestInterceptor);
};

// bool SchemeMaySupportRedirectingToHTTPS(const GURL& url) {
// #if defined(OS_CHROMEOS)
//   return url.SchemeIs(kExternalFileScheme);
// #else   // OS_CHROMEOS
//   return false;
// #endif  // OS_CHROMEOS
// }

}  // namespace

// static
int ServiceWorkerRequestHandler::user_data_key_;

// PlzNavigate:
// static
void ServiceWorkerRequestHandler::InitializeForNavigation(
    net::URLRequest* request,
    ServiceWorkerNavigationHandleCore* navigation_handle_core,
    storage::BlobStorageContext* blob_storage_context,
    bool skip_service_worker,
    common::ResourceType resource_type,
    common::RequestContextType request_context_type,
    network::mojom::RequestContextFrameType frame_type,
    bool is_parent_frame_secure,
    scoped_refptr<network::ResourceRequestBody> body,
    ServiceWorkerProcessType process_type,
    int process_id,
    const base::Callback<ApplicationContents*(void)>& web_contents_getter) {
    // DLOG(INFO) << "ServiceWorkerRequestHandler::InitializeForNavigation";
  //CHECK(IsBrowserSideNavigationEnabled());

  // S13nServiceWorker enabled, NetworkService disabled:
  // To start the navigation, InitializeForNavigationNetworkService() is called
  // instead of this, but when that request handler falls back to network,
  // InitializeForNavigation() is called.
  // Since we already determined to fall back to network, don't create another
  // handler.
  // if (common::ServiceWorkerUtils::IsServicificationEnabled()) {
  //   // DLOG(ERROR) << "ServiceWorkerRequestHandler::InitializeForNavigation: common::ServiceWorkerUtils::IsServicificationEnabled() = false. CANCELLING";
  //   return;
  // }

  // Only create a handler when there is a ServiceWorkerNavigationHandlerCore
  // to take ownership of a pre-created SeviceWorkerProviderHost.
  if (!navigation_handle_core) {
    DLOG(ERROR) << "ServiceWorkerRequestHandler::InitializeForNavigation: navigation_handle_core = nullptr. CANCELLING";
    return;
  }

  // Create the handler even for insecure HTTP since it's used in the
  // case of redirect to HTTPS.
  // if (!request->url().SchemeIsHTTPOrHTTPS() &&
  //     !common::OriginCanAccessServiceWorkers(request->url()) &&
  //     !SchemeMaySupportRedirectingToHTTPS(request->url())) {
  //   // DLOG(ERROR) << "ServiceWorkerRequestHandler::InitializeForNavigation: request->url().SchemeIsHTTPOrHTTPS() || OriginCanAccessServiceWorkers = false. CANCELLING";
  //   return;
  // }

  if (!navigation_handle_core->context_wrapper() ||
      !navigation_handle_core->context_wrapper()->context()) {
    DLOG(ERROR) << "ServiceWorkerRequestHandler::InitializeForNavigation: navigation_handle_core->context_wrapper() is null. CANCELLING";
    return;
  }

  // Initialize the SWProviderHost.
  std::unique_ptr<ServiceWorkerProviderHost> provider_host =
      ServiceWorkerProviderHost::PreCreateNavigationHost(
          navigation_handle_core->context_wrapper()->context()->AsWeakPtr(),
          is_parent_frame_secure, 
          process_type,
          process_id, 
          web_contents_getter);

  std::unique_ptr<ServiceWorkerRequestHandler> handler(
      provider_host->CreateRequestHandler(
          network::mojom::FetchRequestMode::kNavigate,
          network::mojom::FetchCredentialsMode::kInclude,
          network::mojom::FetchRedirectMode::kManual,
          std::string() /* integrity */, false /* keepalive */, resource_type,
          request_context_type, frame_type, blob_storage_context->AsWeakPtr(),
          body, skip_service_worker));
  if (handler) {
    request->SetUserData(&user_data_key_, std::move(handler));
  } else {
    DLOG(ERROR) << "provider_host->CreateRequestHandler() returned null";
  }

  // Transfer ownership to the ServiceWorkerNavigationHandleCore.
  // In the case of a successful navigation, the SWProviderHost will be
  // transferred to its "final" destination in the OnProviderCreated handler. If
  // the navigation fails, it will be destroyed along with the
  // ServiceWorkerNavigationHandleCore.
  navigation_handle_core->DidPreCreateProviderHost(std::move(provider_host));
}

// S13nServiceWorker:
// static
std::unique_ptr<NavigationLoaderInterceptor>
ServiceWorkerRequestHandler::InitializeForNavigationNetworkService(
    const network::ResourceRequest& resource_request,
    ResourceContext* resource_context,
    ServiceWorkerNavigationHandleCore* navigation_handle_core,
    storage::BlobStorageContext* blob_storage_context,
    bool skip_service_worker,
    common::ResourceType resource_type,
    common::RequestContextType request_context_type,
    network::mojom::RequestContextFrameType frame_type,
    bool is_parent_frame_secure,
    scoped_refptr<network::ResourceRequestBody> body,
    const base::Callback<ApplicationContents*(void)>& web_contents_getter) {
  DCHECK(common::ServiceWorkerUtils::IsServicificationEnabled());
  DCHECK(navigation_handle_core);

  // Create the handler even for insecure HTTP since it's used in the
  // case of redirect to HTTPS.
  // if (!resource_request.url.SchemeIsHTTPOrHTTPS() &&
  //     !common::OriginCanAccessServiceWorkers(resource_request.url)) {
  //   return nullptr;
  // }

  if (!navigation_handle_core->context_wrapper() ||
      !navigation_handle_core->context_wrapper()->context()) {
    DLOG(ERROR) << "ServiceWorkerRequestHandler::InitializeForNavigationNetworkService: navigation_handle_core->context_wrapper() is null";
    return nullptr;
  }

  // Initialize the SWProviderHost.
  std::unique_ptr<ServiceWorkerProviderHost> provider_host =
      ServiceWorkerProviderHost::PreCreateNavigationHost(
          navigation_handle_core->context_wrapper()->context()->AsWeakPtr(),
          is_parent_frame_secure, kPROCESS_TYPE_APPLICATION, -8, web_contents_getter);

  std::unique_ptr<ServiceWorkerRequestHandler> handler(
      provider_host->CreateRequestHandler(
          network::mojom::FetchRequestMode::kNavigate,
          network::mojom::FetchCredentialsMode::kInclude,
          network::mojom::FetchRedirectMode::kManual,
          std::string() /* integrity */, false /* keepalive */, resource_type,
          request_context_type, frame_type, blob_storage_context->AsWeakPtr(),
          body, skip_service_worker));

  // Transfer ownership to the ServiceWorkerNavigationHandleCore.
  // In the case of a successful navigation, the SWProviderHost will be
  // transferred to its "final" destination in the OnProviderCreated handler. If
  // the navigation fails, it will be destroyed along with the
  // ServiceWorkerNavigationHandleCore.
  DLOG(ERROR) << "ServiceWorkerRequestHandler::InitializeForNavigationNetworkService: provider_id: " << provider_host->provider_id();
  navigation_handle_core->DidPreCreateProviderHost(std::move(provider_host));

  return base::WrapUnique<NavigationLoaderInterceptor>(handler.release());
}

// static
std::unique_ptr<NavigationLoaderInterceptor>
ServiceWorkerRequestHandler::InitializeForSharedWorker(
    const network::ResourceRequest& resource_request,
    base::WeakPtr<ServiceWorkerProviderHost> host) {
  DCHECK(common::ServiceWorkerUtils::IsServicificationEnabled());

  // Create the handler even for insecure HTTP since it's used in the
  // case of redirect to HTTPS.
  if (!resource_request.url.SchemeIsHTTPOrHTTPS() &&
      !common::OriginCanAccessServiceWorkers(resource_request.url)) {
    return nullptr;
  }

  std::unique_ptr<ServiceWorkerRequestHandler> handler(
      host->CreateRequestHandler(
          resource_request.fetch_request_mode,
          resource_request.fetch_credentials_mode,
          resource_request.fetch_redirect_mode,
          resource_request.fetch_integrity, resource_request.keepalive,
          common::RESOURCE_TYPE_SHARED_WORKER, common::REQUEST_CONTEXT_TYPE_SHARED_WORKER,
          resource_request.fetch_frame_type,
          nullptr /* blob_storage_context: unused in S13n */,
          resource_request.request_body, resource_request.skip_service_worker));

  return base::WrapUnique<NavigationLoaderInterceptor>(handler.release());
}

// static
void ServiceWorkerRequestHandler::InitializeHandler(
    net::URLRequest* request,
    ServiceWorkerContextWrapper* context_wrapper,
    storage::BlobStorageContext* blob_storage_context,
    int process_id,
    int provider_id,
    bool skip_service_worker,
    network::mojom::FetchRequestMode request_mode,
    network::mojom::FetchCredentialsMode credentials_mode,
    network::mojom::FetchRedirectMode redirect_mode,
    const std::string& integrity,
    bool keepalive,
    common::ResourceType resource_type,
    common::RequestContextType request_context_type,
    network::mojom::RequestContextFrameType frame_type,
    scoped_refptr<network::ResourceRequestBody> body) {
  // S13nServiceWorker enabled, NetworkService disabled:
  // for subresource requests, subresource loader should be used, but when that
  // request handler falls back to network, InitializeHandler() is called.
  // Since we already determined to fall back to network, don't create another
  // handler.
  if (common::ServiceWorkerUtils::IsServicificationEnabled())
    return;

  // Create the handler even for insecure HTTP since it's used in the
  // case of redirect to HTTPS.
  if (!request->url().SchemeIsHTTPOrHTTPS() &&
      !common::OriginCanAccessServiceWorkers(request->url())) {
    return;
  }

  if (!context_wrapper || !context_wrapper->context() ||
      provider_id == common::kInvalidServiceWorkerProviderId) {
    return;
  }

  ServiceWorkerProviderHost* provider_host =
      context_wrapper->context()->GetProviderHost(process_id, provider_id);
  if (!provider_host || !provider_host->IsContextAlive())
    return;

  std::unique_ptr<ServiceWorkerRequestHandler> handler(
      provider_host->CreateRequestHandler(
          request_mode, credentials_mode, redirect_mode, integrity, keepalive,
          resource_type, request_context_type, frame_type,
          blob_storage_context->AsWeakPtr(), body, skip_service_worker));
  if (handler)
    request->SetUserData(&user_data_key_, std::move(handler));
}

// static
ServiceWorkerRequestHandler* ServiceWorkerRequestHandler::GetHandler(
    const net::URLRequest* request) {
  return static_cast<ServiceWorkerRequestHandler*>(
      request->GetUserData(&user_data_key_));
}

// static
std::unique_ptr<net::URLRequestInterceptor>
ServiceWorkerRequestHandler::CreateInterceptor(
    ResourceContext* resource_context) {
  return std::unique_ptr<net::URLRequestInterceptor>(
      new ServiceWorkerRequestInterceptor(resource_context));
}

// static
bool ServiceWorkerRequestHandler::IsControlledByServiceWorker(
    const net::URLRequest* request) {
  ServiceWorkerRequestHandler* handler = GetHandler(request);
  if (!handler || !handler->provider_host_)
    return false;
  return handler->provider_host_->associated_registration() ||
         handler->provider_host_->running_hosted_version();
}

// static
ServiceWorkerProviderHost* ServiceWorkerRequestHandler::GetProviderHost(
    const net::URLRequest* request) {
  ServiceWorkerRequestHandler* handler = GetHandler(request);
  return handler ? handler->provider_host_.get() : nullptr;
}

void ServiceWorkerRequestHandler::MaybeCreateLoader(
    const network::ResourceRequest& request,
    ResourceContext* resource_context,
    LoaderCallback callback) {
  NOTREACHED();
  std::move(callback).Run({});
}

void ServiceWorkerRequestHandler::PrepareForCrossSiteTransfer(
    int old_process_id) {
  //CHECK(!IsBrowserSideNavigationEnabled());
}

void ServiceWorkerRequestHandler::CompleteCrossSiteTransfer(
    int new_process_id, int new_provider_id) {
 // CHECK(!IsBrowserSideNavigationEnabled());
}

void ServiceWorkerRequestHandler::MaybeCompleteCrossSiteTransferInOldProcess(
    int old_process_id) {
  //CHECK(!IsBrowserSideNavigationEnabled());
}

bool ServiceWorkerRequestHandler::SanityCheckIsSameContext(
    ServiceWorkerContextWrapper* wrapper) {
  if (!wrapper)
    return !context_;
  return context_.get() == wrapper->context();
}

ServiceWorkerRequestHandler::~ServiceWorkerRequestHandler() {
}

ServiceWorkerRequestHandler::ServiceWorkerRequestHandler(
    base::WeakPtr<ServiceWorkerContextCore> context,
    base::WeakPtr<ServiceWorkerProviderHost> provider_host,
    base::WeakPtr<storage::BlobStorageContext> blob_storage_context,
    common::ResourceType resource_type)
    : context_(context),
      provider_host_(provider_host),
      blob_storage_context_(blob_storage_context),
      resource_type_(resource_type) {}

}  // namespace host
