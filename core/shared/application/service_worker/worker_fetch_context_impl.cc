// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/application/service_worker/worker_fetch_context_impl.h"

#include "base/feature_list.h"
#include "core/shared/common/child_thread_impl.h"
#include "core/shared/application/thread_safe_sender.h"
#include "core/shared/common/frame_messages.h"
#include "core/shared/common/service_worker/service_worker_utils.h"
#include "core/shared/common/wrapper_shared_url_loader_factory.h"
#include "core/shared/common/content_features.h"
#include "core/shared/common/service_names.mojom.h"
#include "core/shared/application/application_thread.h"
#include "core/shared/application/url_loader_throttle_provider.h"
#include "core/shared/application/websocket_handshake_throttle_provider.h"
#include "core/shared/application/request_extra_data.h"
#include "core/shared/application/resource_dispatcher.h"
#include "core/shared/application/application_url_loader.h"
#include "core/shared/application/web_url_request_util.h"
#include "core/shared/application/service_worker/controller_service_worker_connector.h"
#include "core/shared/application/service_worker/service_worker_subresource_loader.h"
#include "mojo/public/cpp/bindings/binding.h"
#include "mojo/public/cpp/bindings/strong_binding.h"
#include "services/service_manager/public/cpp/connector.h"
#include "core/shared/application/application_window_dispatcher.h"
#include "runtime/MumbaShims/ApplicationHandler.h"
#include "third_party/blink/public/mojom/service_worker/service_worker_object.mojom.h"
#include "third_party/blink/renderer/platform/wtf/text/text_encoding.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"

namespace application {

class ReceivedDataImpl : public application::RequestPeer::ReceivedData {
public:
  ReceivedDataImpl():
   payload_(nullptr), length_(0) {}

  ReceivedDataImpl(char* payload, int length):
   payload_(payload), length_(length) {

  }

  ~ReceivedDataImpl() {
    if (payload_) {
      free(payload_);
    }
  }

  const char* payload() const override {
    return payload_;
  } 

  int length() const override {
    return length_;
  }

private:
  char* payload_;
  int length_;
};

class ApplicationResponseHandler : public application::ResponseHandler {
public:
  ApplicationResponseHandler(void* state, CResponseHandler cbs):
   state_(state),
   callbacks_(std::move(cbs)) {
     //DLOG(INFO) << "ApplicationResponseHandler (constructor): calling callbacks_.GetName()";
     name_ = std::string(callbacks_.GetName(state_));
   }

  ~ApplicationResponseHandler() override {}

  const std::string& name() const {
    return name_;
  }

  bool WillHandleResponse(blink::WebURLResponse* response) override {
    //DLOG(INFO) << "ApplicationResponseHandler::WillHandleResponse";
    return callbacks_.WillHandleResponse(state_, response) != 0;
  }

  int OnDataAvailable(const char* input, int input_len) override {
    //DLOG(INFO) << "ApplicationResponseHandler::OnDataAvailable";
    return callbacks_.OnDataAvailable(state_, input, input_len); 
  }

  int OnFinishLoading(int error_code, int total_transfer_size) override {
    //DLOG(INFO) << "ApplicationResponseHandler::OnFinishLoading";
    return callbacks_.OnFinishLoading(state_, error_code, total_transfer_size);
  }

  std::unique_ptr<application::RequestPeer::ReceivedData> GetResult() override {
    //DLOG(INFO) << "ApplicationResponseHandler::GetResult";
    char* data = nullptr;
    int len = 0;
    callbacks_.GetResult(state_, &data, &len);
    return std::make_unique<ReceivedDataImpl>(data, len);
  }

private:
  void* state_;
  CResponseHandler callbacks_;
  std::string name_;

  DISALLOW_COPY_AND_ASSIGN(ApplicationResponseHandler);
};

class WorkerFetchContextImpl::URLLoaderFactoryImpl
    : public blink::WebURLLoaderFactory {
 public:
  URLLoaderFactoryImpl(
      base::WeakPtr<ResourceDispatcher> resource_dispatcher,
      scoped_refptr<network::SharedURLLoaderFactory> loader_factory,
      ApplicationWindowDispatcher* window_dispatcher)
      : resource_dispatcher_(std::move(resource_dispatcher)),
        loader_factory_(std::move(loader_factory)),
        url_loader_state_(nullptr),
        window_dispatcher_(window_dispatcher),
        weak_ptr_factory_(this) {}
  ~URLLoaderFactoryImpl() override = default;

  std::unique_ptr<blink::WebURLLoader> CreateURLLoader(
      const blink::WebURLRequest& request,
      scoped_refptr<base::SingleThreadTaskRunner> task_runner) override {
    DCHECK(task_runner);
    DCHECK(resource_dispatcher_);
    if (auto loader = CreateServiceWorkerURLLoader(request, task_runner))
      return loader;
    //return std::make_unique<ApplicationURLLoader>(
    //    resource_dispatcher_.get(), std::move(task_runner), loader_factory_);
    DCHECK(window_dispatcher_);
    url_loader_state_ = window_dispatcher_->CreateURLLoader(
      const_cast<blink::WebURLRequest *>(&request),
      &callbacks_);

    auto loader = std::make_unique<application::ApplicationURLLoader>(
      resource_dispatcher_.get(),
      task_runner,
      loader_factory_,
      callbacks_, 
      url_loader_state_);

    int resp_handler_count = window_dispatcher_->CountResponseHandler();
    for (int i = 0; i < resp_handler_count; i++) {
      CResponseHandler handler;
      void* handler_state = window_dispatcher_->GetResponseHandlerAt(
      i,
      &handler);
      if (handler_state) {
        loader->AddHandler(std::make_unique<ApplicationResponseHandler>(
          handler_state,
          std::move(handler)));
      }
    }
    return loader;
  }

  void SetServiceWorkerURLLoaderFactory(
      network::mojom::URLLoaderFactoryPtr service_worker_url_loader_factory) {
    service_worker_url_loader_factory_ =
        base::MakeRefCounted<common::WrapperSharedURLLoaderFactory>(
            std::move(service_worker_url_loader_factory));
  }

  base::WeakPtr<URLLoaderFactoryImpl> GetWeakPtr() {
    return weak_ptr_factory_.GetWeakPtr();
  }

 private:
  std::unique_ptr<blink::WebURLLoader> CreateServiceWorkerURLLoader(
      const blink::WebURLRequest& request,
      scoped_refptr<base::SingleThreadTaskRunner> task_runner) {
    // TODO(horo): Unify this code path with
    // ServiceWorkerNetworkProvider::CreateURLLoader that is used for document
    // cases.

    // We need URLLoaderFactory populated in order to create our own URLLoader
    // for subresource loading via a service worker.
    if (!service_worker_url_loader_factory_)
      return nullptr;

    // If it's not for HTTP or HTTPS no need to intercept the request.
    GURL request_url(request.Url().GetString().Utf8(), request.Url().GetParsed(), request.Url().IsValid());
    if (!request_url.SchemeIsHTTPOrHTTPS())
      return nullptr;

    // If GetSkipServiceWorker() returns true, no need to intercept the request.
    if (request.GetSkipServiceWorker())
      return nullptr;

    // Create our own URLLoader to route the request to the controller service
    // worker.
    return std::make_unique<ApplicationURLLoader>(
        resource_dispatcher_.get(), std::move(task_runner),
        service_worker_url_loader_factory_);
  }

  base::WeakPtr<ResourceDispatcher> resource_dispatcher_;
  scoped_refptr<network::SharedURLLoaderFactory> loader_factory_;
  scoped_refptr<network::SharedURLLoaderFactory>
      service_worker_url_loader_factory_;
  CBlinkPlatformCallbacks callbacks_;
  void* url_loader_state_;
  ApplicationWindowDispatcher* window_dispatcher_;
  base::WeakPtrFactory<URLLoaderFactoryImpl> weak_ptr_factory_;
  DISALLOW_COPY_AND_ASSIGN(URLLoaderFactoryImpl);
};

WorkerFetchContextImpl::WorkerFetchContextImpl(
    common::mojom::ServiceWorkerWorkerClientRequest service_worker_client_request,
    common::mojom::ServiceWorkerContainerHostPtrInfo service_worker_container_host_info,
    std::unique_ptr<network::SharedURLLoaderFactoryInfo>
        url_loader_factory_info,
    std::unique_ptr<network::SharedURLLoaderFactoryInfo>
        direct_network_factory_info,
    std::unique_ptr<URLLoaderThrottleProvider> throttle_provider,
    std::unique_ptr<WebSocketHandshakeThrottleProvider>
        websocket_handshake_throttle_provider,
    ThreadSafeSender* thread_safe_sender,
    ApplicationWindowDispatcher* dispatcher)
    : binding_(this),
      service_worker_client_request_(std::move(service_worker_client_request)),
      service_worker_container_host_info_(
          std::move(service_worker_container_host_info)),
      url_loader_factory_info_(std::move(url_loader_factory_info)),
      direct_network_loader_factory_info_(
          std::move(direct_network_factory_info)),
      thread_safe_sender_(thread_safe_sender),
      throttle_provider_(std::move(throttle_provider)),
      websocket_handshake_throttle_provider_(
          std::move(websocket_handshake_throttle_provider)),
      dispatcher_(dispatcher) {
  if (common::ServiceWorkerUtils::IsServicificationEnabled()) {
    //ChildThreadImpl::current()->GetConnector()->BindInterface(
    ApplicationThread::current()->GetConnector()->BindInterface(
        //common::mojom::kBrowserServiceName,
        common::mojom::kHostServiceName,
        mojo::MakeRequest(&blob_registry_ptr_info_));
  }
}

WorkerFetchContextImpl::~WorkerFetchContextImpl() {}

void WorkerFetchContextImpl::SetTerminateSyncLoadEvent(
    base::WaitableEvent* terminate_sync_load_event) {
  DCHECK(!terminate_sync_load_event_);
  terminate_sync_load_event_ = terminate_sync_load_event;
}

std::unique_ptr<blink::WebWorkerFetchContext>
WorkerFetchContextImpl::CloneForNestedWorker() {
  // TODO(japhet?): This doens't plumb service worker state to nested workers,
  // because dedicated workers in service worker-controlled documents are
  // currently not spec compliant and we don't want to propagate the wrong
  // behavior. See https://crbug.com/731604
  auto new_context = std::make_unique<WorkerFetchContextImpl>(
      common::mojom::ServiceWorkerWorkerClientRequest(),
      common::mojom::ServiceWorkerContainerHostPtrInfo(),
      shared_url_loader_factory_->Clone(),
      direct_network_loader_factory_->Clone(),
      throttle_provider_ ? throttle_provider_->Clone() : nullptr,
      websocket_handshake_throttle_provider_
          ? websocket_handshake_throttle_provider_->Clone()
          : nullptr,
      thread_safe_sender_.get(),
      dispatcher_);
  new_context->is_on_sub_frame_ = is_on_sub_frame_;
  new_context->appcache_host_id_ = appcache_host_id_;
  return new_context;
}

void WorkerFetchContextImpl::InitializeOnWorkerThread() {
  DCHECK(!resource_dispatcher_);
  DCHECK(!binding_.is_bound());
  resource_dispatcher_ = std::make_unique<ResourceDispatcher>();
  resource_dispatcher_->set_terminate_sync_load_event(
      terminate_sync_load_event_);

  shared_url_loader_factory_ = network::SharedURLLoaderFactory::Create(
      std::move(url_loader_factory_info_));
  direct_network_loader_factory_ = network::SharedURLLoaderFactory::Create(
      std::move(direct_network_loader_factory_info_));
  if (service_worker_client_request_.is_pending())
    binding_.Bind(std::move(service_worker_client_request_));

  if (common::ServiceWorkerUtils::IsServicificationEnabled()) {
    service_worker_container_host_.Bind(
        std::move(service_worker_container_host_info_));

    blink::mojom::BlobRegistryPtr blob_registry_ptr;
    blob_registry_ptr.Bind(std::move(blob_registry_ptr_info_));
    blob_registry_ = base::MakeRefCounted<
        base::RefCountedData<blink::mojom::BlobRegistryPtr>>(
        std::move(blob_registry_ptr));
  }
}

std::unique_ptr<blink::WebURLLoaderFactory>
WorkerFetchContextImpl::CreateURLLoaderFactory() {
  DCHECK(shared_url_loader_factory_);
  DCHECK(!url_loader_factory_);
  auto factory = std::make_unique<URLLoaderFactoryImpl>(
      resource_dispatcher_->GetWeakPtr(), shared_url_loader_factory_, dispatcher_);
  url_loader_factory_ = factory->GetWeakPtr();

  if (common::ServiceWorkerUtils::IsServicificationEnabled())
    ResetServiceWorkerURLLoaderFactory();

  return factory;
}

std::unique_ptr<blink::WebURLLoaderFactory>
WorkerFetchContextImpl::WrapURLLoaderFactory(
    mojo::ScopedMessagePipeHandle url_loader_factory_handle) {
  return std::make_unique<ApplicationURLLoaderFactory>(
      resource_dispatcher_->GetWeakPtr(),
      base::MakeRefCounted<common::WrapperSharedURLLoaderFactory>(
          network::mojom::URLLoaderFactoryPtrInfo(
              std::move(url_loader_factory_handle),
              network::mojom::URLLoaderFactory::Version_)),
      dispatcher_);
}

void WorkerFetchContextImpl::WillSendRequest(blink::WebURLRequest& request) {
  auto extra_data = std::make_unique<RequestExtraData>();
  extra_data->set_service_worker_provider_id(service_worker_provider_id_);
  extra_data->set_render_frame_id(parent_frame_id_);
  extra_data->set_initiated_in_secure_context(is_secure_context_);
  if (throttle_provider_) {
    extra_data->set_url_loader_throttles(throttle_provider_->CreateThrottles(
        parent_frame_id_, request, WebURLRequestToResourceType(request)));
  }
  request.SetExtraData(std::move(extra_data));
  request.SetAppCacheHostID(appcache_host_id_);

  if (!IsControlledByServiceWorker()) {
    // TODO(falken): Is still this needed? It used to set kForeign for foreign
    // fetch.
    request.SetSkipServiceWorker(true);
  }
}

bool WorkerFetchContextImpl::IsControlledByServiceWorker() const {
  return is_controlled_by_service_worker_ ||
         (controller_version_id_ !=
          blink::mojom::kInvalidServiceWorkerVersionId);
}

void WorkerFetchContextImpl::SetIsOnSubframe(bool is_on_sub_frame) {
  is_on_sub_frame_ = is_on_sub_frame;
}

bool WorkerFetchContextImpl::IsOnSubframe() const {
  return is_on_sub_frame_;
}

blink::WebURL WorkerFetchContextImpl::SiteForCookies() const {
  return blink::KURL(String::FromUTF8(site_for_cookies_.possibly_invalid_spec().data()));
}

void WorkerFetchContextImpl::DidRunContentWithCertificateErrors() {
  //Send(new FrameHostMsg_DidRunContentWithCertificateErrors(parent_frame_id_));
}

void WorkerFetchContextImpl::DidDisplayContentWithCertificateErrors() {
  //Send(new FrameHostMsg_DidDisplayContentWithCertificateErrors(
  //    parent_frame_id_));
}

void WorkerFetchContextImpl::DidRunInsecureContent(
    const blink::WebSecurityOrigin& origin,
    const blink::WebURL& url) {
  //Send(new FrameHostMsg_DidRunInsecureContent(
  //    parent_frame_id_, GURL(origin.ToString().Utf8()), url));
}

void WorkerFetchContextImpl::SetSubresourceFilterBuilder(
    std::unique_ptr<blink::WebDocumentSubresourceFilter::Builder>
        subresource_filter_builder) {
  subresource_filter_builder_ = std::move(subresource_filter_builder);
}

std::unique_ptr<blink::WebDocumentSubresourceFilter>
WorkerFetchContextImpl::TakeSubresourceFilter() {
  if (!subresource_filter_builder_)
    return nullptr;
  return std::move(subresource_filter_builder_)->Build();
}

std::unique_ptr<blink::WebSocketHandshakeThrottle>
WorkerFetchContextImpl::CreateWebSocketHandshakeThrottle() {
  if (!websocket_handshake_throttle_provider_)
    return nullptr;
  return websocket_handshake_throttle_provider_->CreateThrottle(
      parent_frame_id_);
}

void WorkerFetchContextImpl::set_service_worker_provider_id(int id) {
  service_worker_provider_id_ = id;
}

void WorkerFetchContextImpl::set_is_controlled_by_service_worker(bool flag) {
  is_controlled_by_service_worker_ = flag;
}

void WorkerFetchContextImpl::set_parent_frame_id(int id) {
  parent_frame_id_ = id;
}

void WorkerFetchContextImpl::set_site_for_cookies(
    const blink::WebURL& site_for_cookies) {
  site_for_cookies_ = GURL(site_for_cookies.GetString().Utf8(), site_for_cookies.GetParsed(), site_for_cookies.IsValid());;
}

void WorkerFetchContextImpl::set_is_secure_context(bool flag) {
  is_secure_context_ = flag;
}

void WorkerFetchContextImpl::set_origin_url(const GURL& origin_url) {
  origin_url_ = origin_url;
}

void WorkerFetchContextImpl::SetApplicationCacheHostID(int id) {
  appcache_host_id_ = id;
}

int WorkerFetchContextImpl::ApplicationCacheHostID() const {
  return appcache_host_id_;
}

void WorkerFetchContextImpl::SetControllerServiceWorker(
    int64_t controller_version_id) {
  controller_version_id_ = controller_version_id;
  if (common::ServiceWorkerUtils::IsServicificationEnabled())
    ResetServiceWorkerURLLoaderFactory();
}

bool WorkerFetchContextImpl::Send(IPC::Message* message) {
  return thread_safe_sender_->Send(message);
}

void WorkerFetchContextImpl::ResetServiceWorkerURLLoaderFactory() {
  DCHECK(common::ServiceWorkerUtils::IsServicificationEnabled());
  if (!url_loader_factory_)
    return;
  if (!IsControlledByServiceWorker()) {
    url_loader_factory_->SetServiceWorkerURLLoaderFactory(nullptr);
    return;
  }
  network::mojom::URLLoaderFactoryPtr service_worker_url_loader_factory;
  ServiceWorkerSubresourceLoaderFactory::Create(
      base::MakeRefCounted<ControllerServiceWorkerConnector>(
          service_worker_container_host_.get()),
      direct_network_loader_factory_,
      mojo::MakeRequest(&service_worker_url_loader_factory));
  url_loader_factory_->SetServiceWorkerURLLoaderFactory(
      std::move(service_worker_url_loader_factory));
}

}  // namespace application
