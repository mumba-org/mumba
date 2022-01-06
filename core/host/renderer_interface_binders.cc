// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/renderer_interface_binders.h"

#include <utility>

#include "base/bind.h"
#include "core/host/background_fetch/background_fetch_service_impl.h"
//#include "core/host/dedicated_worker/dedicated_worker_host.h"
//#include "core/host/locks/lock_manager.h"
#include "core/host/notifications/platform_notification_context_impl.h"
//#include "core/host/payments/payment_manager.h"
//#include "core/host/permissions/permission_service_context.h"
//#include "core/host/quota_dispatcher_host.h"
//#include "core/host/renderer_host/render_process_host_impl.h"
//#include "core/host/storage_partition_impl.h"
#include "core/host/websockets/websocket_manager.h"
//#include "core/host/browser_context.h"
#include "core/host/host_thread.h"
#include "core/host/host_client.h"
#include "core/host/application/application_window_host.h"
#include "core/host/application/application_process_host.h"
#include "core/host/application/domain.h"
#include "core/host/net/host_network_context.h"
#include "core/shared/common/switches.h"
#include "services/device/public/mojom/constants.mojom.h"
#include "services/device/public/mojom/vibration_manager.mojom.h"
#include "services/network/restricted_cookie_manager.h"
#include "services/service_manager/public/cpp/binder_registry.h"
#include "services/service_manager/public/cpp/connector.h"
#include "services/shape_detection/public/mojom/barcodedetection.mojom.h"
#include "services/shape_detection/public/mojom/constants.mojom.h"
#include "services/shape_detection/public/mojom/facedetection_provider.mojom.h"
#include "services/shape_detection/public/mojom/textdetection.mojom.h"
#include "third_party/blink/public/platform/modules/cache_storage/cache_storage.mojom.h"
#include "third_party/blink/public/platform/modules/notifications/notification_service.mojom.h"
#include "url/origin.h"

namespace host {
namespace {

// A holder for a parameterized BinderRegistry for content-layer interfaces
// exposed to web workers.
class RendererInterfaceBinders {
 public:
  RendererInterfaceBinders() { InitializeParameterizedBinderRegistry(); }

  

  // Bind an interface request |interface_pipe| for |interface_name| received
  // from a web worker with origin |origin| hosted in the renderer |host|.
  void BindInterface(const std::string& interface_name,
                     mojo::ScopedMessagePipeHandle interface_pipe,
                     ApplicationProcessHost* host,
                     const url::Origin& origin) {
    DLOG(INFO) << "RendererInterfaceBinders::BindInterface (host): '" << interface_name << "' (NOT GOING ANYWHERE)\n";
    if (parameterized_binder_registry_.TryBindInterface(
            interface_name, &interface_pipe, host, origin)) {
      return;
    }
    // if (!frame_interfaces_ && !frame_interfaces_parameterized_ &&
    //   !worker_interfaces_parameterized_) {
    //     InitWebContextInterfaces();
    // }
    // worker_interfaces_parameterized_->BindInterface(
    //   interface_name, std::move(interface_pipe), host, origin);
    // GetContentClient()->browser()->BindInterfaceRequestFromWorker(
    //     host, origin, interface_name, std::move(interface_pipe));
  }

  // Try binding an interface request |interface_pipe| for |interface_name|
  // received from |frame|.
  bool TryBindInterface(const std::string& interface_name,
                        mojo::ScopedMessagePipeHandle* interface_pipe,
                        ApplicationWindowHost* frame) {
  DLOG(INFO) << "RendererInterfaceBinders::TryBindInterface (host): '" << interface_name << "'\n";
    return parameterized_binder_registry_.TryBindInterface(
        interface_name, interface_pipe, frame->GetProcess(),
        frame->GetLastCommittedOrigin());
  }

 private:
  void InitializeParameterizedBinderRegistry();

  static void CreateWebSocket(network::mojom::WebSocketRequest request,
                              ApplicationProcessHost* host,
                              const url::Origin& origin);

  service_manager::BinderRegistryWithArgs<ApplicationProcessHost*,
                                          const url::Origin&>
      parameterized_binder_registry_;
};

// Forwards service requests to Service Manager since the renderer cannot launch
// out-of-process services on is own.
template <typename Interface>
void ForwardServiceRequest(const char* service_name,
                           mojo::InterfaceRequest<Interface> request,
                           ApplicationProcessHost* host,
                           const url::Origin& origin) {
  auto* connector = host->GetConnector();//BrowserContext::GetConnectorFor(host->GetBrowserContext());
  connector->BindInterface(service_name, std::move(request));
}

// void GetRestrictedCookieManagerForWorker(
//     network::mojom::RestrictedCookieManagerRequest request,
//     ApplicationProcessHost* render_process_host,
//     const url::Origin& origin) {
//   // if (!base::CommandLine::ForCurrentProcess()->HasSwitch(
//   //         switches::kEnableExperimentalWebPlatformFeatures)) {
//   //   return;
//   // }

//   //StoragePartition* storage_partition =
//   //    render_process_host->GetStoragePartition();
//   network::mojom::NetworkContext* network_context =
//     render_process_host->GetNetworkContext();
//     //storage_partition->GetNetworkContext();
//   uint32_t render_process_id = render_process_host->GetID();
//   network_context->GetRestrictedCookieManager(
//       std::move(request), render_process_id, MSG_ROUTING_NONE);
// }

// Register renderer-exposed interfaces. Each registered interface binder is
// exposed to all renderer-hosted execution context types (document/frame,
// dedicated worker, shared worker and service worker) where the appropriate
// capability spec in the content_browser manifest includes the interface. For
// interface requests from frames, binders registered on the frame itself
// override binders registered here.
void RendererInterfaceBinders::InitializeParameterizedBinderRegistry() {
  DLOG(INFO) << "\n\nRendererInterfaceBinders::InitializeParameterizedBinderRegistry\n\n";
  DCHECK_CURRENTLY_ON(HostThread::IO);
  parameterized_binder_registry_.AddInterface(base::Bind(
      &ForwardServiceRequest<shape_detection::mojom::BarcodeDetection>,
      shape_detection::mojom::kServiceName));
  parameterized_binder_registry_.AddInterface(base::Bind(
      &ForwardServiceRequest<shape_detection::mojom::FaceDetectionProvider>,
      shape_detection::mojom::kServiceName));
  parameterized_binder_registry_.AddInterface(
      base::Bind(&ForwardServiceRequest<shape_detection::mojom::TextDetection>,
                 shape_detection::mojom::kServiceName));
  parameterized_binder_registry_.AddInterface(
      base::Bind(&ForwardServiceRequest<device::mojom::VibrationManager>,
                 device::mojom::kServiceName));
  parameterized_binder_registry_.AddInterface(
      base::BindRepeating(CreateWebSocket));
//   parameterized_binder_registry_.AddInterface(
//       base::Bind([](payments::mojom::PaymentManagerRequest request,
//                     ApplicationProcessHost* host, const url::Origin& origin) {
//         static_cast<StoragePartitionImpl*>(host->GetStoragePartition())
//             ->GetPaymentAppContext()
//             ->CreatePaymentManager(std::move(request));
//       }));
  parameterized_binder_registry_.AddInterface(base::BindRepeating(
      [](blink::mojom::CacheStorageRequest request, ApplicationProcessHost* host,
         const url::Origin& origin) {
        host->BindCacheStorage(
            std::move(request), origin);
      }));
//   parameterized_binder_registry_.AddInterface(
//       base::Bind([](blink::mojom::PermissionServiceRequest request,
//                     ApplicationProcessHost* host, const url::Origin& origin) {
//         static_cast<ApplicationProcessHost*>(host)
//             ->permission_service_context()
//             .CreateServiceForWorker(std::move(request), origin);
//       }));
//   parameterized_binder_registry_.AddInterface(base::BindRepeating(
//       [](blink::mojom::LockManagerRequest request, ApplicationProcessHost* host,
//          const url::Origin& origin) {
//         static_cast<StoragePartitionImpl*>(host->GetStoragePartition())
//             ->GetLockManager()
//             ->CreateService(std::move(request), origin);
//       }));
//   parameterized_binder_registry_.AddInterface(
//       base::Bind(&CreateDedicatedWorkerHostFactory));
  parameterized_binder_registry_.AddInterface(
      base::Bind([](blink::mojom::NotificationServiceRequest request,
                    ApplicationProcessHost* host, const url::Origin& origin) {
        //static_cast<StoragePartitionImpl*>(host->GetStoragePartition())
        host->domain()->GetPlatformNotificationContext()
            ->CreateService(host->GetID(), origin, std::move(request));
      }));
  parameterized_binder_registry_.AddInterface(
      base::BindRepeating(&BackgroundFetchServiceImpl::Create));
  //parameterized_binder_registry_.AddInterface(
  //    base::BindRepeating(GetRestrictedCookieManagerForWorker));
  //parameterized_binder_registry_.AddInterface(
  //    base::BindRepeating(&QuotaDispatcherHost::CreateForWorker));
}

RendererInterfaceBinders& GetRendererInterfaceBinders() {
  CR_DEFINE_STATIC_LOCAL(RendererInterfaceBinders, binders, ());
  return binders;
}

void RendererInterfaceBinders::CreateWebSocket(
    network::mojom::WebSocketRequest request,
    ApplicationProcessHost* host,
    const url::Origin& origin) {
  WebSocketManager::CreateWebSocket(host->GetID(), MSG_ROUTING_NONE, origin,
                                    std::move(request));
}

}  // namespace

void BindWorkerInterface(const std::string& interface_name,
                         mojo::ScopedMessagePipeHandle interface_pipe,
                         ApplicationProcessHost* host,
                         const url::Origin& origin) {
  DCHECK_CURRENTLY_ON(HostThread::IO);

  GetRendererInterfaceBinders().BindInterface(
      interface_name, std::move(interface_pipe), host, origin);
}

bool TryBindFrameInterface(const std::string& interface_name,
                           mojo::ScopedMessagePipeHandle* interface_pipe,
                           ApplicationWindowHost* frame) {
  DCHECK_CURRENTLY_ON(HostThread::UI);

  return GetRendererInterfaceBinders().TryBindInterface(interface_name,
                                                        interface_pipe, frame);
}

}  // namespace content
