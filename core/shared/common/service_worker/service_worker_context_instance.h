// Copyright 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_COMMON_SERVICE_WORKER_SERVICE_WORKER_CONTEXT_INSTANCE_H_
#define CONTENT_COMMON_SERVICE_WORKER_SERVICE_WORKER_CONTEXT_INSTANCE_H_

#include <memory>

#include "base/callback.h"
#include "base/containers/id_map.h"
#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/strings/string16.h"
#include "base/time/time.h"
#include "core/shared/common/service_worker/controller_service_worker.mojom.h"
#include "core/shared/common/service_worker/embedded_worker.mojom.h"
#include "core/shared/common/service_worker/service_worker_event_dispatcher.mojom.h"
#include "core/shared/common/service_worker/service_worker_provider.mojom.h"
#include "core/shared/common/service_worker/service_worker_status_code.h"
#include "core/shared/common/service_worker/service_worker_types.h"
#include "core/shared/common/content_export.h"
#include "core/shared/common/service_worker/worker_native_client_factory.h"
#include "ipc/ipc_listener.h"
#include "mojo/public/cpp/bindings/binding.h"
#include "third_party/blink/public/mojom/blob/blob_registry.mojom.h"
#include "third_party/blink/public/mojom/service_worker/service_worker.mojom.h"
#include "third_party/blink/public/mojom/service_worker/service_worker_client.mojom.h"
#include "third_party/blink/public/mojom/service_worker/service_worker_event_status.mojom.h"
#include "third_party/blink/public/mojom/service_worker/service_worker_registration.mojom.h"
#include "third_party/blink/public/platform/modules/payments/payment_app.mojom.h"
#include "third_party/blink/public/platform/modules/serviceworker/web_service_worker_error.h"
#include "third_party/blink/public/web/modules/serviceworker/web_service_worker_context_client.h"
#include "third_party/blink/public/web/modules/serviceworker/web_service_worker_context_proxy.h"
#include "v8/include/v8.h"
#include "runtime/MumbaShims/WebDefinitions.h"

namespace blink {
class WebDataConsumerHandle;
struct WebServiceWorkerClientQueryOptions;
class WebServiceWorkerContextProxy;
class WebServiceWorkerProvider;
class WebServiceWorkerResponse;
class WebURLResponse;
}

namespace common {

// TODO: C runtime callbacks here to be called by client  

class CONTENT_EXPORT ServiceWorkerContextInstance {
public:
  ServiceWorkerContextInstance(void* state, ServiceWorkerContextClientCallbacks callbacks);
  ~ServiceWorkerContextInstance();

  std::unique_ptr<common::WorkerNativeClientFactory> CreateWorkerNativeClientFactory();

  void OnOpenNewTab(const std::string& url);
  void OnClearCachedMetadata(const std::string& url);
  void OnWorkerReadyForInspection();
  void OnWorkerContextFailedToStart();
  void OnWorkerScriptLoaded();
  void OnWorkerContextStarted(blink::WebServiceWorkerContextProxy* proxy);
  void DidEvaluateClassicScript(bool success);
  void DidInitializeWorkerContext(v8::Local<v8::Context> context);
  void WillDestroyWorkerContext(v8::Local<v8::Context> context);
  void OnWorkerContextDestroyed();
  void OnException(const std::string& error_message, int line_number,int column_number, const std::string& source_url);
  void OnReportConsoleMessage(int source,
                            int level,
                            const std::string& message,
                            int line_number,
                            const std::string& source_url);
  void DidHandleActivateEvent(int request_id,
                              blink::mojom::ServiceWorkerEventStatus status,
                              double dispatch_event_time);
  void DidHandleBackgroundFetchAbortEvent(
      int request_id,
      blink::mojom::ServiceWorkerEventStatus status,
      double dispatch_event_time);
  void DidHandleBackgroundFetchClickEvent(
      int request_id,
      blink::mojom::ServiceWorkerEventStatus status,
      double dispatch_event_time);
  void DidHandleBackgroundFetchFailEvent(
      int request_id,
      blink::mojom::ServiceWorkerEventStatus status,
      double dispatch_event_time);
  void DidHandleBackgroundFetchedEvent(
      int request_id,
      blink::mojom::ServiceWorkerEventStatus status,
      double dispatch_event_time);
  void DidHandleExtendableMessageEvent(
      int request_id,
      blink::mojom::ServiceWorkerEventStatus status,
      double dispatch_event_time);
  void DidHandleInstallEvent(int event_id,
                             blink::mojom::ServiceWorkerEventStatus status,
                             double event_dispatch_time);
  void OnRespondToFetchEventWithNoResponse(int fetch_event_id,
                                         double event_dispatch_time);
  void OnRespondToFetchEvent(int fetch_event_id,
                           const blink::WebServiceWorkerResponse& response,
                           double event_dispatch_time);
  void OnRespondToFetchEventWithResponseStream(
      int fetch_event_id,
      const blink::WebServiceWorkerResponse& response,
      blink::WebServiceWorkerStreamHandle* web_body_as_stream,
      double event_dispatch_time);
  void DidHandleFetchEvent(int fetch_event_id,
                           blink::mojom::ServiceWorkerEventStatus status,
                           double dispatch_event_time);
  void DidHandleNotificationClickEvent(
      int request_id,
      blink::mojom::ServiceWorkerEventStatus status,
      double dispatch_event_time);
  void DidHandleNotificationCloseEvent(
      int request_id,
      blink::mojom::ServiceWorkerEventStatus status,
      double dispatch_event_time);
  void DidHandlePushEvent(int request_id,
                          blink::mojom::ServiceWorkerEventStatus status,
                          double dispatch_event_time);
  void DidHandleSyncEvent(int request_id,
                          blink::mojom::ServiceWorkerEventStatus status,
                          double dispatch_event_time);
  void RespondToAbortPaymentEvent(int event_id,
                                  bool payment_aborted,
                                  double dispatch_event_time);
  void DidHandleAbortPaymentEvent(int event_id,
                                  blink::mojom::ServiceWorkerEventStatus status,
                                  double dispatch_event_time);
  void OnPostMessageToClient(const std::string& uuid,
                             const blink::TransferableMessage& message);
  void OnFocus(const std::string& uuid);
  void OnNavigate(const std::string& uuid, const std::string&);
  void OnSkipWaiting();
  void OnClaim();

private:
 void* state_;
 ServiceWorkerContextClientCallbacks callbacks_;
};

}

#endif
