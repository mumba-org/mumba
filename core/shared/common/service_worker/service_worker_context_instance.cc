// Copyright 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/common/service_worker/service_worker_context_instance.h"

#include "core/shared/common/web_helper.h"

namespace common {

class WorkerNativeClientFactoryImpl : public common::WorkerNativeClientFactory {
public:
  WorkerNativeClientFactoryImpl(void* state, WorkerNativeClientCallbacks callbacks):
    state_(state), callbacks_(std::move(callbacks)) {}
  ~WorkerNativeClientFactoryImpl() override {}
  std::unique_ptr<blink::WorkerNativeClient> CreateWorkerNativeClient() override {
    return std::make_unique<WorkerNativeClientImpl>(kWorkerNativeClientTypeServiceWorker, state_, callbacks_);
  }
private:
  void* state_;
  WorkerNativeClientCallbacks callbacks_;
};

ServiceWorkerContextInstance::ServiceWorkerContextInstance(void* state, ServiceWorkerContextClientCallbacks callbacks):
 state_(state), callbacks_(std::move(callbacks)) {}

ServiceWorkerContextInstance::~ServiceWorkerContextInstance(){}

std::unique_ptr<common::WorkerNativeClientFactory> ServiceWorkerContextInstance::CreateWorkerNativeClientFactory() {
  void* worker_native_client_state = callbacks_.GetWorkerNativeClientState(state_);
  WorkerNativeClientCallbacks callbacks = callbacks_.GetWorkerNativeClientCallbacks(state_);
  return std::make_unique<WorkerNativeClientFactoryImpl>(worker_native_client_state, std::move(callbacks));
}

void ServiceWorkerContextInstance::OnOpenNewTab(const std::string& url){}
void ServiceWorkerContextInstance::OnClearCachedMetadata(const std::string& url){}
void ServiceWorkerContextInstance::OnWorkerReadyForInspection(){}
void ServiceWorkerContextInstance::OnWorkerContextFailedToStart(){}
void ServiceWorkerContextInstance::OnWorkerScriptLoaded(){}
void ServiceWorkerContextInstance::OnWorkerContextStarted(blink::WebServiceWorkerContextProxy* proxy){}
void ServiceWorkerContextInstance::DidEvaluateClassicScript(bool success){}
void ServiceWorkerContextInstance::DidInitializeWorkerContext(v8::Local<v8::Context> context){}
void ServiceWorkerContextInstance::WillDestroyWorkerContext(v8::Local<v8::Context> context){}
void ServiceWorkerContextInstance::OnWorkerContextDestroyed(){}
void ServiceWorkerContextInstance::OnException(const std::string& error_message, int line_number,int column_number, const std::string& source_url){}
void ServiceWorkerContextInstance::OnReportConsoleMessage(int source,
                          int level,
                          const std::string& message,
                          int line_number,
                          const std::string& source_url){}
void ServiceWorkerContextInstance::DidHandleActivateEvent(int request_id,
                            blink::mojom::ServiceWorkerEventStatus status,
                            double dispatch_event_time){}
void ServiceWorkerContextInstance::DidHandleBackgroundFetchAbortEvent(
    int request_id,
    blink::mojom::ServiceWorkerEventStatus status,
    double dispatch_event_time){}
void ServiceWorkerContextInstance::DidHandleBackgroundFetchClickEvent(
    int request_id,
    blink::mojom::ServiceWorkerEventStatus status,
    double dispatch_event_time){}
void ServiceWorkerContextInstance::DidHandleBackgroundFetchFailEvent(
    int request_id,
    blink::mojom::ServiceWorkerEventStatus status,
    double dispatch_event_time){}
void ServiceWorkerContextInstance::DidHandleBackgroundFetchedEvent(
    int request_id,
    blink::mojom::ServiceWorkerEventStatus status,
    double dispatch_event_time){}
void ServiceWorkerContextInstance::DidHandleExtendableMessageEvent(
    int request_id,
    blink::mojom::ServiceWorkerEventStatus status,
    double dispatch_event_time){}
void ServiceWorkerContextInstance::DidHandleInstallEvent(int event_id,
                            blink::mojom::ServiceWorkerEventStatus status,
                            double event_dispatch_time) {}
void ServiceWorkerContextInstance::OnRespondToFetchEventWithNoResponse(int fetch_event_id,
                                        double event_dispatch_time){}
void ServiceWorkerContextInstance::OnRespondToFetchEvent(int fetch_event_id,
                          const blink::WebServiceWorkerResponse& response,
                          double event_dispatch_time){}
void ServiceWorkerContextInstance::OnRespondToFetchEventWithResponseStream(
    int fetch_event_id,
    const blink::WebServiceWorkerResponse& response,
    blink::WebServiceWorkerStreamHandle* web_body_as_stream,
    double event_dispatch_time){}
void ServiceWorkerContextInstance::DidHandleFetchEvent(int fetch_event_id,
                          blink::mojom::ServiceWorkerEventStatus status,
                          double dispatch_event_time){}
void ServiceWorkerContextInstance::DidHandleNotificationClickEvent(
    int request_id,
    blink::mojom::ServiceWorkerEventStatus status,
    double dispatch_event_time){}
void ServiceWorkerContextInstance::DidHandleNotificationCloseEvent(
    int request_id,
    blink::mojom::ServiceWorkerEventStatus status,
    double dispatch_event_time){}
void ServiceWorkerContextInstance::DidHandlePushEvent(int request_id,
                        blink::mojom::ServiceWorkerEventStatus status,
                        double dispatch_event_time){}
void ServiceWorkerContextInstance::DidHandleSyncEvent(int request_id,
                        blink::mojom::ServiceWorkerEventStatus status,
                        double dispatch_event_time){}
void ServiceWorkerContextInstance::RespondToAbortPaymentEvent(int event_id,
                                bool payment_aborted,
                                double dispatch_event_time){}
void ServiceWorkerContextInstance::DidHandleAbortPaymentEvent(int event_id,
                                blink::mojom::ServiceWorkerEventStatus status,
                                double dispatch_event_time){}
void ServiceWorkerContextInstance::OnPostMessageToClient(const std::string& uuid,
                            const blink::TransferableMessage& message){}
void ServiceWorkerContextInstance::OnFocus(const std::string& uuid){}
void ServiceWorkerContextInstance::OnNavigate(const std::string& uuid, const std::string&){}
void ServiceWorkerContextInstance::OnSkipWaiting(){}
void ServiceWorkerContextInstance::OnClaim(){}

}