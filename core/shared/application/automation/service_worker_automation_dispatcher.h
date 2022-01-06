// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_APPLICATION_SERVICE_WORKER_AUTOMATION_DISPATCHER_H_
#define MUMBA_APPLICATION_SERVICE_WORKER_AUTOMATION_DISPATCHER_H_

#include "core/shared/common/mojom/automation.mojom.h"

#include "mojo/public/cpp/bindings/binding.h"
#include "mojo/public/cpp/bindings/associated_binding.h"
#include "third_party/blink/renderer/platform/heap/heap.h"
#include "third_party/blink/renderer/platform/heap/heap_traits.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "third_party/blink/renderer/core/animation/animation.h"

namespace blink {
class WorkerInspectorProxy;
class WorkerGlobalScope;
class WebLocalFrame;
}

namespace service_manager {
class InterfaceProvider;
}

namespace IPC {
class SyncChannel;
}

namespace application {
class InspectorWorkerAgentImpl;
class ApplicationWindowDispatcher;
class PageInstance;

class ServiceWorkerAutomationDispatcher : public automation::ServiceWorker {
public:
  static void Create(automation::ServiceWorkerRequest request, PageInstance* page_instance, blink::WorkerGlobalScope* scope);

  ServiceWorkerAutomationDispatcher(automation::ServiceWorkerRequest request, PageInstance* page_instance, blink::WorkerGlobalScope* scope);
  ServiceWorkerAutomationDispatcher(PageInstance* page_instance, blink::WorkerGlobalScope* scope);
  ~ServiceWorkerAutomationDispatcher() override;

  void Init(IPC::SyncChannel* channel);
  void Bind(automation::ServiceWorkerAssociatedRequest request);

  void Register(int32_t application_id) override;
  void DeliverPushMessage(const std::string& origin, const std::string& registration_id, const std::string& data) override;
  void Disable() override;
  void DispatchSyncEvent(const std::string& origin, const std::string& registration_id, const std::string& tag, bool last_chance) override;
  void Enable() override;
  void InspectWorker(const std::string& version_id) override;
  void SetForceUpdateOnPageLoad(bool force_update_on_pageload) override;
  void SkipWaiting(const std::string& scope_url) override;
  void StartWorker(const std::string& scope_url) override;
  void StopAllWorkers() override;
  void StopWorker(const std::string& version_id) override;
  void Unregister(const std::string& scope_url) override;
  void UpdateRegistration(const std::string& scope_url) override;
  void SendMessageToTarget(const std::string& message,
                           const base::Optional<std::string>& session_id,
                           const base::Optional<std::string>& target_id) override;

  PageInstance* page_instance() const {
    return page_instance_;
  }

  automation::ServiceWorkerClient* GetClient();

  void OnWebFrameCreated(blink::WebLocalFrame* web_frame);
  
private:
  friend class InspectorWorkerAgentImpl;

  void ShouldWaitForDebuggerOnWorkerStart(bool* result);
  void DidStartWorker(blink::WorkerInspectorProxy*, bool waiting_for_debugger);
  void WorkerTerminated(blink::WorkerInspectorProxy*);
  void ConnectToAllProxies();
  void DisconnectFromAllProxies(bool report_to_frontend);
  void ConnectToProxy(blink::WorkerInspectorProxy* proxy, bool waiting_for_debugger);
  void DispatchMessageFromWorker(
    blink::WorkerInspectorProxy* proxy,
    int connection,
    const String& message);
  base::DictionaryValue* AttachedSessionIds();
  
  int32_t application_id_;
  PageInstance* page_instance_;
  blink::Member<blink::WorkerGlobalScope> worker_global_scope_;
  mojo::AssociatedBinding<automation::ServiceWorker> binding_;
  automation::ServiceWorkerClientAssociatedPtr service_worker_client_ptr_;
  blink::Persistent<InspectorWorkerAgentImpl> worker_agent_impl_;
  blink::HeapHashMap<int, blink::Member<blink::WorkerInspectorProxy>> connected_proxies_;
  HashMap<int, String> connection_to_session_id_;
  HashMap<String, int> session_id_to_connection_;
  std::unique_ptr<base::DictionaryValue> attached_session_ids_;
  bool enabled_;
  static int s_last_connection_;

  DISALLOW_COPY_AND_ASSIGN(ServiceWorkerAutomationDispatcher); 
};

}

#endif