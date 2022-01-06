// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/application/automation/service_worker_automation_dispatcher.h"

#include "base/memory/scoped_refptr.h"
#include "core/shared/application/automation/page_instance.h"
#include "core/shared/application/application_window_dispatcher.h"
#include "services/service_manager/public/cpp/interface_provider.h"
#include "third_party/blink/renderer/core/inspector/inspected_frames.h"
#include "third_party/blink/renderer/core/inspector/inspector_worker_agent.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/inspector/identifiers_factory.h"
#include "third_party/blink/renderer/core/loader/document_loader.h"
#include "third_party/blink/renderer/core/loader/frame_loader.h"
#include "third_party/blink/renderer/platform/network/network_state_notifier.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/inspector/inspected_frames.h"
#include "third_party/blink/renderer/core/workers/execution_context_worker_registry.h"
#include "third_party/blink/renderer/core/workers/worker_global_scope.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "ipc/ipc_sync_channel.h"

namespace application {

int ServiceWorkerAutomationDispatcher::s_last_connection_ = 0;

class InspectorWorkerAgentImpl : public blink::InspectorWorkerAgent {
public: 
  InspectorWorkerAgentImpl(ServiceWorkerAutomationDispatcher* dispatcher, blink::WorkerGlobalScope* scope): 
    InspectorWorkerAgent(
      dispatcher->page_instance_->inspected_frames(), scope),// InspectorResourceContainer*),
    dispatcher_(dispatcher) {}

  void ShouldWaitForDebuggerOnWorkerStart(bool* result) override {
    dispatcher_->ShouldWaitForDebuggerOnWorkerStart(result);
  }

  void DidStartWorker(blink::WorkerInspectorProxy* proxy, bool waiting_for_debugger) override {
    dispatcher_->DidStartWorker(proxy, waiting_for_debugger);
  }

  void WorkerTerminated(blink::WorkerInspectorProxy* proxy) override {
    dispatcher_->WorkerTerminated(proxy); 
  }

private:
  ServiceWorkerAutomationDispatcher* dispatcher_;
};

// static 
void ServiceWorkerAutomationDispatcher::Create(automation::ServiceWorkerRequest request, PageInstance* page_instance, blink::WorkerGlobalScope* scope) {
  new ServiceWorkerAutomationDispatcher(std::move(request), page_instance, scope);
}

ServiceWorkerAutomationDispatcher::ServiceWorkerAutomationDispatcher(
  automation::ServiceWorkerRequest request, 
  PageInstance* page_instance,
  blink::WorkerGlobalScope* scope): 
  application_id_(-1),
  page_instance_(page_instance),
  worker_global_scope_(scope),
  binding_(this) {
  
}

ServiceWorkerAutomationDispatcher::ServiceWorkerAutomationDispatcher(
  PageInstance* page_instance,
  blink::WorkerGlobalScope* scope): 
  application_id_(-1),
  page_instance_(page_instance),
  worker_global_scope_(scope),
  binding_(this) {
  
}

ServiceWorkerAutomationDispatcher::~ServiceWorkerAutomationDispatcher() {

}

void ServiceWorkerAutomationDispatcher::Init(IPC::SyncChannel* channel) {
  channel->GetRemoteAssociatedInterface(&service_worker_client_ptr_);
}

void ServiceWorkerAutomationDispatcher::Bind(automation::ServiceWorkerAssociatedRequest request) {
  //DLOG(INFO) << "ServiceWorkerDispatcher::Bind (application)";
  binding_.Bind(std::move(request));
}

void ServiceWorkerAutomationDispatcher::DeliverPushMessage(const std::string& origin, const std::string& registration_id, const std::string& data) {
  
}

void ServiceWorkerAutomationDispatcher::Disable() {
  page_instance_->probe_sink()->removeInspectorWorkerAgent(worker_agent_impl_.Get());
  enabled_ = false;
}

void ServiceWorkerAutomationDispatcher::Register(int32_t application_id) {
  application_id_ = application_id;
}

void ServiceWorkerAutomationDispatcher::DispatchSyncEvent(const std::string& origin, const std::string& registration_id, const std::string& tag, bool last_chance) {

}

void ServiceWorkerAutomationDispatcher::Enable() {
  //DLOG(INFO) << "ServiceWorkerAutomationDispatcher::Enable (application process)";
  if (enabled_) {
    return;
  }
  page_instance_->probe_sink()->addInspectorWorkerAgent(worker_agent_impl_.Get());
  enabled_ = true;
}

void ServiceWorkerAutomationDispatcher::InspectWorker(const std::string& version_id) {

}

void ServiceWorkerAutomationDispatcher::SetForceUpdateOnPageLoad(bool force_update_on_pageload) {

}

void ServiceWorkerAutomationDispatcher::SkipWaiting(const std::string& scope_url) {

}

void ServiceWorkerAutomationDispatcher::StartWorker(const std::string& scope_url) {

}

void ServiceWorkerAutomationDispatcher::StopAllWorkers() {

}

void ServiceWorkerAutomationDispatcher::StopWorker(const std::string& version_id) {

}

void ServiceWorkerAutomationDispatcher::Unregister(const std::string& scope_url) {

}

void ServiceWorkerAutomationDispatcher::UpdateRegistration(const std::string& scope_url) {

}

void ServiceWorkerAutomationDispatcher::ShouldWaitForDebuggerOnWorkerStart(bool* result) {

}

void ServiceWorkerAutomationDispatcher::DidStartWorker(blink::WorkerInspectorProxy* proxy, bool waiting_for_debugger) {
  ConnectToProxy(proxy, false);
}

void ServiceWorkerAutomationDispatcher::WorkerTerminated(blink::WorkerInspectorProxy* proxy) {
  Vector<String> session_ids;
  for (auto& it : session_id_to_connection_) {
    if (connected_proxies_.at(it.value) == proxy)
      session_ids.push_back(it.key);
  }
  for (const String& session_id : session_ids) {
    AttachedSessionIds()->RemoveKey(std::string(session_id.Utf8().data()));
    GetClient()->OnDetachedFromTarget(
      std::string(session_id.Utf8().data()), 
      std::string(proxy->InspectorId().Utf8().data()));
    int connection = session_id_to_connection_.at(session_id);
    proxy->DisconnectFromInspector(connection, worker_agent_impl_.Get());
    connected_proxies_.erase(connection);
    connection_to_session_id_.erase(connection);
    session_id_to_connection_.erase(session_id);
  }
}

automation::ServiceWorkerClient* ServiceWorkerAutomationDispatcher::GetClient() {
  return service_worker_client_ptr_.get();
} 

void ServiceWorkerAutomationDispatcher::ConnectToAllProxies() {
  if (worker_global_scope_) {
    for (blink::WorkerInspectorProxy* proxy :
         blink::ExecutionContextWorkerRegistry::From(*worker_global_scope_)
             ->GetWorkerInspectorProxies()) {
      ConnectToProxy(proxy, false);
    }
    return;
  }

  for (blink::LocalFrame* frame : *page_instance_->inspected_frames()) {
    for (blink::WorkerInspectorProxy* proxy :
         blink::ExecutionContextWorkerRegistry::From(*frame->GetDocument())
             ->GetWorkerInspectorProxies()) {
      ConnectToProxy(proxy, false);
    }
  }
}

void ServiceWorkerAutomationDispatcher::DisconnectFromAllProxies(bool report_to_frontend) {
  for (auto& it : session_id_to_connection_) {
    blink::WorkerInspectorProxy* proxy = connected_proxies_.at(it.value);
    if (report_to_frontend) {
      AttachedSessionIds()->RemoveKey(std::string(it.key.Utf8().data()));
      GetClient()->OnDetachedFromTarget(
        std::string(it.key.Utf8().data()), 
        std::string(proxy->InspectorId().Utf8().data()));
    }
    proxy->DisconnectFromInspector(it.value, worker_agent_impl_.Get());
  }
  connection_to_session_id_.clear();
  session_id_to_connection_.clear();
  connected_proxies_.clear();
}

void ServiceWorkerAutomationDispatcher::ConnectToProxy(
  blink::WorkerInspectorProxy* proxy,
  bool waiting_for_debugger) {
  int connection = ++s_last_connection_;
  connected_proxies_.Set(connection, proxy);

  String session_id = proxy->InspectorId() + "-" + String::Number(connection);
  session_id_to_connection_.Set(session_id, connection);
  connection_to_session_id_.Set(connection, session_id);

  proxy->ConnectToInspector(connection, worker_agent_impl_.Get());
  std::unique_ptr<base::Value> bool_val = std::make_unique<base::Value>(true);
  AttachedSessionIds()->Set(
      std::string(session_id.Utf8().data()), 
      std::move(bool_val));

  auto info = automation::TargetInfo::New();
  info->target_id = std::string(proxy->InspectorId().Utf8().data());
  info->type = "worker";
  info->title = std::string(proxy->Url().Utf8().data());
  info->url = std::string(proxy->Url().Utf8().data());
  info->attached = true;
                                  
  GetClient()->OnAttachedToTarget(std::string(session_id.Utf8().data()),
                                  std::move(info),
                                  waiting_for_debugger);
}

void ServiceWorkerAutomationDispatcher::DispatchMessageFromWorker(
  blink::WorkerInspectorProxy* proxy,
  int connection,
  const String& message) {
  auto it = connection_to_session_id_.find(connection);
  if (it == connection_to_session_id_.end())
    return;
  GetClient()->OnReceivedMessageFromTarget(std::string(it->value.Utf8().data()), 
                                           std::string(message.Utf8().data()),
                                           std::string(proxy->InspectorId().Utf8().data()));
}

base::DictionaryValue* ServiceWorkerAutomationDispatcher::AttachedSessionIds() {
  base::DictionaryValue* ids = attached_session_ids_.get();
  if (!ids) {
    std::unique_ptr<base::DictionaryValue> new_ids = std::make_unique<base::DictionaryValue>();
    ids = new_ids.get();
    attached_session_ids_ = std::move(new_ids);
  }
  return ids;
}

void ServiceWorkerAutomationDispatcher::SendMessageToTarget(const std::string& message,
                                                            const base::Optional<std::string>& session_id,
                                                            const base::Optional<std::string>& target_id) {
  if (session_id.has_value()) {
    auto it = session_id_to_connection_.find(String::FromUTF8(session_id.value().data()));
    if (it == session_id_to_connection_.end()) {
      //DLOG(ERROR) << "No session with given id";
      return;
    }
    blink::WorkerInspectorProxy* proxy = connected_proxies_.at(it->value);
    proxy->SendMessageToInspector(it->value, String::FromUTF8(message.data()));
    return;
  }
  if (target_id.has_value()) {
    int connection = 0;
    for (auto& it : connected_proxies_) {
      if (it.value->InspectorId() == String::FromUTF8(target_id.value().data())) {
        if (connection) {
          //DLOG(ERROR) << "Multiple sessions attached, specify id";
          return;
        }
        connection = it.key;
      }
    }
    if (!connection) {
      //DLOG(ERROR) << "No target with given id";
      return;
    }
    blink::WorkerInspectorProxy* proxy = connected_proxies_.at(connection);
    proxy->SendMessageToInspector(connection, String::FromUTF8(message.data()));
    return;
  }
  //DLOG(ERROR) << "Session id must be specified";
}

void ServiceWorkerAutomationDispatcher::OnWebFrameCreated(blink::WebLocalFrame* web_frame) {
  worker_agent_impl_ = new InspectorWorkerAgentImpl(this, worker_global_scope_);
  worker_agent_impl_->Init(
    page_instance_->probe_sink(), 
    page_instance_->inspector_backend_dispatcher(),
    page_instance_->state());
  
  Enable();
}

}
