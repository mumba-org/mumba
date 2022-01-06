// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/application/automation/dom_storage_dispatcher.h"

#include "services/service_manager/public/cpp/interface_provider.h"
#include "core/shared/application/automation/page_instance.h"
#include "third_party/blink/renderer/modules/storage/inspector_dom_storage_agent.h"
#include "third_party/blink/renderer/bindings/core/v8/exception_state.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/dom/exception_code.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/inspector/inspected_frames.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/modules/storage/storage.h"
#include "third_party/blink/renderer/modules/storage/storage_namespace.h"
#include "third_party/blink/renderer/modules/storage/storage_namespace_controller.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"
#include "ipc/ipc_sync_channel.h"

namespace application {

class InspectorDOMStorageAgentImpl : public blink::InspectorDOMStorageAgent {
public: 
  InspectorDOMStorageAgentImpl(DOMStorageDispatcher* dispatcher): 
    InspectorDOMStorageAgent(
      dispatcher->page_instance_->inspected_frames()->Root()->View()->GetPage()),
    dispatcher_(dispatcher) {}

  void DidDispatchDOMStorageEvent(
    const String& key,
    const String& old_value,
    const String& new_value,
    blink::StorageArea::StorageType storage_type,
    const blink::SecurityOrigin* security_origin) override {
    dispatcher_->DidDispatchDOMStorageEvent(key, old_value, new_value, storage_type, security_origin);
  }

  void Restore() override {
    dispatcher_->Restore();
  }

private:
  DOMStorageDispatcher* dispatcher_;
};

// static 
void DOMStorageDispatcher::Create(automation::DOMStorageRequest request, PageInstance* page_instance) {
  new DOMStorageDispatcher(std::move(request), page_instance);
}

DOMStorageDispatcher::DOMStorageDispatcher(automation::DOMStorageRequest request, PageInstance* page_instance): 
  application_id_(-1),
  page_instance_(page_instance),
  binding_(this),
  enabled_(false) {
  
}

DOMStorageDispatcher::DOMStorageDispatcher(PageInstance* page_instance): 
  application_id_(-1),
  page_instance_(page_instance),
  binding_(this),
  enabled_(false) {
  
 }

DOMStorageDispatcher::~DOMStorageDispatcher() {

}

void DOMStorageDispatcher::Init(IPC::SyncChannel* channel) {
  channel->GetRemoteAssociatedInterface(&dom_storage_client_ptr_);
}

void DOMStorageDispatcher::Bind(automation::DOMStorageAssociatedRequest request) {
  //DLOG(INFO) << "DOMStorageDispatcher::Bind (application)";
  binding_.Bind(std::move(request));
}

automation::DOMStorageClient* DOMStorageDispatcher::GetClient() const {
  return dom_storage_client_ptr_.get();
}

void DOMStorageDispatcher::Register(int32_t application_id) {
  application_id_ = application_id;
}

void DOMStorageDispatcher::Disable() {
  if (!enabled_) {
    return;
  }
  enabled_ = false;
  if (blink::StorageNamespaceController* controller = blink::StorageNamespaceController::From(page_)) {
    controller->SetInspectorAgent(nullptr);
  }
}

void DOMStorageDispatcher::Enable() {
  //DLOG(INFO) << "DOMStorageDispatcher::Enable (application process)";
  if (enabled_) {
    return;
  }
  enabled_ = true;
  if (blink::StorageNamespaceController* controller = blink::StorageNamespaceController::From(page_))
    controller->SetInspectorAgent(dom_storage_agent_.Get());
}

void DOMStorageDispatcher::Clear(automation::StorageIdPtr storage_id) {
  blink::LocalFrame* frame = nullptr;
  blink::StorageArea* storage_area = nullptr;
  bool ok = FindStorageArea(std::move(storage_id), frame, storage_area);
  if (!ok) {
    //DLOG(ERROR) << "Could not clear the storage";
    return;
  }
  blink::DummyExceptionStateForTesting exception_state;
  storage_area->Clear(exception_state, frame);
  if (exception_state.HadException()) {
    //DLOG(ERROR) << "Could not clear the storage";
    return;
  }
}

void DOMStorageDispatcher::GetDOMStorageItems(automation::StorageIdPtr storage_id, GetDOMStorageItemsCallback callback) {
  blink::LocalFrame* frame = nullptr;
  blink::StorageArea* storage_area = nullptr;
  bool ok = FindStorageArea(std::move(storage_id), frame, storage_area);
  if (!ok) {
    std::move(callback).Run(std::vector<std::vector<std::string>>());
    return;
  }

  std::vector<std::vector<std::string>> storage_items;

  blink::DummyExceptionStateForTesting exception_state;
  for (unsigned i = 0; i < storage_area->length(exception_state, frame); ++i) {
    String name(storage_area->Key(i, exception_state, frame));
    if (exception_state.HadException()) {
      //DLOG(ERROR) << "Exception while converting storage_area->Key(i = " << i << ") to a name";
      std::move(callback).Run(std::vector<std::vector<std::string>>());
      return;
    }
    String value(storage_area->GetItem(name, exception_state, frame));
    if (exception_state.HadException()) {
      //DLOG(ERROR) << "Exception while converting storage_area->GetItem(name) to a value";
      std::move(callback).Run(std::vector<std::vector<std::string>>());
      return;
    }
    std::vector<std::string> entry;
    entry.push_back(std::string(name.Utf8().data(), name.length()));
    entry.push_back(std::string(value.Utf8().data(), value.length()));
    storage_items.push_back(std::move(entry));
  }
  std::move(callback).Run(std::move(storage_items));
}

void DOMStorageDispatcher::RemoveDOMStorageItem(automation::StorageIdPtr storage_id, const std::string& key) {
  blink::LocalFrame* frame = nullptr;
  blink::StorageArea* storage_area = nullptr;
  bool ok = FindStorageArea(std::move(storage_id), frame, storage_area);
  if (!ok) {
    return;
  }

  blink::DummyExceptionStateForTesting exception_state;
  storage_area->RemoveItem(String::FromUTF8(key.data()), exception_state, frame);
}

void DOMStorageDispatcher::SetDOMStorageItem(automation::StorageIdPtr storage_id, const std::string& key, const std::string& value) {
  blink::LocalFrame* frame = nullptr;
  blink::StorageArea* storage_area = nullptr;
  bool ok = FindStorageArea(std::move(storage_id), frame, storage_area);
  if (!ok) {
    return;
  }
  blink::DummyExceptionStateForTesting exception_state;
  storage_area->SetItem(String::FromUTF8(key.data()), String::FromUTF8(value.data()), exception_state, frame);
}

void DOMStorageDispatcher::DidDispatchDOMStorageEvent(
  const String& key,
  const String& old_value,
  const String& new_value,
  blink::StorageArea::StorageType storage_type,
  const blink::SecurityOrigin* security_origin) {
  if (!GetClient())
    return;

  automation::StorageIdPtr id = automation::StorageId::New();
  id->security_origin = std::string(security_origin->ToRawString().Utf8().data());
  id->is_local_storage = storage_type == blink::StorageArea::kLocalStorage;

  if (key.IsNull())
    GetClient()->OnDomStorageItemsCleared(std::move(id));
  else if (new_value.IsNull())
    GetClient()->OnDomStorageItemRemoved(std::move(id), std::string(key.Utf8().data(), key.length()));
  else if (old_value.IsNull())
    GetClient()->OnDomStorageItemAdded(
      std::move(id), 
      std::string(key.Utf8().data(), key.length()), 
      std::string(new_value.Utf8().data(), new_value.length()));
  else
    GetClient()->OnDomStorageItemUpdated(
      std::move(id), 
      std::string(key.Utf8().data(), key.length()), 
      std::string(old_value.Utf8().data(), old_value.length()),
      std::string(new_value.Utf8().data(), new_value.length()));
}

void DOMStorageDispatcher::Restore() {
  if (!enabled_) {
    Enable();
  }
}

bool DOMStorageDispatcher::FindStorageArea(automation::StorageIdPtr storage_id, blink::LocalFrame*& frame, blink::StorageArea*& storage_area) {
  String security_origin = String::FromUTF8(storage_id->security_origin.data());
  bool is_local_storage = storage_id->is_local_storage;

  if (!page_->MainFrame()->IsLocalFrame()) {
    return false;
  }

  blink::InspectedFrames* inspected_frames = page_instance_->inspected_frames();
  frame = inspected_frames->FrameWithSecurityOrigin(security_origin);
  if (!frame) {
    //DLOG(ERROR) << "Frame not found for the given security origin";
    return false;
  }

  if (is_local_storage) {
    storage_area = blink::StorageNamespace::LocalStorageArea(
        frame->GetDocument()->GetSecurityOrigin());
    return true;
  }
  blink::StorageNamespace* session_storage = blink::StorageNamespaceController::From(page_)->SessionStorage();
  if (!session_storage) {
    //DLOG(ERROR) << "SessionStorage is not supported";
    return false;
  }
  storage_area = session_storage->GetStorageArea(
      frame->GetDocument()->GetSecurityOrigin());

  return true;
}

void DOMStorageDispatcher::OnWebFrameCreated(blink::WebLocalFrame* web_frame) {
  page_ = page_instance_->inspected_frames()->Root()->View()->GetPage();
  dom_storage_agent_ = new InspectorDOMStorageAgentImpl(this);
  dom_storage_agent_->Init(
    page_instance_->probe_sink(), 
    page_instance_->inspector_backend_dispatcher(),
    page_instance_->state());
  Enable();
}

}