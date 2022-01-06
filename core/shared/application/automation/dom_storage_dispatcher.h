// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_APPLICATION_DOM_STORAGE_DISPATCHER_H_
#define MUMBA_APPLICATION_DOM_STORAGE_DISPATCHER_H_

#include "core/shared/common/mojom/automation.mojom.h"

#include "mojo/public/cpp/bindings/binding.h"
#include "mojo/public/cpp/bindings/associated_binding.h"
#include "third_party/blink/renderer/modules/storage/storage_area.h"
#include "third_party/blink/renderer/platform/wtf/hash_map.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace blink {
class LocalFrame;
class Page;
class StorageArea;
class WebLocalFrame;
}

namespace service_manager {
class InterfaceProvider;
}

namespace IPC {
class SyncChannel;
}

namespace application {
class PageInstance;
class InspectorDOMStorageAgentImpl;

class DOMStorageDispatcher : public automation::DOMStorage {
public:
  static void Create(automation::DOMStorageRequest request, PageInstance* page_instance);

  DOMStorageDispatcher(automation::DOMStorageRequest request, PageInstance* page_instance);
  DOMStorageDispatcher(PageInstance* page_instance);
  ~DOMStorageDispatcher() override;

  void Init(IPC::SyncChannel* channel);
  void Bind(automation::DOMStorageAssociatedRequest request);

  void Register(int32_t application_id) override;
  void Clear(automation::StorageIdPtr storage_id) override;
  void Disable() override;
  void Enable() override;
  void GetDOMStorageItems(automation::StorageIdPtr storageId, GetDOMStorageItemsCallback callback) override;
  void RemoveDOMStorageItem(automation::StorageIdPtr storage_id, const std::string& key) override;
  void SetDOMStorageItem(automation::StorageIdPtr storageId, const std::string& key, const std::string& value) override;

  PageInstance* page_instance() const {
    return page_instance_;
  }

  automation::DOMStorageClient* GetClient() const;

  void OnWebFrameCreated(blink::WebLocalFrame* web_frame);
  
private:
  friend class InspectorDOMStorageAgentImpl;

  void DidDispatchDOMStorageEvent(const String& key,
                                  const String& old_value,
                                  const String& new_value,
                                  blink::StorageArea::StorageType,
                                  const blink::SecurityOrigin*);

  void Restore();
  bool FindStorageArea(automation::StorageIdPtr, blink::LocalFrame*&, blink::StorageArea*&);

  int32_t application_id_;
  PageInstance* page_instance_;
  mojo::AssociatedBinding<automation::DOMStorage> binding_;
  automation::DOMStorageClientAssociatedPtr dom_storage_client_ptr_;
  blink::Member<InspectorDOMStorageAgentImpl> dom_storage_agent_;
  blink::Member<blink::Page> page_;
  bool enabled_;

  DISALLOW_COPY_AND_ASSIGN(DOMStorageDispatcher); 
};

}

#endif