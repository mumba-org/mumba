// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_APPLICATION_INDEXED_DB_DISPATCHER_H_
#define MUMBA_APPLICATION_INDEXED_DB_DISPATCHER_H_

#include "core/shared/common/mojom/automation.mojom.h"

#include "mojo/public/cpp/bindings/binding.h"
#include "mojo/public/cpp/bindings/associated_binding.h"

namespace service_manager {
class InterfaceProvider;
}

namespace blink {
class WebLocalFrame;  
}

namespace IPC {
class SyncChannel;
}

namespace application {
class PageInstance;

class IndexedDBDispatcher : public automation::IndexedDB {
public:
  static void Create(automation::IndexedDBRequest request, PageInstance* page_instance);

  IndexedDBDispatcher(automation::IndexedDBRequest request, PageInstance* page_instance);
  IndexedDBDispatcher(PageInstance* page_instance);
  ~IndexedDBDispatcher() override;

  void Init(IPC::SyncChannel* channel);
  void Bind(automation::IndexedDBAssociatedRequest request);

  void Register(int32_t application_id) override;
  void ClearObjectStore(const std::string& security_origin, const std::string& database_name, const std::string& object_store_name, ClearObjectStoreCallback callback) override;
  void DeleteDatabase(const std::string& security_origin, const std::string& database_name, DeleteDatabaseCallback callback) override;
  void DeleteObjectStoreEntries(const std::string& security_origin, const std::string& database_name, const std::string& object_store_name, automation::KeyRangePtr keyRange, DeleteObjectStoreEntriesCallback callback) override;
  void Disable() override;
  void Enable() override;
  void RequestData(const std::string& security_origin, const std::string& database_name, const std::string& object_store_name, const std::string& index_name, int32_t skip_count, int32_t page_size, automation::KeyRangePtr key_range, RequestDataCallback callback) override;
  void RequestDatabase(const std::string& security_origin, const std::string& database_name, RequestDatabaseCallback callback) override;
  void RequestDatabaseNames(const std::string& security_origin, RequestDatabaseNamesCallback callback) override;

  PageInstance* page_instance() const {
    return page_instance_;
  }

  void OnWebFrameCreated(blink::WebLocalFrame* web_frame);
  
private:
  int32_t application_id_;
  PageInstance* page_instance_;
  mojo::AssociatedBinding<automation::IndexedDB> binding_;

  DISALLOW_COPY_AND_ASSIGN(IndexedDBDispatcher); 
};

}

#endif