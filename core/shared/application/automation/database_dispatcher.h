// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_APPLICATION_DATABASE_DISPATCHER_H_
#define MUMBA_APPLICATION_DATABASE_DISPATCHER_H_

#include "core/shared/common/mojom/automation.mojom.h"

#include "mojo/public/cpp/bindings/binding.h"
#include "mojo/public/cpp/bindings/associated_binding.h"
#include "core/shared/application/automation/inspector_database_resource.h"
#include "third_party/blink/renderer/platform/wtf/text/base64.h"
#include "third_party/blink/renderer/platform/wtf/text/text_encoding.h"
#include "third_party/blink/renderer/platform/wtf/time.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "third_party/blink/renderer/platform/heap/heap.h"
#include "third_party/blink/renderer/platform/heap/heap_traits.h"

namespace blink {
class Page;  
class Database;
class LocalFrame;
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
class InspectorDatabaseAgentImpl;
class AutomationContext;

class DatabaseDispatcher : public automation::DatabaseInterface {
public:

  static void Create(automation::DatabaseInterfaceRequest request, AutomationContext* context, PageInstance* page_instance);

  DatabaseDispatcher(automation::DatabaseInterfaceRequest request, AutomationContext* context, PageInstance* page_instance);
  DatabaseDispatcher(AutomationContext* context, PageInstance* page_instance);
  ~DatabaseDispatcher() override;

  void Init(IPC::SyncChannel* channel);
  void Bind(automation::DatabaseInterfaceAssociatedRequest request);

  void Register(int32_t application_id) override;
  void Disable() override;
  void Enable() override;
  void ExecuteSQL(const std::string& database_id, const std::string& query, ExecuteSQLCallback callback) override;
  void GetDatabaseTableNames(const std::string& database_id, GetDatabaseTableNamesCallback callback) override;

  PageInstance* page_instance() const {
    return page_instance_;
  }

  automation::DatabaseClient* GetClient() const;

  void OnWebFrameCreated(blink::WebLocalFrame* web_frame);
  
private:
  friend class InspectorDatabaseAgentImpl;
  
  blink::Database* DatabaseForId(const String& database_id);
  void RegisterDatabaseOnCreation(blink::Database* database);
  void DidOpenDatabase(blink::Database* database,
                       const String& domain,
                       const String& name,
                       const String& version);
  void DidCommitLoadForLocalFrame(blink::LocalFrame* frame);
  InspectorDatabaseResource* FindByFileName(const String& file_name);
  void Restore();

  PageInstance* page_instance_;
  int32_t application_id_;
  blink::Member<blink::Page> page_;
  blink::Persistent<InspectorDatabaseAgentImpl> database_agent_impl_;
  typedef blink::HeapHashMap<String, blink::Member<InspectorDatabaseResource>> DatabaseResourcesHeapMap;
  DatabaseResourcesHeapMap resources_;
  mojo::AssociatedBinding<automation::DatabaseInterface> binding_;
  automation::DatabaseClientAssociatedPtr database_client_ptr_;
  bool enabled_;

  DISALLOW_COPY_AND_ASSIGN(DatabaseDispatcher); 
};

}

#endif
