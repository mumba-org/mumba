// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/*
 * Copyright (C) 2012 Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "core/shared/application/automation/indexed_db_dispatcher.h"

#include "core/shared/application/automation/page_instance.h"
#include "services/service_manager/public/cpp/interface_provider.h"
#include "third_party/blink/public/platform/modules/indexeddb/web_idb_cursor.h"
#include "third_party/blink/public/platform/modules/indexeddb/web_idb_types.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/bindings/core/v8/exception_state.h"
#include "third_party/blink/renderer/bindings/core/v8/script_controller.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/dom_string_list.h"
#include "third_party/blink/renderer/core/dom/events/event_listener.h"
#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/inspector/inspected_frames.h"
#include "third_party/blink/renderer/core/inspector/v8_inspector_string.h"
#include "third_party/blink/renderer/modules/indexed_db_names.h"
#include "third_party/blink/renderer/modules/indexeddb/global_indexed_db.h"
#include "third_party/blink/renderer/modules/indexeddb/idb_cursor.h"
#include "third_party/blink/renderer/modules/indexeddb/idb_cursor_with_value.h"
#include "third_party/blink/renderer/modules/indexeddb/idb_database.h"
#include "third_party/blink/renderer/modules/indexeddb/idb_factory.h"
#include "third_party/blink/renderer/modules/indexeddb/idb_index.h"
#include "third_party/blink/renderer/modules/indexeddb/idb_key.h"
#include "third_party/blink/renderer/modules/indexeddb/idb_key_path.h"
#include "third_party/blink/renderer/modules/indexeddb/idb_key_range.h"
#include "third_party/blink/renderer/modules/indexeddb/idb_metadata.h"
#include "third_party/blink/renderer/modules/indexeddb/idb_object_store.h"
#include "third_party/blink/renderer/modules/indexeddb/idb_open_db_request.h"
#include "third_party/blink/renderer/modules/indexeddb/idb_request.h"
#include "third_party/blink/renderer/modules/indexeddb/idb_transaction.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/bindings/v8_per_isolate_data.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"
#include "ipc/ipc_sync_channel.h"

namespace application {

static blink::IDBTransaction* TransactionForDatabase(
    blink::ScriptState* script_state,
    blink::IDBDatabase* idb_database,
    const String& object_store_name,
    const String& mode = blink::IndexedDBNames::readonly) {
  blink::DummyExceptionStateForTesting exception_state;
  blink::StringOrStringSequence scope;
  scope.SetString(object_store_name);
  blink::IDBTransaction* idb_transaction =
      idb_database->transaction(script_state, scope, mode, exception_state);
  if (exception_state.HadException())
    return nullptr;
  return idb_transaction;
}

static blink::IDBObjectStore* ObjectStoreForTransaction(
    blink::IDBTransaction* idb_transaction,
    const String& object_store_name) {
  blink::DummyExceptionStateForTesting exception_state;
  blink::IDBObjectStore* idb_object_store =
      idb_transaction->objectStore(object_store_name, exception_state);
  if (exception_state.HadException())
    return nullptr;
  return idb_object_store;
}

static blink::IDBIndex* IndexForObjectStore(blink::IDBObjectStore* idb_object_store,
                                            const String& index_name) {
  blink::DummyExceptionStateForTesting exception_state;
  blink::IDBIndex* idb_index = idb_object_store->index(index_name, exception_state);
  if (exception_state.HadException())
    return nullptr;
  return idb_index;
}

static bool AssertIDBFactory(blink::Document* document, blink::IDBFactory*& result) {
  blink::LocalDOMWindow* dom_window = document->domWindow();
  if (!dom_window) {
    //DLOG(ERROR) << "No IndexedDB factory for given frame found";
    return false;
  }
  blink::IDBFactory* idb_factory = blink::GlobalIndexedDB::indexedDB(*dom_window);

  if (!idb_factory) {
    //DLOG(ERROR) << "No IndexedDB factory for given frame found";
    return false;
  }
  result = idb_factory;
  return true;
}

template <typename RequestCallback>
class OpenDatabaseCallback;
template <typename RequestCallback>
class UpgradeDatabaseCallback;

template <typename RequestCallback>
class ExecutableWithDatabase
    : public RefCounted<ExecutableWithDatabase<RequestCallback>> {
 public:
  virtual ~ExecutableWithDatabase() = default;
  virtual void Execute(blink::IDBDatabase*, blink::ScriptState*) = 0;
  virtual RequestCallback* GetRequestCallback() = 0;
  void Start(blink::LocalFrame* frame, const String& database_name) {
    blink::Document* document = frame ? frame->GetDocument() : nullptr;
    if (!document) {
      //DLOG(ERROR) << "No document error.";
      // FIXME
      //SendFailure();//Response::Error(kNoDocumentError));
      return;
    }
    blink::IDBFactory* idb_factory = nullptr;
    bool ok = AssertIDBFactory(document, idb_factory);
    if (!ok) {
      SendFailure();//response);
      return;
    }

    blink::ScriptState* script_state = blink::ToScriptStateForMainWorld(frame);
    if (!script_state) {
      //DLOG(ERROR) << "Internal error.";
      // FIXME
      //SendFailure();//Response::InternalError());
      return;
    }

    blink::ScriptState::Scope scope(script_state);
    DoStart(idb_factory, 
            script_state, 
            document->GetSecurityOrigin(),
            database_name);
  }

 private:
  void DoStart(blink::IDBFactory* idb_factory,
               blink::ScriptState* script_state,
               const blink::SecurityOrigin*,
               const String& database_name) {
    OpenDatabaseCallback<RequestCallback>* open_callback =
        OpenDatabaseCallback<RequestCallback>::Create(this, script_state);
    UpgradeDatabaseCallback<RequestCallback>* upgrade_callback =
        UpgradeDatabaseCallback<RequestCallback>::Create(this);
    blink::DummyExceptionStateForTesting exception_state;
    blink::IDBOpenDBRequest* idb_open_db_request =
        idb_factory->open(script_state, database_name, exception_state);
    if (exception_state.HadException()) {
      //DLOG(ERROR) << "Could not open database.";
      // FIXME
      //SendFailure();//Response::Error("Could not open database."));
      return;
    }
    idb_open_db_request->addEventListener(blink::EventTypeNames::upgradeneeded,
                                          upgrade_callback, false);
    idb_open_db_request->addEventListener(blink::EventTypeNames::success,
                                          open_callback, false);
  }

  void SendFailure() {//Response response) {
    // FIXME
    //GetRequestCallback()->Run(false);
  }
};

template <typename RequestCallback>
class OpenDatabaseCallback final : public blink::EventListener {
 public:
  static OpenDatabaseCallback* Create(
      ExecutableWithDatabase<RequestCallback>* executable_with_database,
      scoped_refptr<blink::ScriptState> script_state) {
    return new OpenDatabaseCallback(executable_with_database, script_state);
  }

  ~OpenDatabaseCallback() override = default;

  bool operator==(const blink::EventListener& other) const override {
    return this == &other;
  }

  void handleEvent(blink::ExecutionContext* context, blink::Event* event) override {
    if (event->type() != blink::EventTypeNames::success) {
      // FIXME
      //DLOG(ERROR) << "Unexpected event type.";
          //Response::Error("Unexpected event type."));
      //executable_with_database_->GetRequestCallback()->Run(std::vector<automation::IndexedDBDataEntryPtr>(), false);
      return;
    }

    blink::IDBOpenDBRequest* idb_open_db_request =
        static_cast<blink::IDBOpenDBRequest*>(event->target());
    blink::IDBAny* request_result = idb_open_db_request->ResultAsAny();
    if (request_result->GetType() != blink::IDBAny::kIDBDatabaseType) {
      // FIXME
      //DLOG(ERROR) << "Unexpected result type.";
      //executable_with_database_->GetRequestCallback()->Run(std::vector<automation::IndexedDBDataEntryPtr>(), false);
          //Response::Error("Unexpected result type."));
      return;
    }

    blink::IDBDatabase* idb_database = request_result->IdbDatabase();
    executable_with_database_->Execute(idb_database, script_state_.get());
    blink::V8PerIsolateData::From(script_state_->GetIsolate())->RunEndOfScopeTasks();
    idb_database->close();
  }

 private:
  OpenDatabaseCallback(
      ExecutableWithDatabase<RequestCallback>* executable_with_database,
      scoped_refptr<blink::ScriptState> script_state)
      : blink::EventListener(blink::EventListener::kCPPEventListenerType),
        executable_with_database_(executable_with_database),
        script_state_(script_state) {}
  scoped_refptr<ExecutableWithDatabase<RequestCallback>>
      executable_with_database_;
  scoped_refptr<blink::ScriptState> script_state_;
};

template <typename RequestCallback>
class UpgradeDatabaseCallback final : public blink::EventListener {
 public:
  static UpgradeDatabaseCallback* Create(
      ExecutableWithDatabase<RequestCallback>* executable_with_database) {
    return new UpgradeDatabaseCallback(executable_with_database);
  }

  ~UpgradeDatabaseCallback() override = default;

  bool operator==(const blink::EventListener& other) const override {
    return this == &other;
  }

  void handleEvent(blink::ExecutionContext* context, blink::Event* event) override {
    if (event->type() != blink::EventTypeNames::upgradeneeded) {
      // FIXME
      //DLOG(ERROR) << "Unexpected event type.";
      //executable_with_database_->GetRequestCallback()->sendFailure();
          //Response::Error("Unexpected event type."));
      return;
    }

    // If an "upgradeneeded" event comes through then the database that
    // had previously been enumerated was deleted. We don't want to
    // implicitly re-create it here, so abort the transaction.
    blink::IDBOpenDBRequest* idb_open_db_request =
        static_cast<blink::IDBOpenDBRequest*>(event->target());
    blink::NonThrowableExceptionState exception_state;
    idb_open_db_request->transaction()->abort(exception_state);
    // FIXME
    //DLOG(ERROR) << "Aborted upgrade.";
    //executable_with_database_->GetRequestCallback()->sendFailure();//
        //Response::Error("Aborted upgrade."));
  }

 private:
  UpgradeDatabaseCallback(
      ExecutableWithDatabase<RequestCallback>* executable_with_database)
      : EventListener(blink::EventListener::kCPPEventListenerType),
        executable_with_database_(executable_with_database) {}
  scoped_refptr<ExecutableWithDatabase<RequestCallback>>
      executable_with_database_;
};

class GetDatabaseNamesCallback final : public blink::EventListener {
  WTF_MAKE_NONCOPYABLE(GetDatabaseNamesCallback);

 public:
  static GetDatabaseNamesCallback* Create(
      IndexedDBDispatcher::RequestDatabaseNamesCallback callback,
      const String& security_origin) {
    return new GetDatabaseNamesCallback(std::move(callback),
                                        security_origin);
  }

  ~GetDatabaseNamesCallback() override = default;

  bool operator==(const blink::EventListener& other) const override {
    return this == &other;
  }

  void handleEvent(blink::ExecutionContext*, blink::Event* event) override {
    if (event->type() != blink::EventTypeNames::success) {
      //request_callback_->sendFailure(Response::Error("Unexpected event type."));
      //DLOG(ERROR) << "Unexpected event type.";
      return;
    }

    blink::IDBRequest* idb_request = static_cast<blink::IDBRequest*>(event->target());
    blink::IDBAny* request_result = idb_request->ResultAsAny();
    if (request_result->GetType() != blink::IDBAny::kDOMStringListType) {
      //request_callback_->sendFailure(
      //    Response::Error("Unexpected result type."));
      //DLOG(ERROR) << "Unexpected result type.";
      return;
    }

    blink::DOMStringList* database_names_list = request_result->DomStringList();
    std::vector<std::string> database_names;
    for (size_t i = 0; i < database_names_list->length(); ++i) {
      database_names.push_back(std::string(database_names_list->item(i).Utf8().data()));
    }
    std::move(callback_).Run(std::move(database_names));
  }

  void Trace(blink::Visitor* visitor) override {
    blink::EventListener::Trace(visitor);
  }

 private:
  GetDatabaseNamesCallback(
      IndexedDBDispatcher::RequestDatabaseNamesCallback callback,
      const String& security_origin)
      : blink::EventListener(blink::EventListener::kCPPEventListenerType),
        callback_(std::move(callback)),
        security_origin_(security_origin) {}
  IndexedDBDispatcher::RequestDatabaseNamesCallback callback_;
  String security_origin_;
};

class DeleteCallback final : public blink::EventListener {
  WTF_MAKE_NONCOPYABLE(DeleteCallback);

 public:
  static DeleteCallback* Create(
      IndexedDBDispatcher::DeleteDatabaseCallback callback,
      const String& security_origin) {
    return new DeleteCallback(std::move(callback), security_origin);
  }

  ~DeleteCallback() override = default;

  bool operator==(const blink::EventListener& other) const override {
    return this == &other;
  }

  void handleEvent(blink::ExecutionContext*, blink::Event* event) override {
    if (event->type() != blink::EventTypeNames::success) {
      //request_callback_->sendFailure(
      //    Response::Error("Failed to delete database."));
      //DLOG(INFO) << "Failed to delete database.";
      std::move(callback_).Run(false);
      return;
    }
    std::move(callback_).Run(true);
  }

  void Trace(blink::Visitor* visitor) override {
    blink::EventListener::Trace(visitor);
  }

 private:
  DeleteCallback(IndexedDBDispatcher::DeleteDatabaseCallback callback,
                 const String& security_origin)
      : EventListener(blink::EventListener::kCPPEventListenerType),
        callback_(std::move(callback)),
        security_origin_(security_origin) {}
  IndexedDBDispatcher::DeleteDatabaseCallback callback_;
  String security_origin_;
};

class ClearObjectStoreListener final : public blink::EventListener {
  WTF_MAKE_NONCOPYABLE(ClearObjectStoreListener);

 public:
  static ClearObjectStoreListener* Create(
      IndexedDBDispatcher::ClearObjectStoreCallback request_callback) {
    return new ClearObjectStoreListener(std::move(request_callback));
  }

  ~ClearObjectStoreListener() override = default;

  bool operator==(const blink::EventListener& other) const override {
    return this == &other;
  }

  void handleEvent(blink::ExecutionContext*, blink::Event* event) override {
    if (event->type() != blink::EventTypeNames::complete) {
      //request_callback_->sendFailure(Response::Error("Unexpected event type."));
      std::move(request_callback_).Run(false);
      return;
    }

    //request_callback_->sendSuccess();
    std::move(request_callback_).Run(true);
  }

  void Trace(blink::Visitor* visitor) override {
    blink::EventListener::Trace(visitor);
  }

 private:
  ClearObjectStoreListener(
    IndexedDBDispatcher::ClearObjectStoreCallback request_callback)
      : blink::EventListener(blink::EventListener::kCPPEventListenerType),
        request_callback_(std::move(request_callback)) {}

  IndexedDBDispatcher::ClearObjectStoreCallback request_callback_;
};

class ClearObjectStoreImpl final
    : public ExecutableWithDatabase<IndexedDBDispatcher::ClearObjectStoreCallback> {
 public:
  static scoped_refptr<ClearObjectStoreImpl> Create(
      const String& object_store_name,
      IndexedDBDispatcher::ClearObjectStoreCallback request_callback) {
    return base::AdoptRef(
        new ClearObjectStoreImpl(object_store_name, std::move(request_callback)));
  }

  ClearObjectStoreImpl(const String& object_store_name,
                   IndexedDBDispatcher::ClearObjectStoreCallback request_callback)
      : object_store_name_(object_store_name),
        request_callback_(std::move(request_callback)) {}

  void Execute(blink::IDBDatabase* idb_database, blink::ScriptState* script_state) override {
    blink::IDBTransaction* idb_transaction =
        TransactionForDatabase(script_state, idb_database, object_store_name_,
                                      blink::IndexedDBNames::readwrite);
    if (!idb_transaction) {
      // request_callback_->sendFailure(
      //     Response::Error("Could not get transaction"));
      //DLOG(ERROR) << "Could not get transaction";
      std::move(request_callback_).Run(false);
      return;
    }
    blink::IDBObjectStore* idb_object_store =
        ObjectStoreForTransaction(idb_transaction, object_store_name_);
    if (!idb_object_store) {
      // request_callback_->sendFailure(
      //     Response::Error("Could not get object store"));
      //DLOG(ERROR) << "Could not get object store";
      std::move(request_callback_).Run(false);
      return;
    }

    blink::DummyExceptionStateForTesting exception_state;
    idb_object_store->clear(script_state, exception_state);
    DCHECK(!exception_state.HadException());
    if (exception_state.HadException()) {
      //ExceptionCode ec = exception_state.Code();
      // request_callback_->sendFailure(Response::Error(
      //     String::Format("Could not clear object store '%s': %d",
      //                    object_store_name_.Utf8().data(), ec)));
      //DLOG(ERROR) << "Could not clear object store";
      std::move(request_callback_).Run(false);
      return;
    }
    idb_transaction->addEventListener(
        blink::EventTypeNames::complete,
        ClearObjectStoreListener::Create(std::move(request_callback_)), false);
  }

  IndexedDBDispatcher::ClearObjectStoreCallback* GetRequestCallback() override {
    return &request_callback_;
  }

 private:
  const String object_store_name_;
  IndexedDBDispatcher::ClearObjectStoreCallback request_callback_;
};

class DeleteObjectStoreEntriesListener final : public blink::EventListener {
  WTF_MAKE_NONCOPYABLE(DeleteObjectStoreEntriesListener);

 public:
  static DeleteObjectStoreEntriesListener* Create(
      IndexedDBDispatcher::DeleteObjectStoreEntriesCallback request_callback) {
    return new DeleteObjectStoreEntriesListener(std::move(request_callback));
  }

  ~DeleteObjectStoreEntriesListener() override = default;

  bool operator==(const blink::EventListener& other) const override {
    return this == &other;
  }

  void handleEvent(blink::ExecutionContext*, blink::Event* event) override {
    if (event->type() != blink::EventTypeNames::success) {
      //request_callback_->sendFailure(
      //    Response::Error("Failed to delete specified entries"));
      //DLOG(ERROR) << "Failed to delete specified entries";
      std::move(request_callback_).Run(false);
      return;
    }

    std::move(request_callback_).Run(true);
  }

  void Trace(blink::Visitor* visitor) override {
    EventListener::Trace(visitor);
  }

 private:
  DeleteObjectStoreEntriesListener(
      IndexedDBDispatcher::DeleteObjectStoreEntriesCallback request_callback)
      : EventListener(blink::EventListener::kCPPEventListenerType),
        request_callback_(std::move(request_callback)) {}

  IndexedDBDispatcher::DeleteObjectStoreEntriesCallback request_callback_;
};

class DeleteObjectStoreEntriesImpl final
    : public ExecutableWithDatabase<IndexedDBDispatcher::DeleteObjectStoreEntriesCallback> {
 public:
  static scoped_refptr<DeleteObjectStoreEntriesImpl> Create(
      const String& object_store_name,
      blink::IDBKeyRange* idb_key_range,
      IndexedDBDispatcher::DeleteObjectStoreEntriesCallback request_callback) {
    return base::AdoptRef(new DeleteObjectStoreEntriesImpl(
        object_store_name, idb_key_range, std::move(request_callback)));
  }

  DeleteObjectStoreEntriesImpl(
      const String& object_store_name,
      blink::IDBKeyRange* idb_key_range,
      IndexedDBDispatcher::DeleteObjectStoreEntriesCallback request_callback)
      : object_store_name_(object_store_name),
        idb_key_range_(idb_key_range),
        request_callback_(std::move(request_callback)) {}

  void Execute(blink::IDBDatabase* idb_database, blink::ScriptState* script_state) override {
    blink::IDBTransaction* idb_transaction =
        TransactionForDatabase(script_state, idb_database, object_store_name_,
                               blink::IndexedDBNames::readwrite);
    if (!idb_transaction) {
      // request_callback_->sendFailure(
      //     Response::Error("Could not get transaction"));
      std::move(request_callback_).Run(false);
      //DLOG(ERROR) << "Could not get transaction";
      return;
    }
    blink::IDBObjectStore* idb_object_store = ObjectStoreForTransaction(idb_transaction, object_store_name_);
    if (!idb_object_store) {
      //request_callback_->sendFailure(
      //    Response::Error("Could not get object store"));
      //DLOG(ERROR) << "Could not get object store";
      std::move(request_callback_).Run(false);
      return;
    }

    blink::IDBRequest* idb_request =
        idb_object_store->deleteFunction(script_state, idb_key_range_.Get());
    idb_request->addEventListener(
        blink::EventTypeNames::success,
        DeleteObjectStoreEntriesListener::Create(std::move(request_callback_)),
        false);
  }

  IndexedDBDispatcher::DeleteObjectStoreEntriesCallback* GetRequestCallback() override {
    return &request_callback_;
  }

 private:
  const String object_store_name_;
  blink::Persistent<blink::IDBKeyRange> idb_key_range_;
  IndexedDBDispatcher::DeleteObjectStoreEntriesCallback request_callback_;
};

static automation::KeyPathPtr KeyPathFromIDBKeyPath(
    const blink::IDBKeyPath& idb_key_path) {
  automation::KeyPathPtr key_path = automation::KeyPath::New();
  switch (idb_key_path.GetType()) {
    case blink::IDBKeyPath::kNullType:
      key_path->type = automation::KeyPathType::kKEY_PATH_NULL;
      break;
    case blink::IDBKeyPath::kStringType:
      key_path->type = automation::KeyPathType::kKEY_PATH_STRING;
      key_path->str = std::string(idb_key_path.GetString().Utf8().data(), idb_key_path.GetString().Utf8().length());
      break;
    case blink::IDBKeyPath::kArrayType: {
      key_path->type = automation::KeyPathType::kKEY_PATH_ARRAY;
      std::vector<std::string> array;
      const Vector<String>& string_array = idb_key_path.Array();
      for (size_t i = 0; i < string_array.size(); ++i) {
        array.push_back(std::string(string_array[i].Utf8().data(), string_array[i].Utf8().length()));
      }
      key_path->arr = std::move(array);
      break;
    }
    default:
      NOTREACHED();
  }

  return key_path;
}

class DatabaseLoader final
    : public ExecutableWithDatabase<IndexedDBDispatcher::RequestDatabaseCallback> {
 public:
  static scoped_refptr<DatabaseLoader> Create(IndexedDBDispatcher::RequestDatabaseCallback request_callback) {
    return base::AdoptRef(new DatabaseLoader(std::move(request_callback)));
  }

  ~DatabaseLoader() override = default;

  void Execute(blink::IDBDatabase* idb_database, blink::ScriptState*) override {
    const blink::IDBDatabaseMetadata database_metadata = idb_database->Metadata();
    std::vector<automation::ObjectStorePtr> object_stores;

    for (const auto& store_map_entry : database_metadata.object_stores) {
      const blink::IDBObjectStoreMetadata& object_store_metadata =
          *store_map_entry.value;

      std::vector<automation::ObjectStoreIndexPtr> indexes;

      for (const auto& metadata_map_entry : object_store_metadata.indexes) {
        const blink::IDBIndexMetadata& index_metadata = *metadata_map_entry.value;

        automation::ObjectStoreIndexPtr object_store_index = automation::ObjectStoreIndex::New();
        object_store_index->name = std::string(index_metadata.name.Utf8().data(), index_metadata.name.Utf8().length());
        object_store_index->key_path = KeyPathFromIDBKeyPath(index_metadata.key_path);
        object_store_index->unique = index_metadata.unique;
        object_store_index->multi_entry = index_metadata.multi_entry;
        indexes.push_back(std::move(object_store_index));
      }

      automation::ObjectStorePtr object_store = automation::ObjectStore::New();
      object_store->name = std::string(object_store_metadata.name.Utf8().data(), object_store_metadata.name.Utf8().length());
      object_store->key_path = KeyPathFromIDBKeyPath(object_store_metadata.key_path);
      object_store->auto_increment = object_store_metadata.auto_increment;
      object_store->indexes = std::move(indexes);
        
      object_stores.push_back(std::move(object_store));
    }
    automation::DatabaseWithObjectStoresPtr result = automation::DatabaseWithObjectStores::New();
    result->name = std::string(idb_database->name().Utf8().data(), idb_database->name().Utf8().length());
    result->version = idb_database->version();
    result->object_stores = std::move(object_stores);

    std::move(request_callback_).Run(std::move(result));
  }

  IndexedDBDispatcher::RequestDatabaseCallback* GetRequestCallback() override {
    return &request_callback_;
  }

 private:
  DatabaseLoader(IndexedDBDispatcher::RequestDatabaseCallback request_callback)
      : request_callback_(std::move(request_callback)) {}
  IndexedDBDispatcher::RequestDatabaseCallback request_callback_;
};

static std::unique_ptr<blink::IDBKey> IdbKeyFromInspectorObject(automation::Key* key) {
  std::unique_ptr<blink::IDBKey> idb_key;

  if (!key)
    return nullptr;

  automation::KeyType type = key->type;

  if (type == automation::KeyType::kKEY_TYPE_NUMBER) {
    idb_key = blink::IDBKey::CreateNumber(key->number);
  } else if (type == automation::KeyType::kKEY_TYPE_STRING) {
    idb_key = blink::IDBKey::CreateString(key->str.has_value() ? String::FromUTF8(key->str.value().data()) : String());
  } else if (type == automation::KeyType::kKEY_TYPE_DATE) {
    idb_key = blink::IDBKey::CreateDate(key->date);
  } else if (type == automation::KeyType::kKEY_TYPE_ARRAY) {
    blink::IDBKey::KeyArray key_array;
    std::vector<automation::KeyPtr> array = std::move(key->arr.value());
    for (auto it = array.begin(); it != array.end(); ++it) {
      automation::Key* value = it->get();
      key_array.push_back(IdbKeyFromInspectorObject(value));
    }
    idb_key = blink::IDBKey::CreateArray(std::move(key_array));
  } else {
    return nullptr;
  }

  return idb_key;
}

static blink::IDBKeyRange* IdbKeyRangeFromKeyRange(automation::KeyRange* key_range) {
  std::unique_ptr<blink::IDBKey> idb_lower = IdbKeyFromInspectorObject(key_range->lower.get());
  if (key_range->lower.get() && !idb_lower)
    return nullptr;

  std::unique_ptr<blink::IDBKey> idb_upper =
      IdbKeyFromInspectorObject(key_range->upper.get());
  if (key_range->upper.get() && !idb_upper)
    return nullptr;

  blink::IDBKeyRange::LowerBoundType lower_bound_type =
      key_range->lower_open ? blink::IDBKeyRange::kLowerBoundOpen
                            : blink::IDBKeyRange::kLowerBoundClosed;
  blink::IDBKeyRange::UpperBoundType upper_bound_type =
      key_range->upper_open ? blink::IDBKeyRange::kUpperBoundOpen
                            : blink::IDBKeyRange::kUpperBoundClosed;
  return blink::IDBKeyRange::Create(
    std::move(idb_lower), 
    std::move(idb_upper),
    lower_bound_type, 
    upper_bound_type);
}

class DataLoader;

class OpenCursorCallback final : public blink::EventListener {
 public:
  static OpenCursorCallback* Create(
      blink::ScriptState* script_state,
      IndexedDBDispatcher::RequestDataCallback request_callback,
      int skip_count,
      unsigned page_size) {
    return new OpenCursorCallback(script_state,
                                  std::move(request_callback), 
                                  skip_count,
                                  page_size);
  }

  ~OpenCursorCallback() override = default;

  bool operator==(const blink::EventListener& other) const override {
    return this == &other;
  }

  void handleEvent(blink::ExecutionContext*, blink::Event* event) override {
    if (event->type() != blink::EventTypeNames::success) {
      //DLOG(ERROR) << "Unexpected event type.";
      //request_callback_->sendFailure();//Response::Error("Unexpected event type."));
      std::move(request_callback_).Run(std::move(result_), false);
      return;
    }

    blink::IDBRequest* idb_request = static_cast<blink::IDBRequest*>(event->target());
    blink::IDBAny* request_result = idb_request->ResultAsAny();
    if (request_result->GetType() == blink::IDBAny::kIDBValueType) {
      end(false);
      return;
    }
    if (request_result->GetType() != blink::IDBAny::kIDBCursorWithValueType) {
      //DLOG(ERROR) << "Unexpected result type.";
      //request_callback_->sendFailure();
          //Response::Error("Unexpected result type."));
      std::move(request_callback_).Run(std::move(result_), false);
      return;
    }

    blink::IDBCursorWithValue* idb_cursor = request_result->IdbCursorWithValue();

    if (skip_count_) {
      blink::DummyExceptionStateForTesting exception_state;
      idb_cursor->advance(skip_count_, exception_state);
      if (exception_state.HadException()) {
        //DLOG(ERROR) << "Could not advance cursor.";
        std::move(request_callback_).Run(std::move(result_), false);
            //Response::Error("Could not advance cursor."));
      }
      skip_count_ = 0;
      return;
    }

    if (result_.size() == page_size_) {
      end(true);
      return;
    }

    // Continue cursor before making injected script calls, otherwise
    // transaction might be finished.
    blink::DummyExceptionStateForTesting exception_state;
    idb_cursor->Continue(nullptr,  
                         nullptr, 
                         blink::IDBRequest::AsyncTraceState(),
                         exception_state);
    if (exception_state.HadException()) {
      std::move(request_callback_).Run(std::move(result_), false);
      //request_callback_->sendFailure(
      //    Response::Error("Could not continue cursor."));
      return;
    }

    blink::Document* document = blink::ToDocument(blink::ExecutionContext::From(script_state_.get()));
    if (!document)
      return;
    blink::ScriptState* script_state = script_state_.get();
    blink::ScriptState::Scope scope(script_state);
    v8::Local<v8::Context> context = script_state->GetContext();
    //v8_inspector::StringView object_group = blink::ToV8InspectorStringView(kIndexedDBObjectGroup);
    automation::IndexedDBDataEntryPtr data_entry = automation::IndexedDBDataEntry::New();
    blink::SerializedScriptValue::SerializeOptions options;
    v8::Local<v8::Value> key_value = idb_cursor->key(script_state).V8Value();
    v8::Local<v8::Value> pkey_value = idb_cursor->primaryKey(script_state).V8Value();
    v8::Local<v8::Value> value_value = idb_cursor->value(script_state).V8Value();
    scoped_refptr<blink::SerializedScriptValue> serialized_key = blink::SerializedScriptValue::Serialize(context->GetIsolate(), key_value, options, exception_state);
    scoped_refptr<blink::SerializedScriptValue> serialized_pkey = blink::SerializedScriptValue::Serialize(context->GetIsolate(), pkey_value, options, exception_state);
    scoped_refptr<blink::SerializedScriptValue> serialized_value = blink::SerializedScriptValue::Serialize(context->GetIsolate(), value_value, options, exception_state);
    
    String str_key = serialized_key->ToWireString();
    String str_pkey = serialized_pkey->ToWireString();
    String str_value = serialized_value->ToWireString();

    data_entry->key = std::string(reinterpret_cast<const char *>(str_key.Characters8()), str_key.length());//v8_session_->wrapObject(
    data_entry->primary_key = std::string(reinterpret_cast<const char *>(str_pkey.Characters8()), str_pkey.length());
    data_entry->value = std::string(reinterpret_cast<const char *>(str_value.Characters8()), str_value.length());
    //   context, idb_cursor->key(script_state).V8Value(), object_group,
    //   true /* generatePreview */);
    // data_entry->primary_key = v8_session_->wrapObject(
    //   context, idb_cursor->primaryKey(script_state).V8Value(),
    //   object_group, true /* generatePreview */);
    // data_entry->value = v8_session_->wrapObject(
    //   context, idb_cursor->value(script_state).V8Value(),
    //   object_group, true /* generatePreview */);
    result_.push_back(std::move(data_entry));
  }

  void end(bool has_more) {
    std::move(request_callback_).Run(std::move(result_), has_more);
  }

  void Trace(blink::Visitor* visitor) override {
    blink::EventListener::Trace(visitor);
  }

 private:
  OpenCursorCallback(blink::ScriptState* script_state,
                     IndexedDBDispatcher::RequestDataCallback request_callback,
                     int skip_count,
                     unsigned page_size)
      : blink::EventListener(blink::EventListener::kCPPEventListenerType),
        script_state_(script_state),
        request_callback_(std::move(request_callback)),
        skip_count_(skip_count),
        page_size_(page_size) {
    
  }
  scoped_refptr<blink::ScriptState> script_state_;
  IndexedDBDispatcher::RequestDataCallback request_callback_;
  int skip_count_;
  unsigned page_size_;
  std::vector<automation::IndexedDBDataEntryPtr> result_;
};

class DataLoader final : public ExecutableWithDatabase<IndexedDBDispatcher::RequestDataCallback> {
 public:
  static scoped_refptr<DataLoader> Create(
      IndexedDBDispatcher::RequestDataCallback request_callback,
      const String& object_store_name,
      const String& index_name,
      blink::IDBKeyRange* idb_key_range,
      int skip_count,
      unsigned page_size) {
    return base::AdoptRef(new DataLoader(
        std::move(request_callback), object_store_name, index_name,
        idb_key_range, skip_count, page_size));
  }

  ~DataLoader() override = default;

  void Execute(blink::IDBDatabase* idb_database, blink::ScriptState* script_state) override {
    blink::IDBTransaction* idb_transaction =
        TransactionForDatabase(script_state, idb_database, object_store_name_);
    if (!idb_transaction) {
      std::move(request_callback_).Run(std::vector<automation::IndexedDBDataEntryPtr>(), false);
      //request_callback_->sendFailure();
          //Response::Error("Could not get transaction"));
      return;
    }
    blink::IDBObjectStore* idb_object_store =
        ObjectStoreForTransaction(idb_transaction, object_store_name_);
    if (!idb_object_store) {
      std::move(request_callback_).Run(std::vector<automation::IndexedDBDataEntryPtr>(), false);
      //request_callback_->sendFailure();
          //Response::Error("Could not get object store"));
      return;
    }

    blink::IDBRequest* idb_request;
    if (!index_name_.IsEmpty()) {
      blink::IDBIndex* idb_index = IndexForObjectStore(idb_object_store, index_name_);
      if (!idb_index) {
        std::move(request_callback_).Run(std::vector<automation::IndexedDBDataEntryPtr>(), false);//->sendFailure();//Response::Error("Could not get index"));
        return;
      }

      idb_request = idb_index->openCursor(script_state, idb_key_range_.Get(),
                                          blink::kWebIDBCursorDirectionNext);
    } else {
      idb_request = idb_object_store->openCursor(
          script_state, idb_key_range_.Get(), blink::kWebIDBCursorDirectionNext);
    }
    OpenCursorCallback* open_cursor_callback = OpenCursorCallback::Create(
        script_state, std::move(request_callback_), skip_count_,
        page_size_);
    idb_request->addEventListener(blink::EventTypeNames::success, open_cursor_callback,
                                  false);
  }

  IndexedDBDispatcher::RequestDataCallback* GetRequestCallback() override {
    return &request_callback_;
  }
  DataLoader(IndexedDBDispatcher::RequestDataCallback request_callback,
             const String& object_store_name,
             const String& index_name,
             blink::IDBKeyRange* idb_key_range,
             int skip_count,
             unsigned page_size)
      : request_callback_(std::move(request_callback)),
        object_store_name_(object_store_name),
        index_name_(index_name),
        idb_key_range_(idb_key_range),
        skip_count_(skip_count),
        page_size_(page_size) {}

  IndexedDBDispatcher::RequestDataCallback request_callback_;
  String object_store_name_;
  String index_name_;
  blink::Persistent<blink::IDBKeyRange> idb_key_range_;
  int skip_count_;
  unsigned page_size_;
};

// static 
void IndexedDBDispatcher::Create(automation::IndexedDBRequest request, PageInstance* page_instance) {
  new IndexedDBDispatcher(std::move(request), page_instance);
}

IndexedDBDispatcher::IndexedDBDispatcher(automation::IndexedDBRequest request, PageInstance* page_instance): 
  application_id_(-1),
  page_instance_(page_instance),
  binding_(this) {

}

IndexedDBDispatcher::IndexedDBDispatcher(PageInstance* page_instance): 
  application_id_(-1),
  page_instance_(page_instance),
  binding_(this) {

}

IndexedDBDispatcher::~IndexedDBDispatcher() {

}

void IndexedDBDispatcher::Init(IPC::SyncChannel* channel) {

}

void IndexedDBDispatcher::Bind(automation::IndexedDBAssociatedRequest request) {
  //DLOG(INFO) << "IndexedDispatcher::Bind (application)";
  binding_.Bind(std::move(request));
}

void IndexedDBDispatcher::Register(int32_t application_id) {
  application_id_ = application_id;
}

void IndexedDBDispatcher::Disable() {

}

void IndexedDBDispatcher::Enable() {
  //DLOG(INFO) << "IndexedDBDispatcher::Enable (application process)";
}

void IndexedDBDispatcher::ClearObjectStore(const std::string& security_origin, const std::string& database_name, const std::string& object_store_name, ClearObjectStoreCallback callback) {
  scoped_refptr<ClearObjectStoreImpl> clear_object_store = ClearObjectStoreImpl::Create(
    String::FromUTF8(object_store_name.data(), object_store_name.size()), 
    std::move(callback));
  clear_object_store->Start(
      page_instance_->inspected_frames()->FrameWithSecurityOrigin(
        String::FromUTF8(security_origin.data())),
        String::FromUTF8(database_name.data()));
}

void IndexedDBDispatcher::DeleteDatabase(const std::string& security_origin, const std::string& database_name, DeleteDatabaseCallback callback) {
  blink::LocalFrame* frame = page_instance_->inspected_frames()->FrameWithSecurityOrigin(String::FromUTF8(security_origin.data()));
  blink::Document* document = frame ? frame->GetDocument() : nullptr;
  if (!document) {
    //request_callback->sendFailure(Response::Error(kNoDocumentError));
    return;
  }
  blink::IDBFactory* idb_factory = nullptr;
  bool ok = AssertIDBFactory(document, idb_factory);
  if (!ok) {
    //DLOG(ERROR) << "no idb factory";
    //request_callback->sendFailure(response);
    std::move(callback).Run(false);
    return;
  }

  blink::ScriptState* script_state = ToScriptStateForMainWorld(frame);
  if (!script_state) {
    //DLOG(ERROR) << "no script state";
    //request_callback->sendFailure(Response::InternalError());
    std::move(callback).Run(false);
    return;
  }
  blink::ScriptState::Scope scope(script_state);
  blink::DummyExceptionStateForTesting exception_state;
  blink::IDBRequest* idb_request = idb_factory->CloseConnectionsAndDeleteDatabase(
      script_state, 
      String::FromUTF8(database_name.data()), 
      exception_state);
  if (exception_state.HadException()) {
    //request_callback->sendFailure(
    //    Response::Error("Could not delete database."));
    std::move(callback).Run(false);
    //DLOG(ERROR) << "Could not delete database.";
    return;
  }
  String security_origin_str = document->GetSecurityOrigin()->ToRawString();
  idb_request->addEventListener(
      blink::EventTypeNames::success,
      DeleteCallback::Create(std::move(callback), security_origin_str),
      false);
}

void IndexedDBDispatcher::DeleteObjectStoreEntries(const std::string& security_origin, const std::string& database_name, const std::string& object_store_name, automation::KeyRangePtr key_range, DeleteObjectStoreEntriesCallback callback) {
  blink::IDBKeyRange* idb_key_range = IdbKeyRangeFromKeyRange(key_range.get());
  if (!idb_key_range) {
    //request_callback->sendFailure(Response::Error("Can not parse key range"));
    std::move(callback).Run(false);
    //DLOG(ERROR) << "Can not parse key range.";
    return;
  }
  scoped_refptr<DeleteObjectStoreEntriesImpl> delete_object_store_entries =
      DeleteObjectStoreEntriesImpl::Create(
        String::FromUTF8(object_store_name.data()), 
        idb_key_range,
        std::move(callback));
  delete_object_store_entries->Start(
      page_instance_->inspected_frames()->FrameWithSecurityOrigin(
        String::FromUTF8(security_origin.data())),
        String::FromUTF8(database_name.data()));
}

void IndexedDBDispatcher::RequestData(const std::string& security_origin, const std::string& database_name, const std::string& object_store_name, const std::string& index_name, int32_t skip_count, int32_t page_size, automation::KeyRangePtr key_range, RequestDataCallback callback) {
  blink::IDBKeyRange* idb_key_range = IdbKeyRangeFromKeyRange(key_range.get());
  if (!idb_key_range) {
    //request_callback->sendFailure(Response::Error("Can not parse key range."));
    std::move(callback).Run(std::vector<automation::IndexedDBDataEntryPtr>(), false);
    //DLOG(ERROR) << "Can not parse key range.";
    return;
  }

  scoped_refptr<DataLoader> data_loader = DataLoader::Create(
      std::move(callback), 
      String::FromUTF8(object_store_name.data()), 
      String::FromUTF8(index_name.data()),
      idb_key_range, 
      skip_count, 
      page_size);

  data_loader->Start(
      page_instance_->inspected_frames()->FrameWithSecurityOrigin(
        String::FromUTF8(security_origin.data())),
        String::FromUTF8(database_name.data()));
}

void IndexedDBDispatcher::RequestDatabase(const std::string& security_origin, const std::string& database_name, RequestDatabaseCallback callback) {
  scoped_refptr<DatabaseLoader> database_loader =
      DatabaseLoader::Create(std::move(callback));
  database_loader->Start(
      page_instance_->inspected_frames()->FrameWithSecurityOrigin(
        String::FromUTF8(security_origin.data())),
        String::FromUTF8(database_name.data()));
}

void IndexedDBDispatcher::RequestDatabaseNames(const std::string& security_origin, RequestDatabaseNamesCallback callback) {
  std::vector<std::string> failed_result;
  blink::LocalFrame* frame = page_instance_->inspected_frames()->FrameWithSecurityOrigin(
    String::FromUTF8(security_origin.data()));
  blink::Document* document = frame ? frame->GetDocument() : nullptr;
  if (!document) {
    std::move(callback).Run(failed_result);
    return;
  }
  blink::IDBFactory* idb_factory = nullptr;
  bool ok = AssertIDBFactory(document, idb_factory);
  if (!ok) {
    std::move(callback).Run(failed_result);
    return;
  }

  blink::ScriptState* script_state = ToScriptStateForMainWorld(frame);
  if (!script_state) {
    std::move(callback).Run(failed_result);
    return;
  }
  blink::ScriptState::Scope scope(script_state);
  blink::DummyExceptionStateForTesting exception_state;
  blink::IDBRequest* idb_request = idb_factory->GetDatabaseNames(script_state, exception_state);
  if (exception_state.HadException()) {
    std::move(callback).Run(failed_result);
    //DLOG(ERROR) << "Could not obtain database names.";
    return;
  }
  idb_request->addEventListener(
      blink::EventTypeNames::success,
      GetDatabaseNamesCallback::Create(
          std::move(callback),
          document->GetSecurityOrigin()->ToRawString()),
      false);
}

void IndexedDBDispatcher::OnWebFrameCreated(blink::WebLocalFrame* web_frame) {
  Enable();
}

}