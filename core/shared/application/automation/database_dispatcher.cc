// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/application/automation/database_dispatcher.h"

#include "core/shared/application/automation/page_instance.h"
#include "services/service_manager/public/cpp/interface_provider.h"
#include "third_party/blink/renderer/bindings/core/v8/exception_state.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/loader/document_loader.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/inspector/inspected_frames.h"
#include "third_party/blink/renderer/modules/webdatabase/database.h"
#include "third_party/blink/renderer/modules/webdatabase/database_client.h"
#include "third_party/blink/renderer/modules/webdatabase/database_tracker.h"
#include "third_party/blink/renderer/modules/webdatabase/sql_error.h"
#include "third_party/blink/renderer/modules/webdatabase/sql_result_set.h"
#include "third_party/blink/renderer/modules/webdatabase/sql_result_set_row_list.h"
#include "third_party/blink/renderer/modules/webdatabase/sql_transaction.h"
#include "third_party/blink/renderer/modules/webdatabase/sqlite/sql_value.h"
#include "third_party/blink/renderer/platform/wtf/ref_counted.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"
#include "third_party/blink/renderer/modules/webdatabase/inspector_database_agent.h"
#include "ipc/ipc_sync_channel.h"

namespace application {

typedef DatabaseDispatcher::ExecuteSQLCallback ExecuteSQLCallback;  

namespace {

class ExecuteSQLCallbackWrapper : public RefCounted<ExecuteSQLCallbackWrapper> {
 public:
  static scoped_refptr<ExecuteSQLCallbackWrapper> Create(ExecuteSQLCallback callback) {
    return base::AdoptRef(new ExecuteSQLCallbackWrapper(std::move(callback)));
  }
  ~ExecuteSQLCallbackWrapper() = default;
  //ExecuteSQLCallback* Get() { return &callback_; }

  void ReportTransactionFailed(blink::SQLError* error) {
    automation::ErrorPtr error_object = automation::Error::New();
    error_object->message = std::string(error->message().Utf8().data());
    error_object->code = error->code();
    std::move(callback_).Run(base::Optional<std::vector<std::string>>(),
                             base::Optional<std::vector<std::unique_ptr<base::Value>>>(),
                             std::move(error_object));
  }

  void SendSuccess(std::vector<std::string> column_names,
                   std::vector<std::unique_ptr<base::Value>> values) {
    std::move(callback_).Run(std::move(column_names),
                             std::move(values),
                             nullptr);
  }

 private:
  explicit ExecuteSQLCallbackWrapper(
    ExecuteSQLCallback callback)
      : callback_(std::move(callback)) {}
  ExecuteSQLCallback callback_;
};

class StatementCallback final : public blink::SQLStatement::OnSuccessCallback {
 public:
  static StatementCallback* Create(
      scoped_refptr<ExecuteSQLCallbackWrapper> request_callback) {
    return new StatementCallback(std::move(request_callback));
  }

  ~StatementCallback() override = default;

  bool OnSuccess(blink::SQLTransaction*, blink::SQLResultSet* result_set) override {
    blink::SQLResultSetRowList* row_list = result_set->rows();

    std::vector<std::string> column_names;
    const Vector<String>& columns = row_list->ColumnNames();
    for (size_t i = 0; i < columns.size(); ++i)
      column_names.push_back(std::string(columns[i].Utf8().data(), columns[i].length()));

    std::vector<std::unique_ptr<base::Value>> values;
    const Vector<blink::SQLValue>& data = row_list->Values();
    for (size_t i = 0; i < data.size(); ++i) {
      const blink::SQLValue& value = row_list->Values()[i];
      switch (value.GetType()) {
        case blink::SQLValue::kStringValue: {
          String str_value = value.GetString();
          values.push_back(std::make_unique<base::Value>(
            std::string(str_value.Utf8().data(), str_value.length())));
          break;
        }
        case blink::SQLValue::kNumberValue: {
          values.push_back(std::make_unique<base::Value>(value.Number()));
          break;
        }
        case blink::SQLValue::kNullValue: {
          values.push_back(std::unique_ptr<base::Value>());
          break;
        }
      }
    }
    request_callback_->SendSuccess(std::move(column_names),
                                   std::move(values));
    return true;
  }

 private:
  explicit StatementCallback(
      scoped_refptr<ExecuteSQLCallbackWrapper> request_callback)
      : request_callback_(std::move(request_callback)) {}

  scoped_refptr<ExecuteSQLCallbackWrapper> request_callback_;
};

class StatementErrorCallback final : public blink::SQLStatement::OnErrorCallback {
 public:
  static StatementErrorCallback* Create(
      scoped_refptr<ExecuteSQLCallbackWrapper> request_callback) {
    return new StatementErrorCallback(std::move(request_callback));
  }

  ~StatementErrorCallback() override = default;

  bool OnError(blink::SQLTransaction*, blink::SQLError* error) override {
    request_callback_->ReportTransactionFailed(error);
    return true;
  }

 private:
  explicit StatementErrorCallback(
      scoped_refptr<ExecuteSQLCallbackWrapper> request_callback)
      : request_callback_(std::move(request_callback)) {}

  scoped_refptr<ExecuteSQLCallbackWrapper> request_callback_;
};

class TransactionCallback final : public blink::SQLTransaction::OnProcessCallback {
 public:
  static TransactionCallback* Create(
      const String& sql_statement,
      scoped_refptr<ExecuteSQLCallbackWrapper> request_callback) {
    return new TransactionCallback(sql_statement, std::move(request_callback));
  }

  ~TransactionCallback() override = default;

  bool OnProcess(blink::SQLTransaction* transaction) override {
    Vector<blink::SQLValue> sql_values;
    transaction->ExecuteSQL(sql_statement_, sql_values,
                            StatementCallback::Create(request_callback_),
                            StatementErrorCallback::Create(request_callback_),
                            IGNORE_EXCEPTION_FOR_TESTING);
    return true;
  }

 private:
  explicit TransactionCallback(
      const String& sql_statement,
      scoped_refptr<ExecuteSQLCallbackWrapper> request_callback)
      : sql_statement_(sql_statement),
        request_callback_(std::move(request_callback)) {}

  String sql_statement_;
  scoped_refptr<ExecuteSQLCallbackWrapper> request_callback_;
};

class TransactionErrorCallback final : public blink::SQLTransaction::OnErrorCallback {
 public:
  static TransactionErrorCallback* Create(
      scoped_refptr<ExecuteSQLCallbackWrapper> request_callback) {
    return new TransactionErrorCallback(std::move(request_callback));
  }

  ~TransactionErrorCallback() override = default;

  bool OnError(blink::SQLError* error) override {
    request_callback_->ReportTransactionFailed(error);
    return true;
  }

 private:
  explicit TransactionErrorCallback(
      scoped_refptr<ExecuteSQLCallbackWrapper> request_callback)
      : request_callback_(std::move(request_callback)) {}

  scoped_refptr<ExecuteSQLCallbackWrapper> request_callback_;
};

}  // namespace

class InspectorDatabaseAgentImpl : public blink::InspectorDatabaseAgent {
public: 
  InspectorDatabaseAgentImpl(DatabaseDispatcher* dispatcher): 
    InspectorDatabaseAgent(
      dispatcher->page_instance_->inspected_frames()->Root()->View()->GetPage()),
    dispatcher_(dispatcher) {}

  void Restore() override {
    dispatcher_->Restore();
  }

  void DidCommitLoadForLocalFrame(blink::LocalFrame* frame) override {
    dispatcher_->DidCommitLoadForLocalFrame(frame);
  }

  void DidOpenDatabase(blink::Database* db,
                       const String& domain,
                       const String& name,
                       const String& version) override {
    dispatcher_->DidOpenDatabase(db, domain, name, version);
  }

private:
  DatabaseDispatcher* dispatcher_;
};

// static 
void DatabaseDispatcher::Create(automation::DatabaseInterfaceRequest request, AutomationContext* context, PageInstance* page_instance) {
  new DatabaseDispatcher(std::move(request), context, page_instance);
}

DatabaseDispatcher::DatabaseDispatcher(automation::DatabaseInterfaceRequest request, AutomationContext* context, PageInstance* page_instance): 
  page_instance_(page_instance),
  application_id_(-1),
  binding_(this),
  enabled_(false) {
  
}

DatabaseDispatcher::DatabaseDispatcher(AutomationContext* context, PageInstance* page_instance): 
  page_instance_(page_instance),
  application_id_(-1),
  binding_(this),
  enabled_(false) {
  
}

DatabaseDispatcher::~DatabaseDispatcher() {

}

void DatabaseDispatcher::Init(IPC::SyncChannel* channel) {
  channel->GetRemoteAssociatedInterface(&database_client_ptr_);
}

void DatabaseDispatcher::Bind(automation::DatabaseInterfaceAssociatedRequest request) {
  //DLOG(INFO) << "DatabaseDispatcher::Bind (application)";
  binding_.Bind(std::move(request));
}

void DatabaseDispatcher::Register(int32_t application_id) {
  application_id_ = application_id;
}

void DatabaseDispatcher::Disable() {
  if (!enabled_) {
    return;
  }
  enabled_ = false;
  if (blink::DatabaseClient* client = blink::DatabaseClient::FromPage(page_))
    client->SetInspectorAgent(nullptr);
  resources_.clear();
}

void DatabaseDispatcher::Enable() {
  //DLOG(INFO) << "DatabaseDispatcher::Enable (application process)";
  if (enabled_) {
    return;
  }
  enabled_ = true;
  if (blink::DatabaseClient* client = blink::DatabaseClient::FromPage(page_)) {
    client->SetInspectorAgent(database_agent_impl_.Get());
  }
  blink::DatabaseTracker::Tracker().ForEachOpenDatabaseInPage(
      page_,
      WTF::BindRepeating(&DatabaseDispatcher::RegisterDatabaseOnCreation,
                         WTF::Unretained(this)));
}

void DatabaseDispatcher::ExecuteSQL(const std::string& database_id, const std::string& query, ExecuteSQLCallback reply_callback) {
  if (!enabled_) {
    //DLOG(ERROR) << "Database agent is not enabled";
    automation::ErrorPtr error_object = automation::Error::New();
    error_object->message = std::string("Database agent is not enabled");
    error_object->code = 999;
    std::move(reply_callback).Run(base::Optional<std::vector<std::string>>(),
                             base::Optional<std::vector<std::unique_ptr<base::Value>>>(),
                             std::move(error_object));
    return;
  }

  blink::Database* database = DatabaseForId(String::FromUTF8(database_id.data()));
  if (!database) {
    //DLOG(ERROR) << "Database not found";
    automation::ErrorPtr error_object = automation::Error::New();
    error_object->message = std::string("Database not found");
    error_object->code = 999;
    std::move(reply_callback).Run(base::Optional<std::vector<std::string>>(),
                             base::Optional<std::vector<std::unique_ptr<base::Value>>>(),
                             std::move(error_object));
    return;
  }

  scoped_refptr<ExecuteSQLCallbackWrapper> wrapper =
      ExecuteSQLCallbackWrapper::Create(std::move(reply_callback));
  TransactionCallback* callback = TransactionCallback::Create(String::FromUTF8(query.data()), wrapper);
  TransactionErrorCallback* error_callback =
      TransactionErrorCallback::Create(wrapper);
  blink::SQLTransaction::OnSuccessCallback* success_callback = nullptr;
  database->PerformTransaction(callback, error_callback, success_callback);
}

void DatabaseDispatcher::GetDatabaseTableNames(const std::string& database_id, GetDatabaseTableNamesCallback callback) {
  if (!enabled_) {
    //DLOG(ERROR) << "Database agent is not enabled";
    std::move(callback).Run(std::vector<std::string>());
    return;
  }

  std::vector<std::string> names;
  blink::Database* database = DatabaseForId(String::FromUTF8(database_id.data()));
  if (database) {
    Vector<String> table_names = database->TableNames();
    unsigned length = table_names.size();
    for (unsigned i = 0; i < length; ++i)
      names.push_back(std::string(table_names[i].Utf8().data(), table_names[i].length()));
  }
  std::move(callback).Run(std::move(names));
}

blink::Database* DatabaseDispatcher::DatabaseForId(const String& database_id) {
  DatabaseResourcesHeapMap::iterator it = resources_.find(database_id);
  if (it == resources_.end())
    return nullptr;
  return it->value->GetDatabase();
}

void DatabaseDispatcher::RegisterDatabaseOnCreation(blink::Database* database) {
  DidOpenDatabase(database, database->GetSecurityOrigin()->Host(),
                  database->StringIdentifier(), database->version());
}

void DatabaseDispatcher::DidOpenDatabase(blink::Database* database,
                                         const String& domain,
                                         const String& name,
                                         const String& version) {
  if (InspectorDatabaseResource* resource = FindByFileName(database->FileName())) {
    resource->SetDatabase(database);
    return;
  }

  InspectorDatabaseResource* resource =
      InspectorDatabaseResource::Create(database, domain, name, version);
  resources_.Set(resource->Id(), resource);
  // Resources are only bound while visible.
  DCHECK(enabled_);
  DCHECK(GetClient());
  resource->Bind(GetClient());
}

void DatabaseDispatcher::DidCommitLoadForLocalFrame(blink::LocalFrame* frame) {
  // FIXME(dgozman): adapt this for out-of-process iframes.
  if (frame != page_->MainFrame())
    return;

  resources_.clear();
}

InspectorDatabaseResource* DatabaseDispatcher::FindByFileName(const String& file_name) {
  for (DatabaseResourcesHeapMap::iterator it = resources_.begin();
       it != resources_.end(); ++it) {
    if (it->value->GetDatabase()->FileName() == file_name)
      return it->value.Get();
  }
  return nullptr;
}

automation::DatabaseClient* DatabaseDispatcher::GetClient() const {
  return database_client_ptr_.get();
}

void DatabaseDispatcher::Restore() {
  if (!enabled_) {
    Enable();
  }
}

void DatabaseDispatcher::OnWebFrameCreated(blink::WebLocalFrame* web_frame) {
  database_agent_impl_ = new InspectorDatabaseAgentImpl(this);
  page_ = page_instance_->inspected_frames()->Root()->View()->GetPage();
  database_agent_impl_->Init(
    page_instance_->probe_sink(), 
    page_instance_->inspector_backend_dispatcher(),
    page_instance_->state());
  Enable();
}

}