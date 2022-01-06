// Copyright 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "storage/data_catalog.h"

#include "base/files/file_util.h"
#include "base/task_scheduler/post_task.h"
#include "storage/block.h"
#include "storage/data_column.h"
#include "storage/backend/storage_entry.h"
#include "zetasql/public/type.h"
#include "zetasql/proto/type.pb.h"
#include "third_party/protobuf/src/google/protobuf/compiler/parser.h"
#include "third_party/protobuf/src/google/protobuf/io/tokenizer.h"
#include "third_party/protobuf/src/google/protobuf/io/zero_copy_stream_impl.h"
#include "third_party/protobuf/src/google/protobuf/stubs/strutil.h"
#include "third_party/protobuf/src/google/protobuf/io/zero_copy_stream_impl_lite.h"
#include "third_party/protobuf/src/google/protobuf/arena.h"
#include "third_party/protobuf/src/google/protobuf/arenastring.h"
#include "third_party/protobuf/src/google/protobuf/generated_message_table_driven.h"
#include "third_party/protobuf/src/google/protobuf/generated_message_util.h"
#include "third_party/protobuf/src/google/protobuf/inlined_string_field.h"
#include "third_party/protobuf/src/google/protobuf/metadata.h"
#include "third_party/protobuf/src/google/protobuf/message.h"
#include "third_party/protobuf/src/google/protobuf/util/json_util.h"

namespace storage {

namespace {

const char kMetaTableIndex[] = "meta";

}

DataCatalog::DataCatalog(
  scoped_refptr<Torrent> torrent,
  //storage_proto::Info info,
  //const std::string& name,
  scoped_refptr<base::SingleThreadTaskRunner> db_task_runner):
  torrent_(torrent),
  //info_(std::move(info)),
  //name_(name),
  //database_(std::move(database)),
  type_factory_(new zetasql::TypeFactory),
  allocator_(new HeapBufferAllocator()),
  descriptor_pool_(new google::protobuf::DescriptorPool()),
  db_task_runner_(db_task_runner),
  meta_table_(nullptr),
  opened_(torrent->db_is_open()) {

}

// DataCatalog::DataCatalog(
//   storage_proto::Info info,
//   const std::string& name,
//   scoped_refptr<base::SingleThreadTaskRunner> db_task_runner,
//   std::unique_ptr<Database> database):
//   torrent_(nullptr),
//   info_(std::move(info)), 
//   name_(name),
//   database_(std::move(database)),
//   type_factory_(new zetasql::TypeFactory),
//   allocator_(new HeapBufferAllocator()),
//   descriptor_pool_(new google::protobuf::DescriptorPool()),
//   db_task_runner_(db_task_runner),
//   meta_table_(nullptr),
//   opened_(true) {

// }

DataCatalog::~DataCatalog() {
  db_task_runner_ = nullptr;
}

std::string DataCatalog::FullName() const { 
  return torrent_->info().path(); 
}

zetasql::Table* DataCatalog::meta_table() const {
  return meta_table_;
}

//Database* DataCatalog::db() const {
//  return torrent_->db();
//}

const storage_proto::Info& DataCatalog::info() const {
  return torrent_->info();
}

void DataCatalog::Open(base::Callback<void(bool)> cb, bool sync) {
  if (opened_) {
    std::move(cb).Run(true);
    return;
  }
  if (db_task_runner_->BelongsToCurrentThread()) {
    OpenImpl(false, std::move(cb), nullptr);
  } else {
    if (sync) {
      base::WaitableEvent do_sync{base::WaitableEvent::ResetPolicy::MANUAL, base::WaitableEvent::InitialState::NOT_SIGNALED};
      db_task_runner_->PostTask(
        FROM_HERE, 
        base::Bind(&DataCatalog::OpenImpl, 
          base::Unretained(this), 
          false,
          base::Passed(std::move(cb)),
          base::Unretained(&do_sync)));
      do_sync.Wait();
    } else {
      db_task_runner_->PostTask(
        FROM_HERE, 
        base::Bind(&DataCatalog::OpenImpl, 
          base::Unretained(this), 
          false,
          base::Passed(std::move(cb)),
          nullptr));
    }

  }
}

void DataCatalog::Create(base::Callback<void(bool)> cb, bool sync) {
  if (opened_) {
    std::move(cb).Run(true);
    return;
  }
  if (db_task_runner_->BelongsToCurrentThread()) {
    OpenImpl(true, std::move(cb), nullptr);
  } else {
    if (sync) {
      base::WaitableEvent do_sync{base::WaitableEvent::ResetPolicy::MANUAL, base::WaitableEvent::InitialState::NOT_SIGNALED};
      db_task_runner_->PostTask(
        FROM_HERE, 
        base::Bind(&DataCatalog::OpenImpl, 
          base::Unretained(this),
          true,
          base::Passed(std::move(cb)),
          base::Unretained(&do_sync)));
      do_sync.Wait();
    } else {
      db_task_runner_->PostTask(
        FROM_HERE, 
        base::Bind(&DataCatalog::OpenImpl, 
          base::Unretained(this), 
          true,
          base::Passed(std::move(cb)),
          nullptr));
    }
  }
}

void DataCatalog::Close(bool sync) {
  ////D//LOG(INFO) << "DataCatalog::Close";
  if (db_task_runner_->BelongsToCurrentThread()) {
    CloseImpl(nullptr);
  } else {
    ////D//LOG(INFO) << "DataCatalog::Close: posting to db thread.. sync ? " << sync;
    if (sync) {
      base::WaitableEvent do_sync{base::WaitableEvent::ResetPolicy::MANUAL, base::WaitableEvent::InitialState::NOT_SIGNALED};
      db_task_runner_->PostTask(
          FROM_HERE, 
          base::Bind(&DataCatalog::CloseImpl, 
            base::Unretained(this), 
            base::Unretained(&do_sync)));
      ////D//LOG(INFO) << "DataCatalog::Close: waiting on db thread... base::WaitableEvent = " << &do_sync;
      do_sync.Wait(); 
      ////D//LOG(INFO) << "DataCatalog::Close: end waiting on db thread";
    } else {
      db_task_runner_->PostTask(
          FROM_HERE,
          base::Bind(&DataCatalog::CloseImpl, 
            base::Unretained(this), 
            nullptr));
    }
  }
}


std::unique_ptr<Cursor> DataCatalog::CreateCursor(Transaction* tr, const std::string& table_name) {
  DataTable* table = GetTable(table_name);
  if (!table) {
    return {};
  }
  return torrent_->db().CreateCursor(tr, table->keyspace());
}

//std::unique_ptr<Cursor> DataCatalog::CreateCursor(bool write, const std::string& keyspace) {
//  return db()->CreateCursor(write, keyspace); 
//}

std::unique_ptr<Transaction> DataCatalog::BeginTransaction(bool write) {
  return torrent_->db().BeginTransaction(write);
}

bool DataCatalog::Init() {
  return LoadMetatables() && LoadTables();
}

zetasql_base::Status DataCatalog::GetTable(
  const std::string& name, 
  const zetasql::Table** table,
  const FindOptions& options) {
  auto it = tables_.find(name);
  if (it == tables_.end()) {
    return zetasql_base::Status(zetasql_base::NOT_FOUND, "table " + name + " not found");
  }
  *table = it->second.get();  
  return zetasql_base::Status(zetasql_base::OK, "");
}

zetasql_base::Status DataCatalog::GetModel(
  const std::string& name, 
  const zetasql::Model** model,
  const FindOptions& options) {
  return zetasql_base::Status();
}

zetasql_base::Status DataCatalog::GetFunction(
  const std::string& name, 
  const zetasql::Function** function,
  const FindOptions& options) {
  return zetasql_base::Status();
}

zetasql_base::Status DataCatalog::GetTableValuedFunction(
  const std::string& name, 
  const zetasql::TableValuedFunction** function,
  const FindOptions& options) {
  return zetasql_base::Status();
}

zetasql_base::Status DataCatalog::GetProcedure(
  const std::string& name,
  const zetasql::Procedure** procedure,
  const FindOptions& options) { 
  return zetasql_base::Status();
}

zetasql_base::Status DataCatalog::GetType(
  const std::string& name, 
  const zetasql::Type** type,
  const FindOptions& options) {
  return zetasql_base::Status();
}

zetasql_base::Status DataCatalog::GetCatalog(
  const std::string& name, 
  zetasql::Catalog** catalog,
  const FindOptions& options) {
  return zetasql_base::Status();
}

zetasql_base::Status DataCatalog::GetConstant(
  const std::string& name, 
  const zetasql::Constant** constant,
  const FindOptions& options) {
  return zetasql_base::Status();
}

std::string DataCatalog::SuggestTable(const absl::Span<const std::string>& mistyped_path) {
  return std::string();
}

std::string DataCatalog::SuggestFunction(const absl::Span<const std::string>& mistyped_path)  {
  return std::string();
}

std::string DataCatalog::SuggestTableValuedFunction(const absl::Span<const std::string>& mistyped_path)  {
  return std::string();
}

std::string DataCatalog::SuggestConstant(const absl::Span<const std::string>& mistyped_path) {
  return std::string();
}

void DataCatalog::Close() {
  Close(true);
}

std::unique_ptr<Block> DataCatalog::Scan(const zetasql::ResolvedQueryStmt* stmt) {
  const zetasql::ResolvedTableScan* table_scan = nullptr;
  const zetasql::ResolvedProjectScan* project_scan = nullptr;

  std::vector<const zetasql::ResolvedNode*> scan_nodes;
  stmt->GetDescendantsSatisfying(&zetasql::ResolvedNode::IsScan, &scan_nodes);
  
  for (auto const* scan : scan_nodes) {
    //////D//LOG(INFO) << "iterating over scan node '" << scan->node_kind_string() << "'";
    if (scan->node_kind() == zetasql::RESOLVED_TABLE_SCAN) {
      table_scan = scan->GetAs<zetasql::ResolvedTableScan>();
    } else if (scan->node_kind() == zetasql::RESOLVED_PROJECT_SCAN) {
      project_scan = scan->GetAs<zetasql::ResolvedProjectScan>(); 
    }
  }
  
  if (!table_scan || !project_scan) {
    ////D//LOG(INFO) << "theres no table or project scan on query. aborting";
    return {};
  }

  std::unique_ptr<Schema> block_schema = std::make_unique<Schema>();
  const auto& column_list = project_scan->column_list();
  for (auto const& column : column_list) {
    block_schema->AddColumn(column.name(), column.type());
  }

  const DataTable* table = static_cast<const DataTable *>(table_scan->table());
  DCHECK(table);
  
  BlockRowWriter writer;
  std::unique_ptr<Block> block = std::make_unique<Block>(std::make_unique<HeapBufferAllocator>(), std::move(block_schema), table->NumRows() > 0 ? table->NumRows() : 20);
  writer.Init(block.get());

  // TODO: doing some of these for each scan sounds stupid 
  const google::protobuf::Message* table_prototype = factory_.GetPrototype(table->descriptor());
  auto trans = torrent_->db().BeginTransaction(false);
  auto cursor = torrent_->db().CreateCursor(trans.get(), table->keyspace());
  cursor->First();
  while (cursor->IsValid()) { // for each row
    google::protobuf::Message* table_message = table_prototype->New(nullptr);
    bool valid = false;
    KeyValuePair kv = DbDecodeKV(cursor->GetData(), &valid);
    if (!table_message->ParseFromArray(kv.second.data(), kv.second.size())) {
      ////D//LOG(INFO) << "oops. problem parsing row. raw data (" << kv.second.size() << "):\n'" << kv.second.as_string() << "'";
      delete table_message;
      cursor->Next();
      continue;    
    
    }

    const google::protobuf::Reflection* table_descr = table_message->GetReflection();

    writer.AddRow();

    for (auto const& column : column_list) {
      const zetasql::Type* column_type = column.type();
      const google::protobuf::FieldDescriptor* proto_field = table->descriptor()->FindFieldByName(column.name());
      if (!proto_field) { 
        ////D//LOG(INFO) << "oops. " << column.name() << " was not found in the descriptor";
        cursor->Next();
        continue;
      }
      SetByFieldDescriptor(&writer, column_type, proto_field, table_descr, table_message);
    }
    //std::string realdata(data.data(), data.size());
    //printf("row: %s\n", realdata.c_str());
    delete table_message;
    cursor->Next();
  }

  trans->Commit();
  
  return block;
}

DataTable* DataCatalog::GetTable(const std::string& table_name) const {
  auto it = tables_.find(table_name);
  if (it == tables_.end()) {
    return nullptr;
  }
  return it->second.get();  
}

std::unique_ptr<Iterator> DataCatalog::NewIterator(const std::string& table_name) {
  //DCHECK(db_task_runner_->BelongsToCurrentThread());
  DataTable* table = GetTable(table_name);
  if (!table) {
    return {};
  }

  auto tr = torrent_->db().BeginTransaction(false);
  auto cursor = torrent_->db().CreateCursor(tr.get(), table->keyspace());

  return std::make_unique<Iterator>(std::move(tr), std::move(cursor));
}

void DataCatalog::Get(const std::string& table_name, base::StringPiece key, base::Callback<void(std::string, bool)> cb) {
  DataTable* table = GetTable(table_name);
  if (!table) {
    std::move(cb).Run(std::string(), false);
    return;
  }
  if (db_task_runner_->BelongsToCurrentThread()) {
    table->Get(key, std::move(cb));
  } else {
    db_task_runner_->PostTask(
      FROM_HERE, 
      base::Bind(&DataTable::Get, 
        base::Unretained(table), 
        key, 
        base::Passed(std::move(cb))));
  }
}

void DataCatalog::Insert(const std::string& table_name, base::StringPiece key, base::StringPiece data, base::Callback<void(bool)> cb) {
  DataTable* table = GetTable(table_name);
  if (!table) {
    std::move(cb).Run(false);
    return;
  }
  if (db_task_runner_->BelongsToCurrentThread()) {
    table->Insert(key, data, std::move(cb));
  } else {
    db_task_runner_->PostTask(
      FROM_HERE, 
      base::Bind(&DataTable::Insert, base::Unretained(table), key, data, base::Passed(std::move(cb))));
  }
}

void DataCatalog::Insert(const std::string& table_name, base::StringPiece key, scoped_refptr<net::IOBufferWithSize> data, base::Callback<void(bool)> cb) {
  DataTable* table = GetTable(table_name);
  if (!table) {
    std::move(cb).Run(false);
    return;
  }
  if (db_task_runner_->BelongsToCurrentThread()) {
    table->InsertData(key, data, std::move(cb));
  } else {
    db_task_runner_->PostTask(
      FROM_HERE, 
      base::Bind(&DataTable::InsertData, base::Unretained(table), key, data, base::Passed(std::move(cb))));
  }
}

void DataCatalog::Remove(const std::string& table_name, base::StringPiece key, base::Callback<void(bool)> cb) {
  DataTable* table = GetTable(table_name);
  if (!table) {
    std::move(cb).Run(false);
    return;
  }
  if (db_task_runner_->BelongsToCurrentThread()) {
    table->Remove(key, std::move(cb));
  } else {
    db_task_runner_->PostTask(
      FROM_HERE, 
      base::Bind(&DataTable::Remove, base::Unretained(table), key, base::Passed(std::move(cb))));
  }
}

bool DataCatalog::Get(const std::string& table_name, base::StringPiece key, std::string* value) {
  DataTable* table = GetTable(table_name);
  if (!table) {
    return false;
  }
  return table->GetSync(key, value);
}

bool DataCatalog::Insert(const std::string& table_name, base::StringPiece key, base::StringPiece data) {
  DataTable* table = GetTable(table_name);
  if (!table) {
    return false;
  }
  return table->InsertSync(key, data);
}

bool DataCatalog::InsertData(const std::string& table_name, base::StringPiece key, scoped_refptr<net::IOBufferWithSize> data) {
  DataTable* table = GetTable(table_name);
  if (!table) {
    return false;
  }
  return table->InsertDataSync(key, data);
}

bool DataCatalog::Remove(const std::string& table_name, base::StringPiece key) {
  DataTable* table = GetTable(table_name);
  if (!table) {
    return false;
  }
  return table->RemoveSync(key);
}

bool DataCatalog::LoadMetatables() {
  KeyValuePair keyval;
  auto trans = torrent_->db().BeginTransaction(false);
  std::unique_ptr<Cursor> cursor = torrent_->db().CreateCursor(trans.get(), kMetaTableIndex);
  //////D//LOG(INFO) << "getting 'catalog.proto' at table " << kMetaTableIndex;
  bool ok = cursor->Get("catalog.proto", &keyval);
  ok ? trans->Commit() : trans->Rollback();
  if (!ok) {
    LOG(ERROR) << "DataCatalog " << FullName() << ": failed to recover metadata from database";
    return false;
  }
  
  if (!catalog_proto_.ParseFromArray(keyval.second.data(), keyval.second.size())) {
    LOG(ERROR) << "DataCatalog " << FullName() << ": failed to deserialize metadata from database";
    return false;
  }
  const auto& catalog = catalog_proto_.catalog();

  auto meta = std::make_unique<DataTable>(this); 
  meta_table_ = meta.get();
  auto meta_proto = catalog.meta_table();
  if (!meta->Deserialize(meta_proto)) {
    return false;
  }
  AddTable(std::move(meta));

  return true;
}

bool DataCatalog::LoadTables() {
  const auto& catalog = catalog_proto_.catalog();

  for (const auto& table_proto : catalog.table()) {
    auto table = std::make_unique<DataTable>(this);
    table->Deserialize(table_proto); 
    AddTable(std::move(table));
  }
  return true;
}

void DataCatalog::AddTable(std::unique_ptr<DataTable> table) {
  std::string table_name = table->Name();
  tables_.emplace(std::move(table_name), std::move(table));
}

void DataCatalog::SetByFieldDescriptor(
  BlockRowWriter* writer, 
  const zetasql::Type* column_type, 
  const google::protobuf::FieldDescriptor* field, 
  const google::protobuf::Reflection* table, 
  const google::protobuf::Message* table_message) const {

  //zetasql::TypeKind kind = column_type->kind();
  auto cpp_type = field->cpp_type();

  switch (cpp_type) {
    case google::protobuf::FieldDescriptor::CPPTYPE_ENUM: {
      const google::protobuf::EnumValueDescriptor* enum_descr = table->GetEnum(*table_message, field);
      //////D//LOG(INFO) << "setting enum: " << enum_descr->number();
      writer->Set<zetasql::TYPE_INT32>(enum_descr->number());
      break;
    }
    case google::protobuf::FieldDescriptor::CPPTYPE_INT32:
      //////D//LOG(INFO) << "setting int32: " << table->GetInt32(*table_message, field);
      writer->Set<zetasql::TYPE_INT32>(table->GetInt32(*table_message, field));
      break;
    case google::protobuf::FieldDescriptor::CPPTYPE_INT64:
      //////D//LOG(INFO) << "setting int64: " << table->GetInt64(*table_message, field);    
      writer->Set<zetasql::TYPE_INT64>(table->GetInt64(*table_message, field));
      break;
    case google::protobuf::FieldDescriptor::CPPTYPE_UINT32:
      //////D//LOG(INFO) << "setting uint32: " << table->GetUInt32(*table_message, field);
      writer->Set<zetasql::TYPE_UINT32>(table->GetUInt32(*table_message, field));
      break;
    case google::protobuf::FieldDescriptor::CPPTYPE_UINT64:
      //////D//LOG(INFO) << "setting uint64: " << table->GetInt64(*table_message, field);
      writer->Set<zetasql::TYPE_UINT64>(table->GetUInt64(*table_message, field));
      break;
    case google::protobuf::FieldDescriptor::CPPTYPE_BOOL:
      //////D//LOG(INFO) << "setting bool: " << table->GetBool(*table_message, field);
      writer->Set<zetasql::TYPE_BOOL>(table->GetBool(*table_message, field));
      break;
    case google::protobuf::FieldDescriptor::CPPTYPE_FLOAT:
      //////D//LOG(INFO) << "setting float: " << table->GetFloat(*table_message, field);
      writer->Set<zetasql::TYPE_FLOAT>(table->GetFloat(*table_message, field));
      break;
    case google::protobuf::FieldDescriptor::CPPTYPE_DOUBLE:
      //////D//LOG(INFO) << "setting double: " << table->GetDouble(*table_message, field);
      writer->Set<zetasql::TYPE_DOUBLE>(table->GetDouble(*table_message, field));
      break;
    case google::protobuf::FieldDescriptor::CPPTYPE_STRING:
      //////D//LOG(INFO) << "setting string: " << table->GetString(*table_message, field);
      writer->Set<zetasql::TYPE_STRING>(table->GetString(*table_message, field));
      break;
    default:
      NOTREACHED();
  }
}

void DataCatalog::OpenImpl(bool create, base::Callback<void(bool)> cb, base::WaitableEvent* do_sync) {
  Database* db = nullptr;
  std::vector<std::string> keyspaces;
  keyspaces.push_back("meta");
  keyspaces.push_back(FullName());

  if (create) {
    db = Database::Create(torrent_, keyspaces);
  } else {
    db = Database::Open(torrent_);
  }

  if (db) {
    opened_ = true;
    std::move(cb).Run(true);
    if (do_sync) {
      do_sync->Signal();
    }
    return;
  }

  std::move(cb).Run(false);

  if (do_sync) {
    do_sync->Signal();
  }
}

void DataCatalog::CloseImpl(base::WaitableEvent* do_sync) {
  ////D//LOG(INFO) << "DataCatalog::CloseImpl: base::WaitableEvent = " << do_sync;
  if (torrent_->db_is_open()) {
    ////D//LOG(INFO) << "DataCatalog::CloseImpl: calling database_->Close()";
    torrent_->db().Close();
    opened_ = false;
    ////D//LOG(INFO) << "DataCatalog::CloseImpl: calling database_->Close() end";
  }
  if (do_sync) {
    ////D//LOG(INFO) << "DataCatalog::CloseImpl: sending signal";
    do_sync->Signal();
  }
}

void DataCatalog::OnInfoHeaderChanged(const storage_proto::Info& info) {
  ////D//LOG(INFO) << "DataCatalog::OnInfoHeaderChanged. see if we can update the info directly from torrent now..";
  //torrent_->mutable_info()->CopyFrom(info);
}

}