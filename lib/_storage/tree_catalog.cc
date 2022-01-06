// Copyright 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "storage/tree_catalog.h"

#include "base/callback.h"
#include "base/threading/thread_task_runner_handle.h"
#include "base/task_scheduler/post_task.h"
#include "storage/db/db.h"
#include "storage/data_table.h"
#include "storage/torrent.h"
#include "storage/block.h"

namespace storage {

namespace {

// TODO change this

const char kProtoData[] = 
  R"(
syntax = "proto3";

package disk_proto;

enum InfoFileType {
  BLOB_FILE = 0;
  BLOB_EXECUTABLE = 1;
  BLOB_DATABASE = 2;
  BLOB_TABLE = 3;
}

message InfoFile {
  string name = 1;
  bytes root_hash = 2;
  string parent = 3;
  int64 offset = 4;
  int64 piece_count = 5;
  int64 piece_start = 6;
  int64 piece_end = 7;
  int64 length = 8;
  // dir + name + ext
  string path = 11;
  string content_type = 12;
  int64 creation_date = 13;
  int32 mtime = 14;
  string attr = 15;
  // for when a blob is a db
  InfoFileType type = 16;
}

enum InfoKind {
  INFO_TREE = 0; // tree is the 'disk manifest'
  INFO_FILESET = 1;
  INFO_DATABASE = 2;
  INFO_APP = 3;
}

enum InfoState {
  // empty entry, when not even metadata is here
  STATE_NONE = 0;
  STATE_CHECKING = 1;
  STATE_DOWNLOADING_META = 2;
  STATE_DOWNLOADING = 3;
  STATE_FINISHED = 4;
  STATE_SEEDING = 5;
  STATE_ERROR = 6;
}

message InfoPeerNode {
  string address = 1;
  int32 port = 2;
}

message InfoTracker {

}

message InfoPiece {
  int32 index = 1;
  int64 length = 2;
  // all torrent states work here
  // except maybe 'downloading meta'
  InfoState state = 3;
}

message Info {
  InfoKind kind = 1;
  InfoState state = 2;
  string path = 3;
  bytes id = 4;
  bytes tree = 5;
  bytes root_hash = 6;
  string comment = 7;
  string created_by = 8;
  int64 piece_length = 9;
  int64 piece_count = 10;
  int64 length = 11;
  int64 hash_header_length = 12;
  int64 hash_content_length = 13;
  int64 creation_date = 14;
  int32 mtime = 15;
  int64 file_count = 16;
  bool readonly = 17;
  string announce = 18;
  repeated string announce_list = 19;
  repeated InfoFile files = 20;
  repeated InfoPeerNode nodes = 21;
  repeated InfoTracker trackers = 22;
  repeated InfoPiece pieces = 23;
})";

}

const char TreeCatalog::kKey[] = "registry";

// static 
std::unique_ptr<TreeCatalog> TreeCatalog::Create(Torrent* torrent, scoped_refptr<base::SingleThreadTaskRunner> db_task_runner) {
  std::unique_ptr<TreeCatalog> result = std::make_unique<TreeCatalog>(torrent, db_task_runner);
  if (!result->CreateMetadata()) {
    return {};
  }
  return result;
}

// static 
std::unique_ptr<TreeCatalog> TreeCatalog::Open(Torrent* torrent, scoped_refptr<base::SingleThreadTaskRunner> db_task_runner) {
  std::unique_ptr<TreeCatalog> result = std::make_unique<TreeCatalog>(torrent, db_task_runner);
  if (!result->InitMetadata()) {
    return {};
  }
  return result;
}

TreeCatalog::TreeCatalog(Torrent* torrent, scoped_refptr<base::SingleThreadTaskRunner> db_task_runner):
  catalog_(std::make_unique<DataCatalog>(torrent, db_task_runner)),
  closed_(false),
  updating_index_(false),
  keyspace_("registry"),
  db_event_(
      base::WaitableEvent::ResetPolicy::MANUAL, 
      base::WaitableEvent::InitialState::NOT_SIGNALED),
  weak_factory_(this) {

}

TreeCatalog::~TreeCatalog() {
  if (!closed_) {
    DLOG(INFO) << "warning: auto closing db on TreeCatalog destructor";
    Close();
  }
}

const storage_proto::Info& TreeCatalog::info() const {
  return catalog_->info();
}
  
int TreeCatalog::AddEncodedIndex(base::StringPiece key, base::StringPiece data, const base::Callback<void(int64_t)>& callback) {
  updating_index_ = true;
  int result = net::ERR_FAILED;
  scoped_refptr<base::SingleThreadTaskRunner> current = base::ThreadTaskRunnerHandle::Get();
  scoped_refptr<base::SingleThreadTaskRunner> db_task_runner = catalog_->db_task_runner();
  if (current != db_task_runner) {
    db_task_runner->PostTask(FROM_HERE, 
      base::BindOnce(&TreeCatalog::AddEncodedIndexOnDbThread, 
        base::Unretained(this), 
        key, 
        data,
        callback,
        current));
    result = net::ERR_IO_PENDING;
  } else {
    auto tr = catalog_->torrent()->db().BeginTransaction(true);
    bool ok = catalog_->torrent()->db().Put(tr.get(), keyspace_, key, data);
    ok ? tr->Commit() : tr->Rollback();
    result = ok ? net::OK : net::ERR_FAILED;
  }
  return result;
}

void TreeCatalog::AddEncodedIndexOnDbThread(base::StringPiece key, base::StringPiece data, const base::Callback<void(int64_t)>& callback, scoped_refptr<base::SingleThreadTaskRunner> reply_to) {
  auto tr = catalog_->torrent()->db().BeginTransaction(true);
  bool result = catalog_->torrent()->db().Put(tr.get(), keyspace_, key, data);
  result ? tr->Commit() : tr->Rollback();
  reply_to->PostTask(FROM_HERE, base::Bind(callback, result ? net::OK : net::ERR_FAILED));
  updating_index_ = false;
}

bool TreeCatalog::GetTable(const std::string& name, const DataTable** table) {
  const zetasql::Table* ztable = nullptr;
  zetasql_base::Status status = catalog_->GetTable(name, &ztable);
  if (status.ok())
    *table = static_cast<const DataTable*>(ztable);
  
  return status.ok();
}

bool TreeCatalog::CreateMetadata() {
  storage_proto::CatalogMetadata catalog_meta_proto;
  
  // now fill the meta with catalog metadata
  storage_proto::Catalog* catalog_proto = catalog_meta_proto.mutable_catalog();
  catalog_proto->set_name("registry");
  catalog_proto->set_table_count(1);

  /*
   * Meta
   */

  storage_proto::Table* meta_table = catalog_proto->mutable_meta_table();
  meta_table->set_name("meta");
  meta_table->set_keyspace("meta");
  // meta is equivalent to table 0. and starts at the first page
  meta_table->set_index(0);
  
  /*
   * Meta table columns
   */


  auto* meta_id_column = meta_table->add_column();
  meta_id_column->set_name("id");
  meta_id_column->set_type(storage_proto::COLUMN_INT32);
  meta_id_column->set_offset(0);

  auto* table_name_column = meta_table->add_column();
  table_name_column->set_name("table_name");
  table_name_column->set_type(storage_proto::COLUMN_STRING);
  table_name_column->set_offset(1);

  /*
   * Main
   */

  // create the 'main' table
  storage_proto::Table* main_table = catalog_proto->add_table();
  main_table->set_name("registry");
  main_table->set_keyspace("registry");
  main_table->set_index(1);
  main_table->set_proto(kProtoData);
  main_table->set_table_descriptor_name("Info");
  /*
   * Main table columns
   * TODO: we need to use Reflection here
   * and JUST REPEAT what we see in Info
   */

  auto* kind_column = main_table->add_column();
  kind_column->set_name("kind");
  kind_column->set_type(storage_proto::COLUMN_INT32);
  kind_column->set_offset(0);

  auto* state_column = main_table->add_column();
  state_column->set_name("state");
  state_column->set_type(storage_proto::COLUMN_INT32);
  state_column->set_offset(1);

  auto* path_column = main_table->add_column();
  path_column->set_name("path");
  path_column->set_type(storage_proto::COLUMN_STRING);
  path_column->set_offset(2);

  auto* id_column = main_table->add_column();
  id_column->set_name("id");
  id_column->set_type(storage_proto::COLUMN_STRING);
  id_column->set_offset(3);

  auto* name_column = main_table->add_column();
  name_column->set_name("tree");
  name_column->set_type(storage_proto::COLUMN_STRING);
  name_column->set_offset(4);

  auto* hash_column = main_table->add_column();
  hash_column->set_name("root_hash");
  hash_column->set_type(storage_proto::COLUMN_BYTES);
  hash_column->set_offset(5);

  auto* blocksz_column = main_table->add_column();
  blocksz_column->set_name("piece_length");
  blocksz_column->set_type(storage_proto::COLUMN_INT64);
  blocksz_column->set_offset(6);

  auto* blockcnt_column = main_table->add_column();
  blockcnt_column->set_name("piece_count");
  blockcnt_column->set_type(storage_proto::COLUMN_INT64);
  blockcnt_column->set_offset(7);

  auto* size_column = main_table->add_column();
  size_column->set_name("length");
  size_column->set_type(storage_proto::COLUMN_INT64);
  size_column->set_offset(8);

  auto* created_column = main_table->add_column();
  created_column->set_name("creation_date");
  created_column->set_type(storage_proto::COLUMN_TIMESTAMP);
  created_column->set_offset(9);

  auto* modified_column = main_table->add_column();
  modified_column->set_name("mtime");
  modified_column->set_type(storage_proto::COLUMN_TIMESTAMP);
  modified_column->set_offset(10);

  auto* blobcnt_column = main_table->add_column();
  blobcnt_column->set_name("file_count");
  blobcnt_column->set_type(storage_proto::COLUMN_INT64);
  blobcnt_column->set_offset(11);
  
  std::string encoded_catalog;
  if (!catalog_meta_proto.SerializeToString(&encoded_catalog)) {
    DLOG(ERROR) << "failed encoding catalog";
    return false;
  }

  //DLOG(INFO) << "Master: setting 'catalog.proto' at table " << meta_table->keyspace();
  auto tr = catalog_->torrent()->db().BeginTransaction(true);
  bool result = catalog_->torrent()->db().Put(tr.get(), meta_table->keyspace(), "catalog.proto", encoded_catalog);
  result ? tr->Commit() : tr->Rollback();
  if (!result) {
    DLOG(ERROR) << "Registry: failed while writing catalog int db";
    return false;
  }
  return true;
}

bool TreeCatalog::InitMetadata() {
  return catalog_->Init();
}

std::string TreeCatalog::FullName() const {
  return catalog_->FullName();
}

//Database* TreeCatalog::db() const {
//  return catalog_->db();
//}

BufferAllocator* TreeCatalog::allocator() const {
  return catalog_->allocator();
}

zetasql::TypeFactory* TreeCatalog::type_factory() {
  return catalog_->type_factory();
}

zetasql::Table* TreeCatalog::meta_table() const {
  return catalog_->meta_table();
}

google::protobuf::DynamicMessageFactory* TreeCatalog::message_factory() {
  return catalog_->message_factory();
}

google::protobuf::DescriptorPool* TreeCatalog::descriptor_pool() const {
  return catalog_->descriptor_pool();
}

bool TreeCatalog::Init() {
  return catalog_->Init();
}

zetasql_base::Status TreeCatalog::GetTable(
                      const std::string& name, 
                      const zetasql::Table** table,
                      const FindOptions& options) {
  return catalog_->GetTable(name, table, options);
}

zetasql_base::Status TreeCatalog::GetModel(const std::string& name, 
	const zetasql::Model** model, 
	const FindOptions& options) {
  return catalog_->GetModel(name, model, options);
}

zetasql_base::Status TreeCatalog::GetFunction(const std::string& name, 
	const zetasql::Function** function,
        const FindOptions& options) {
  return catalog_->GetFunction(name, function, options);
}

zetasql_base::Status TreeCatalog::GetTableValuedFunction(
    const std::string& name, const zetasql::TableValuedFunction** function,
    const FindOptions& options) {
  return catalog_->GetTableValuedFunction(name, function, options);
}

zetasql_base::Status TreeCatalog::GetProcedure(
    const std::string& name,
    const zetasql::Procedure** procedure,
    const FindOptions& options) {
  return catalog_->GetProcedure(name, procedure, options);
}

zetasql_base::Status TreeCatalog::GetType(const std::string& name, const zetasql::Type** type,
                      const FindOptions& options) {
  return catalog_->GetType(name, type, options);
}

zetasql_base::Status TreeCatalog::GetCatalog(const std::string& name, zetasql::Catalog** catalog,
                        const FindOptions& options) {
  return catalog_->GetCatalog(name, catalog, options);
}

zetasql_base::Status TreeCatalog::GetConstant(const std::string& name, const zetasql::Constant** constant,
                          const FindOptions& options) {
  return catalog_->GetConstant(name, constant, options);
}

std::string TreeCatalog::SuggestTable(const absl::Span<const std::string>& mistyped_path) {
  return catalog_->SuggestTable(mistyped_path);
}

std::string TreeCatalog::SuggestFunction(
    const absl::Span<const std::string>& mistyped_path) {
  return catalog_->SuggestFunction(mistyped_path);
}

std::string TreeCatalog::SuggestTableValuedFunction(
    const absl::Span<const std::string>& mistyped_path) {
  return catalog_->SuggestTableValuedFunction(mistyped_path);
}

std::string TreeCatalog::SuggestConstant(
    const absl::Span<const std::string>& mistyped_path) {
  return catalog_->SuggestConstant(mistyped_path);
}

void TreeCatalog::Shutdown(base::WaitableEvent* sync) {
  LOG(INFO) << "TreeCatalog::Close";
  if (!updating_index_) {
    Close();
    if (sync) {
      sync->Signal();
    }
    return;
  }
  base::ThreadTaskRunnerHandle::Get()->PostDelayedTask(
    FROM_HERE, 
    base::BindOnce(&TreeCatalog::Shutdown, weak_factory_.GetWeakPtr(), base::Unretained(sync)),
    base::TimeDelta::FromMilliseconds(200));
}

void TreeCatalog::Close() {
  catalog_->Close();
  closed_ = true;
}

std::unique_ptr<Block> TreeCatalog::Scan(const zetasql::ResolvedQueryStmt* scan_stmt) {
  return catalog_->Scan(scan_stmt);
}

std::unique_ptr<Cursor> TreeCatalog::CreateCursor(Transaction* tr, const std::string& table_name) {
  return catalog_->CreateCursor(tr, table_name);
}

std::unique_ptr<Transaction> TreeCatalog::BeginTransaction(bool write) {
  return catalog_->BeginTransaction(write);
}

std::unique_ptr<Iterator> TreeCatalog::NewIterator(const std::string& table_name) {
  return catalog_->NewIterator(table_name);
}

void TreeCatalog::Get(const std::string& table_name, base::StringPiece key, base::Callback<void(std::string, bool)> cb) {
  catalog_->Get(table_name, key, std::move(cb));
}

void TreeCatalog::Insert(const std::string& table_name, base::StringPiece key, base::StringPiece data, base::Callback<void(bool)> cb) {
  catalog_->Insert(table_name, key, data, std::move(cb));
}

void TreeCatalog::Insert(const std::string& table_name, base::StringPiece key, scoped_refptr<net::IOBufferWithSize> data, base::Callback<void(bool)> cb) {
  catalog_->Insert(table_name, key, data, std::move(cb));
}

void TreeCatalog::Remove(const std::string& table_name, base::StringPiece key, base::Callback<void(bool)> cb) {
  catalog_->Remove(table_name, key, std::move(cb));  
}

bool TreeCatalog::Get(const std::string& table_name, base::StringPiece key, std::string* value) {
  return catalog_->Get(table_name, key, value);
}

bool TreeCatalog::Insert(const std::string& table_name, base::StringPiece key, base::StringPiece data) {
  return catalog_->Insert(table_name, key, data);
}

bool TreeCatalog::InsertData(const std::string& table_name, base::StringPiece key, scoped_refptr<net::IOBufferWithSize> data) {
  return catalog_->InsertData(table_name, key, data);
}

bool TreeCatalog::Remove(const std::string& table_name, base::StringPiece key) {
  return catalog_->Remove(table_name, key);
}

void TreeCatalog::OnInfoHeaderChanged(const storage_proto::Info& info) {
  //catalog_->OnInfoHeaderChanged(info);
}

}
