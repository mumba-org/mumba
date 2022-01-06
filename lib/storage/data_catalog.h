// Copyright 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_STORAGE_DATA_CATALOG_
#define MUMBA_STORAGE_DATA_CATALOG_

#include <memory>
#include <string>
#include <unordered_map>

#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/synchronization/waitable_event.h"
#include "base/single_thread_task_runner.h"
#include "zetasql/public/catalog.h"
#include "storage/catalog.h"
#include "storage/data_table.h"
#include "storage/db/db.h"
#include "storage/torrent.h"
#include "google/protobuf/descriptor.h"
#include "google/protobuf/dynamic_message.h"
#include "google/protobuf/text_format.h"
#include "third_party/zetasql/public/builtin_function.h"
#include "third_party/zetasql/public/constant.h"
#include "third_party/zetasql/public/function.h"
#include "third_party/zetasql/public/procedure.h"
#include "third_party/zetasql/public/table_valued_function.h"
#include "third_party/zetasql/public/type.h"
#include "third_party/zetasql/public/value.h"
#include "third_party/zetasql/base/ret_check.h"
#include "third_party/zetasql/base/status.h"
#include "third_party/zetasql/public/analyzer.h"
#include "third_party/zetasql/resolved_ast/resolved_ast.h"
#include "storage/proto/storage.pb.h"
#include "storage/storage_export.h"
#include "absl/types/span.h"

namespace storage {
class BufferAllocator;
class Block;
class BlockRowWriter;
class Cursor;
class Transaction;
//class Storage;
class IOHandler;
class StorageEntry;

class STORAGE_EXPORT DataCatalog : public Catalog {
public:
  DataCatalog(scoped_refptr<Torrent> torrent,
              //const std::string& name, 
              scoped_refptr<base::SingleThreadTaskRunner> db_task_runner);

  //DataCatalog(storage_proto::Info info,
  //            const std::string& name, 
  //            scoped_refptr<base::SingleThreadTaskRunner> db_task_runner, 
  //            std::unique_ptr<Database> database);

  ~DataCatalog() override;

  std::string FullName() const override;

  //Database* db() const;

  void Open(base::Callback<void(bool)> cb, bool sync);
  void Create(base::Callback<void(bool)> cb, bool sync);
  void Close(bool sync);

  std::unique_ptr<Cursor> CreateCursor(Transaction* tr, const std::string& table_name) override;
  std::unique_ptr<Transaction> BeginTransaction(bool write) override;

  BufferAllocator* allocator() const override {
    return allocator_.get();
  }

  const storage_proto::Info& info() const override;

  zetasql::TypeFactory* type_factory() override { 
    return type_factory_.get(); 
  }

  zetasql::Table* meta_table() const override;

  google::protobuf::DynamicMessageFactory* message_factory() override {
    return &factory_;
  }

  google::protobuf::DescriptorPool* descriptor_pool() const override {
    return descriptor_pool_.get();
  }

  scoped_refptr<base::SingleThreadTaskRunner> db_task_runner() const {
    return db_task_runner_;
  }

  bool Init() override;
  
  zetasql_base::Status GetTable(const std::string& name, const zetasql::Table** table,
                        const FindOptions& options = FindOptions()) override;

  zetasql_base::Status GetModel(const std::string& name, const zetasql::Model** model,
                        const FindOptions& options = FindOptions()) override;

  zetasql_base::Status GetFunction(const std::string& name, const zetasql::Function** function,
                           const FindOptions& options = FindOptions()) override;

  zetasql_base::Status GetTableValuedFunction(
      const std::string& name, const zetasql::TableValuedFunction** function,
      const FindOptions& options = FindOptions()) override;

  zetasql_base::Status GetProcedure(
      const std::string& name,
      const zetasql::Procedure** procedure,
      const FindOptions& options = FindOptions()) override;

  zetasql_base::Status GetType(const std::string& name, const zetasql::Type** type,
                       const FindOptions& options = FindOptions()) override;

  zetasql_base::Status GetCatalog(const std::string& name, zetasql::Catalog** catalog,
                          const FindOptions& options = FindOptions()) override;

  zetasql_base::Status GetConstant(const std::string& name, const zetasql::Constant** constant,
                           const FindOptions& options = FindOptions()) override;

  std::string SuggestTable(const absl::Span<const std::string>& mistyped_path) override;
  std::string SuggestFunction(
      const absl::Span<const std::string>& mistyped_path) override;
  std::string SuggestTableValuedFunction(
      const absl::Span<const std::string>& mistyped_path) override;
  std::string SuggestConstant(
      const absl::Span<const std::string>& mistyped_path) override;

  void Close() override;

  void OnInfoHeaderChanged(const storage_proto::Info& info) override;

  // i know this is ammateurish, but is just for start
  std::unique_ptr<Block> Scan(const zetasql::ResolvedQueryStmt* scan_stmt) override;
  template <class T> std::vector<std::unique_ptr<T>> ScanTable(const zetasql::ResolvedQueryStmt* scan_stmt);
  template <class T> std::vector<std::unique_ptr<T>> ScanTableAll(const std::string& table_name);

  // most direct data accessors
  std::unique_ptr<Iterator> NewIterator(const std::string& table_name) override;
  void Get(const std::string& table_name, base::StringPiece key, base::Callback<void(std::string, bool)> cb) override;
  void Insert(const std::string& table_name, base::StringPiece key, base::StringPiece data, base::Callback<void(bool)> cb) override;
  void Insert(const std::string& table_name, base::StringPiece key, scoped_refptr<net::IOBufferWithSize> data, base::Callback<void(bool)> cb) override;
  void Remove(const std::string& table_name, base::StringPiece key, base::Callback<void(bool)> cb) override;

  bool Get(const std::string& table_name, base::StringPiece key, std::string* value) override;
  bool Insert(const std::string& table_name, base::StringPiece key, base::StringPiece data) override;
  bool InsertData(const std::string& table_name, base::StringPiece key, scoped_refptr<net::IOBufferWithSize> data) override;
  bool Remove(const std::string& table_name, base::StringPiece key) override;

  DataTable* GetTable(const std::string& table_name) const;

  const scoped_refptr<Torrent>& torrent() const { 
    return torrent_;
  }

private:
  friend class DataTable;  

  void OpenImpl(bool create, base::Callback<void(bool)> cb, base::WaitableEvent* do_sync);
  void CloseImpl(base::WaitableEvent* do_sync);

  bool LoadMetatables();
  bool LoadTables();

  //std::unique_ptr<Cursor> CreateCursor(bool write, const std::string& keyspace);

  void AddTable(std::unique_ptr<DataTable> table);

  void SetByFieldDescriptor(BlockRowWriter* writer, 
    const zetasql::Type* column_type, 
    const google::protobuf::FieldDescriptor* field, 
    const google::protobuf::Reflection* table, 
    const google::protobuf::Message* table_message) const;

  scoped_refptr<Torrent> torrent_;
  //storage_proto::Info info_;
  //std::string name_;
  //std::unique_ptr<Database> database_;
  storage_proto::CatalogMetadata catalog_proto_;
  std::unordered_map<std::string, std::unique_ptr<DataTable>> tables_;
  std::unique_ptr<zetasql::TypeFactory> type_factory_;
  std::unique_ptr<BufferAllocator> allocator_;
  std::unique_ptr<google::protobuf::DescriptorPool> descriptor_pool_;
  google::protobuf::DynamicMessageFactory factory_;
  scoped_refptr<base::SingleThreadTaskRunner> db_task_runner_;
  // pointer to the meta table. the table with the proto types for the other
  // tables in the database
  DataTable* meta_table_;
  bool opened_;

  DISALLOW_COPY_AND_ASSIGN(DataCatalog);
};
 
template <class T> 
std::vector<std::unique_ptr<T>> DataCatalog::ScanTable(const zetasql::ResolvedQueryStmt* stmt) {
  const zetasql::ResolvedTableScan* table_scan = nullptr;
  const zetasql::ResolvedProjectScan* project_scan = nullptr;
  std::vector<const zetasql::ResolvedNode*> scan_nodes;
  std::vector<std::unique_ptr<T>> result;

  stmt->GetDescendantsSatisfying(&zetasql::ResolvedNode::IsScan, &scan_nodes);
  
  for (auto const* scan : scan_nodes) {
    ////D//LOG(INFO) << "iterating over scan node '" << scan->node_kind_string() << "'";
    if (scan->node_kind() == zetasql::RESOLVED_TABLE_SCAN) {
      table_scan = scan->GetAs<zetasql::ResolvedTableScan>();
    } else if (scan->node_kind() == zetasql::RESOLVED_PROJECT_SCAN) {
      project_scan = scan->GetAs<zetasql::ResolvedProjectScan>(); 
    }
  }
  
  if (!table_scan || !project_scan) {
    //D//LOG(INFO) << "theres no table or project scan on query. aborting";
    return {};
  }
  
  const DataTable* table = static_cast<const DataTable *>(table_scan->table());

  const  google::protobuf::Message* table_prototype = factory_.GetPrototype(table->descriptor());
  Transaction* trans = torrent_->db().Begin(false);
  Cursor* cursor = trans->CreateCursor(table->keyspace());
  cursor->First();
  while (cursor->IsValid()) { // for each row
    google::protobuf::Message* table_message = table_prototype->New(nullptr);
    bool valid = false;
    KeyValuePair kv = DbDecodeKV(cursor->GetData(), &valid);
    if (!table_message->ParseFromArray(kv.second.data(), kv.second.size())) {
      //D//LOG(INFO) << "oops. problem parsing row. raw data (" << kv.second.size() << "):\n'" << kv.second.as_string() << "'";
      delete table_message;
      cursor->Next();
      continue;    
    }

    // We will not do any filtering for now

    //for (auto const& column : column_list) {
    //  const zetasql::Type* column_type = column.type();
    //  const google::protobuf::FieldDescriptor* proto_field = table->descriptor()->FindFieldByName(column.name());
    //  if (!proto_field) { 
    //    //D//LOG(INFO) << "oops. " << column.name() << " was not found in the descriptor";
    //    delete table_message;
    //    cursor->Next();
    //    continue;
    //  }
    //  SetByFieldDescriptor(&writer, column_type, proto_field, table_descr, table_message);
    //}
    result.push_back(std::unique_ptr<T>(static_cast<T *>(table_message)));
    cursor->Next();
  }

  trans->Commit();
  
  return result;
}

template <class T> 
std::vector<std::unique_ptr<T>> DataCatalog::ScanTableAll(const std::string& table_name) {
  std::vector<std::unique_ptr<T>> result;
  auto it = tables_.find(table_name);
  if (it == tables_.end()) {
    //D//LOG(INFO) << "theres no table "  << table_name << ". aborting";
    return {};
  }
  const DataTable* table = it->second.get();
  const  google::protobuf::Message* table_prototype = factory_.GetPrototype(table->descriptor());
  Transaction* trans = torrent_->db().Begin(false);
  Cursor* cursor = trans->CreateCursor(table->keyspace());
  cursor->First();
  while (cursor->IsValid()) { // for each row
    google::protobuf::Message* table_message = table_prototype->New(nullptr);
    bool valid = false;
    KeyValuePair kv = DbDecodeKV(cursor->GetData(), &valid);
    if (!table_message->ParseFromArray(kv.second.data(), kv.second.size())) {
      //D//LOG(INFO) << "oops. problem parsing row. raw data (" << kv.second.size() << "):\n'" << kv.second.as_string() << "'";
      delete table_message;
      cursor->Next();
      continue;
    }
    // temporary..
    std::string text;
    if (google::protobuf::TextFormat::PrintToString(*table_message, &text)) {
      printf("---*---\n%s\n---*---\n", text.c_str());
    }
    result.push_back(std::unique_ptr<T>(static_cast<T *>(table_message)));
    cursor->Next();
  }

  trans->Commit();
  
  return result;
}

}

#endif