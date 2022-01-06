// Copyright 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_STORAGE_TREE_CATALOG_H_
#define MUMBA_STORAGE_TREE_CATALOG_H_

#include <memory>

#include "base/macros.h"
#include "base/strings/string_piece.h"
#include "base/memory/ref_counted.h"
#include "base/memory/weak_ptr.h"
#include "base/single_thread_task_runner.h"
#include "base/synchronization/waitable_event.h"
#include "net/base/net_errors.h"
#include "storage/data_catalog.h"
#include "zetasql/public/catalog.h"
#include "storage/catalog.h"
#include "google/protobuf/descriptor.h"
#include "google/protobuf/dynamic_message.h"
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
#include "absl/types/span.h"

namespace storage {
class Database;
class DataTable;

class TreeCatalog : public Catalog {
public:
  static const char kKey[];

  static std::unique_ptr<TreeCatalog> Create(Torrent* torrent , scoped_refptr<base::SingleThreadTaskRunner> db_task_runner);
  static std::unique_ptr<TreeCatalog> Open(Torrent* torrent, scoped_refptr<base::SingleThreadTaskRunner> db_task_runner);

  TreeCatalog(Torrent* torrent, scoped_refptr<base::SingleThreadTaskRunner> db_task_runner);
  ~TreeCatalog();

  int AddEncodedIndex(base::StringPiece key, base::StringPiece data, const base::Callback<void(int64_t)>& callback);

  bool GetTable(const std::string& name, const DataTable** table);

  std::string FullName() const override;
//  Database* db() const;
  const storage_proto::Info& info() const override;
  BufferAllocator* allocator() const override;
  zetasql::TypeFactory* type_factory() override;
  zetasql::Table* meta_table() const override;
  google::protobuf::DynamicMessageFactory* message_factory() override;
  google::protobuf::DescriptorPool* descriptor_pool() const override;

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
  void Shutdown(base::WaitableEvent* sync);

  std::unique_ptr<Block> Scan(const zetasql::ResolvedQueryStmt* scan_stmt) override;
  template <class T> std::vector<std::unique_ptr<T>> ScanTable(const zetasql::ResolvedQueryStmt* scan_stmt);
  template <class T> std::vector<std::unique_ptr<T>> ScanTableAll(const std::string& table_name);

  std::unique_ptr<Cursor> CreateCursor(Transaction* tr, const std::string& table_name) override;
  std::unique_ptr<Transaction> BeginTransaction(bool write) override;

  std::unique_ptr<Iterator> NewIterator(const std::string& table_name) override;
  void Get(const std::string& table_name, base::StringPiece key, base::Callback<void(std::string, bool)> cb) override;
  void Insert(const std::string& table_name, base::StringPiece key, base::StringPiece data, base::Callback<void(bool)> cb) override;
  void Insert(const std::string& table_name, base::StringPiece key, scoped_refptr<net::IOBufferWithSize> data, base::Callback<void(bool)> cb) override;
  void Remove(const std::string& table_name, base::StringPiece key, base::Callback<void(bool)> cb) override;

  bool Get(const std::string& table_name, base::StringPiece key, std::string* value) override;
  bool Insert(const std::string& table_name, base::StringPiece key, base::StringPiece data) override;
  bool InsertData(const std::string& table_name, base::StringPiece key, scoped_refptr<net::IOBufferWithSize> data) override;
  bool Remove(const std::string& table_name, base::StringPiece key) override;

  void OnInfoHeaderChanged(const storage_proto::Info& info) override;
  
private:
  
  bool CreateMetadata();
  bool InitMetadata();

  void AddEncodedIndexOnDbThread(base::StringPiece key, base::StringPiece data, const base::Callback<void(int64_t)>& callback, scoped_refptr<base::SingleThreadTaskRunner> reply_to);

  std::unique_ptr<DataCatalog> catalog_;
  bool closed_;
  mutable bool updating_index_;
  std::string keyspace_;
  base::WaitableEvent db_event_;
  base::WeakPtrFactory<TreeCatalog> weak_factory_;
  
  DISALLOW_COPY_AND_ASSIGN(TreeCatalog);
};

template <class T> 
std::vector<std::unique_ptr<T>> TreeCatalog::ScanTable(const zetasql::ResolvedQueryStmt* scan_stmt) {
  return catalog_->ScanTable<T>(scan_stmt);
}

template <class T> std::vector<std::unique_ptr<T>> TreeCatalog::ScanTableAll(const std::string& table_name) {
  return catalog_->ScanTableAll<T>(table_name);
}

}

#endif
