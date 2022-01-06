// Copyright 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_STORAGE_DATA_TABLE_
#define MUMBA_STORAGE_DATA_TABLE_

#include <memory>
#include <string>

#include "base/macros.h"
#include "zetasql/public/catalog.h"
#include "zetasql/base/status.h"
#include "net/base/net_errors.h"
#include "net/base/io_buffer.h"
#include "storage/proto/storage.pb.h"
#include "storage/storage_export.h"
#include "third_party/zetasql/public/analyzer.h"
#include "third_party/zetasql/resolved_ast/resolved_ast.h"
#include "third_party/protobuf/src/google/protobuf/descriptor.h"
#include "third_party/protobuf/src/google/protobuf/descriptor.pb.h"

namespace storage {
class Database;
class DataCatalog;
class DataColumn;
class Block;
class Schema;
class BlockRowWriter;
class Transaction;
class Cursor;

class STORAGE_EXPORT Iterator {
public:
  Iterator(std::unique_ptr<Transaction> trans, std::unique_ptr<Cursor> cursor);
  ~Iterator();

  bool Seek(const std::string& key);
  base::StringPiece Get();
  base::StringPiece GetKey();
  base::StringPiece GetValue();
  bool HasNext();
  bool Next();
  void First();
  void Last();
  void Previous();

private:
  std::unique_ptr<Transaction> trans_;
  std::unique_ptr<Cursor> cursor_;
  bool done_;

  DISALLOW_COPY_AND_ASSIGN(Iterator);
};

class STORAGE_EXPORT DataTable : public zetasql::Table {
public:
  DataTable(DataCatalog* catalog, 
            const std::string& name,
            std::unique_ptr<Schema> schema,
            const google::protobuf::Descriptor* descriptor,
            const std::string& keyspace,
            int table_index);
  
  DataTable(DataCatalog* catalog);

  ~DataTable() override;

  std::string Name() const override;
  std::string FullName() const override;

  int NumColumns() const override;
  const zetasql::Column* GetColumn(int i) const override;
  int NumRows() const {
    return row_count_;
  }

  const zetasql::Column* FindColumnByName(const std::string& name) const override;
  bool IsValueTable() const override;
  int64_t GetSerializationId() const override;

  zetasql_base::StatusOr<std::unique_ptr<zetasql::EvaluatorTableIterator>>
   CreateEvaluatorTableIterator(absl::Span<const int> column_idxs) const override;

  bool Deserialize(const storage_proto::Table& table);

  const Schema& schema() const { return *schema_; }

  bool readonly() const { return readonly_; }

  const google::protobuf::Descriptor* descriptor() const {
    return descriptor_;
  }

  int table_index() const {
    return table_index_;
  }

  const std::string& keyspace() const {
    return keyspace_;
  }

  void Get(base::StringPiece key, base::Callback<void(std::string, bool)> cb);
  void Insert(base::StringPiece key, base::StringPiece data, base::Callback<void(bool)> cb);
  void InsertData(base::StringPiece key, scoped_refptr<net::IOBufferWithSize> data, base::Callback<void(bool)> cb);
  void Remove(base::StringPiece key, base::Callback<void(bool)> cb);

  bool GetSync(base::StringPiece key, std::string* value);
  bool InsertSync(base::StringPiece key, base::StringPiece data);
  bool InsertDataSync(base::StringPiece key, scoped_refptr<net::IOBufferWithSize> data);
  bool RemoveSync(base::StringPiece key);
  
private:

  void AddColumn(std::unique_ptr<DataColumn> column);
  
  bool DeserializeDescriptor(const storage_proto::Table& table);

  DataCatalog* catalog_;
  std::string name_;
  std::unordered_map<std::string, int> columns_offset_;
  std::unique_ptr<Schema> schema_;
  const google::protobuf::Descriptor* descriptor_;
  const google::protobuf::FileDescriptor* file_proto_;
  std::vector<std::unique_ptr<DataColumn>> columns_;
  //std::string table_proto_;
  size_t row_count_;
  bool readonly_;
  std::string keyspace_;
  int table_index_;
  int column_offset_;
  bool valid_;

  DISALLOW_COPY_AND_ASSIGN(DataTable);
};


}

#endif