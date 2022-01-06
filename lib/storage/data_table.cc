// Copyright 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "storage/data_table.h"
#include "storage/data_catalog.h"
#include "storage/data_column.h"
#include "storage/db/db.h"
#include "storage/block.h"
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

namespace storage {

namespace {

class SingleFileErrorCollector : public google::protobuf::io::ErrorCollector {
 public:
  SingleFileErrorCollector(const std::string& filename)
    : filename_(filename),
      had_errors_(false) {}
  ~SingleFileErrorCollector() {}

  bool had_errors() { return had_errors_; }

  // implements ErrorCollector ---------------------------------------
  void AddError(int line, int column, const std::string& message) override {
    DLOG(ERROR) << "error: line " << line << " col " << column << ": " << message;
    had_errors_ = true;
  }

 private:
  std::string filename_;
  bool had_errors_;
};

}

Iterator::Iterator(
  std::unique_ptr<Transaction> trans, 
  std::unique_ptr<Cursor> cursor): 
    trans_(std::move(trans)),
    cursor_(std::move(cursor)),
    done_(false) {

}

Iterator::~Iterator() {
  trans_->Commit();
}

bool Iterator::Seek(const std::string& key) {
  DCHECK(key.size() > 0);
  bool match;
  int seek = cursor_->SeekTo(key, Seek::EQ, &match);
  return (seek == 0 || match);
}

base::StringPiece Iterator::Get() {
  return cursor_->GetData();
}

base::StringPiece Iterator::GetKey() {
  bool valid = false;
  KeyValuePair kv = DbDecodeKV(cursor_->GetData(), &valid);
  if (valid) {
    return kv.first;
  }
  return base::StringPiece();
}

base::StringPiece Iterator::GetValue() {
  bool valid = false;
  KeyValuePair kv = DbDecodeKV(cursor_->GetData(), &valid);
  if (valid) {
    return kv.second;
  }
  return base::StringPiece();
}

bool Iterator::HasNext() {
  return !cursor_->IsEof();
}

bool Iterator::Next() {
  bool has_next = !cursor_->IsEof();
  if (has_next) {
    cursor_->Next();
  } else {
    done_ = true;
  }
  return has_next && !done_;
}

void Iterator::First() {
  cursor_->First();
  if (done_)
   done_ = false;
}

void Iterator::Last() {
  cursor_->Last();
  done_ = true;
}

void Iterator::Previous() {
  cursor_->Previous();
  if (done_)
   done_ = false;
}

DataTable::DataTable(
  DataCatalog* catalog, 
  const std::string& name,
  std::unique_ptr<Schema> schema,
  const google::protobuf::Descriptor* descriptor,
  const std::string& keyspace,
  int table_index):
    catalog_(catalog),
    name_(name),
    schema_(std::move(schema)), 
    descriptor_(descriptor), 
    file_proto_(nullptr),
    row_count_(0),
    readonly_(false),
    keyspace_(keyspace),
    table_index_(table_index),
    valid_(true) {
  
  //BufferAllocator* allocator = catalog_->allocator();
  //DCHECK(allocator);
  //for (size_t i = 0; i < schema->count(); ++i) {
  //  columns_[i].Init(allocator, schema->Get(i), initial_rows);
  //}

}

DataTable::DataTable(DataCatalog* catalog):
  catalog_(catalog),
  schema_(nullptr),
  descriptor_(nullptr),
  file_proto_(nullptr),
  row_count_(0),
  readonly_(true),
  table_index_(-1),
  valid_(false) {

}

DataTable::~DataTable() {
  // just to silence warnings of "not using"
  catalog_ = nullptr;
  table_index_ = -1 ;
}

std::string DataTable::Name() const {
  return name_;
}

std::string DataTable::FullName() const {
  return name_;
}

int DataTable::NumColumns() const {
  return schema_->count();
}

const zetasql::Column* DataTable::GetColumn(int i) const {
  if (i > (NumColumns() -1)) {
    return nullptr;
  }
  return columns_[i].get();
}

const zetasql::Column* DataTable::FindColumnByName(const std::string& name) const {
  auto it = columns_offset_.find(name);
  if (it != columns_offset_.end()) {
    return columns_[it->second].get();
  }
  return nullptr;
}

bool DataTable::IsValueTable() const {
  return false;
}

int64_t DataTable::GetSerializationId() const {
  return 0;
}

zetasql_base::StatusOr<std::unique_ptr<zetasql::EvaluatorTableIterator>>
  DataTable::CreateEvaluatorTableIterator(absl::Span<const int> column_idxs) const {
    //D//LOG(INFO) << "DataTable::CreateEvaluatorTableIterator";
    return zetasql_base::Status();
}

bool DataTable::Deserialize(const storage_proto::Table& table) {
  name_ = table.name();
  table_index_ = table.index();
  keyspace_ = table.keyspace();
  readonly_ = table.readonly();
  //table_proto_ = table.proto();

  schema_ = std::make_unique<Schema>();
  
  if (!schema_->Deserialize(catalog_->type_factory(), table)) {
    return false;
  }

  if (!DeserializeDescriptor(table)) {
    return false;
  }

  for (const auto& column_proto : table.column()) {
    auto column = std::make_unique<DataColumn>();
    if (!column->Deserialize(catalog_->type_factory(), column_proto)) {
      return false;
    }
    AddColumn(std::move(column));
  }
  valid_ = true;
  return true;
}

void DataTable::Get(base::StringPiece key, base::Callback<void(std::string, bool)> cb) {
  base::StringPiece data;
  bool result = true;
  std::unique_ptr<Transaction> trans = catalog_->BeginTransaction(true);
  if (trans) {
    std::unique_ptr<Cursor> cursor = catalog_->CreateCursor(trans.get(), keyspace_);
    result = cursor->GetValue(key, &data);
    if (!result) {
      LOG(ERROR) << "failed to get value for key " << key;
    }
  }
  std::move(cb).Run(data.as_string(), result);
  result ? trans->Commit() : trans->Rollback();
}

void DataTable::Insert(base::StringPiece key, base::StringPiece data, base::Callback<void(bool)> cb) {
  DCHECK(key.size() > 0);
  DCHECK(data.size() > 0);
  bool result = false;
  auto kv = std::make_pair(key, data);
  std::unique_ptr<Transaction> trans = catalog_->BeginTransaction(true);
  if (trans) {
    std::unique_ptr<Cursor> cursor = catalog_->CreateCursor(trans.get(), keyspace_);
    cursor->Insert(kv) ? trans->Commit() : trans->Rollback();
    std::move(cb).Run(result);
    return;
  } else {
    LOG(ERROR) << "insert: failed to create transaction";
  }
  std::move(cb).Run(result);
}

void DataTable::InsertData(base::StringPiece key, scoped_refptr<net::IOBufferWithSize> data, base::Callback<void(bool)> cb) {
  Insert(key, base::StringPiece(data->data(), data->size()), std::move(cb));
}

void DataTable::Remove(base::StringPiece key, base::Callback<void(bool)> cb) {
  bool result = false;
  bool match = false;
  std::unique_ptr<Transaction> trans = catalog_->BeginTransaction(true);
  if (trans) {
    std::unique_ptr<Cursor> cursor = catalog_->CreateCursor(trans.get(), keyspace_);
    int seek = cursor->SeekTo(key, Seek::EQ, &match);
    if (seek == 0 || match) {
      result = cursor->Delete();
    }
    result ? trans->Commit() : trans->Rollback();
    std::move(cb).Run(result);
    return;
  }
  std::move(cb).Run(result);
}

bool DataTable::GetSync(base::StringPiece key, std::string* value) {
  bool result = false;
  std::unique_ptr<Transaction> trans = catalog_->BeginTransaction(false);
  if (trans) {
    base::StringPiece data_view;
    std::unique_ptr<Cursor> cursor = catalog_->CreateCursor(trans.get(), keyspace_);
    result = cursor->GetValue(key, &data_view);
    if (result) {
      data_view.CopyToString(value);
    }
    result ? trans->Commit() : trans->Rollback();
  }
  return result;
}

bool DataTable::InsertSync(base::StringPiece key, base::StringPiece data) {
  bool result = false;
  auto kv = std::make_pair(key, data);
  std::unique_ptr<Transaction> trans = catalog_->BeginTransaction(true);
  if (trans) {
    std::unique_ptr<Cursor> cursor = catalog_->CreateCursor(trans.get(), keyspace_);
    result = cursor->Insert(kv);
    result ? trans->Commit() : trans->Rollback();
    return result;
  } else {
    LOG(ERROR) << "insert: failed to create transaction";
  }
  return result;
}

bool DataTable::InsertDataSync(base::StringPiece key, scoped_refptr<net::IOBufferWithSize> data) {
  return InsertSync(key, base::StringPiece(data->data(), data->size()));
} 

bool DataTable::RemoveSync(base::StringPiece key) {
  bool result = false;
  bool match = false;
  std::unique_ptr<Transaction> trans = catalog_->BeginTransaction(true);
  if (trans) {
    std::unique_ptr<Cursor> cursor = catalog_->CreateCursor(trans.get(), keyspace_);
    int seek = cursor->SeekTo(key, Seek::EQ, &match);
    if (seek == 0 || match) {
      result = cursor->Delete();
    }
    result ? trans->Commit() : trans->Rollback();
    return result;
  } 
  return result;
}

void DataTable::AddColumn(std::unique_ptr<DataColumn> column) {
  std::string column_name = column->Name();
  columns_offset_.emplace(std::move(column_name), column_offset_);
  columns_.push_back(std::move(column));
  column_offset_++;
}


bool DataTable::DeserializeDescriptor(const storage_proto::Table& table) {
  // this should be temporary
  if (table.proto().empty()) {
    return true;
  }
  // build the FileDescriptor 
  google::protobuf::io::ArrayInputStream input(table.proto().data(), table.proto().size());
  SingleFileErrorCollector file_error_collector("_");
  google::protobuf::io::Tokenizer tokenizer(&input, &file_error_collector);
  google::protobuf::compiler::Parser parser;
 
  google::protobuf::FileDescriptorProto file_proto;
  file_proto.set_name(table.name());
  if (!parser.Parse(&tokenizer, &file_proto)) {
    DLOG(ERROR) << "error parsing table proto\n" << table.proto();
    return false;
  }

  if (table.table_descriptor_name().empty()) {
    return false;
  }

  file_proto_ = catalog_->descriptor_pool()->BuildFile(file_proto);
  descriptor_ = file_proto_->FindMessageTypeByName(table.table_descriptor_name());//message_type(1); 
  return descriptor_ != nullptr;
}


}