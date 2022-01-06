// Copyright 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_STORAGE_CATALOG_
#define MUMBA_STORAGE_CATALOG_

#include <memory>
#include <string>

#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "net/base/io_buffer.h"
#include "third_party/zetasql/public/catalog.h"
#include "storage/proto/storage.pb.h"
#include "storage/io_entity.h"
#include "storage/storage_export.h"
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
#include "absl/types/span.h"

namespace storage {
class Database;
class BufferAllocator;
class Block;
class Cursor;
class Transaction;
class Iterator;

class STORAGE_EXPORT Catalog : public zetasql::Catalog,
                               public IOEntity {
public:
  virtual ~Catalog() {}
  virtual BufferAllocator* allocator() const = 0;
  virtual zetasql::TypeFactory* type_factory() = 0;
  virtual zetasql::Table* meta_table() const = 0;
  virtual google::protobuf::DynamicMessageFactory* message_factory() = 0;
  virtual google::protobuf::DescriptorPool* descriptor_pool() const = 0;
  virtual bool Init() = 0;
  virtual void Close() = 0;
  virtual std::unique_ptr<Cursor> CreateCursor(Transaction* tr, const std::string& table_name) = 0;
  virtual std::unique_ptr<Transaction> BeginTransaction(bool write) = 0;
  virtual std::unique_ptr<Iterator> NewIterator(const std::string& table_name) = 0;
  virtual void Get(const std::string& table_name, base::StringPiece key, base::Callback<void(std::string, bool)> cb) = 0;
  virtual void Insert(const std::string& table_name, base::StringPiece key, base::StringPiece data, base::Callback<void(bool)> cb) = 0;
  virtual void Insert(const std::string& table_name, base::StringPiece key, scoped_refptr<net::IOBufferWithSize> data, base::Callback<void(bool)> cb) = 0;
  virtual void Remove(const std::string& table_name, base::StringPiece key, base::Callback<void(bool)> cb) = 0;
  virtual bool Get(const std::string& table_name, base::StringPiece key, std::string* value) = 0;
  virtual bool Insert(const std::string& table_name, base::StringPiece key, base::StringPiece data) = 0;
  virtual bool InsertData(const std::string& table_name, base::StringPiece key, scoped_refptr<net::IOBufferWithSize> data) = 0;
  virtual bool Remove(const std::string& table_name, base::StringPiece key) = 0;
  virtual std::unique_ptr<Block> Scan(const zetasql::ResolvedQueryStmt* scan_stmt) = 0;
};

}

#endif