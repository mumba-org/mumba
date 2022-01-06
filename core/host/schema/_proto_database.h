// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_SCHEMA_SCHEMA_DATABASE_H_
#define MUMBA_HOST_SCHEMA_SCHEMA_DATABASE_H_

#include <memory>

#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "db/db.h"
#include "base/uuid.h"
#include "net/base/io_buffer.h"

namespace host {

class SchemaDatabaseIterator {
public:
  SchemaDatabaseIterator(std::unique_ptr<db::Transaction> trans, std::unique_ptr<db::Cursor> cursor);
  ~SchemaDatabaseIterator();

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
  
  std::unique_ptr<db::Transaction> trans_;
  std::unique_ptr<db::Cursor> cursor_;
  bool done_;

  DISALLOW_COPY_AND_ASSIGN(SchemaDatabaseIterator);
};

class SchemaDatabase {
public:
  
  enum Tables {
    kSchemaTable = 0,
    kMaxTables = 1
  };
  
  SchemaDatabase();
  ~SchemaDatabase();

  bool Open(const base::FilePath& path);
  void Close();

  std::unique_ptr<SchemaDatabaseIterator> iterator() const;
  base::StringPiece Get(const std::string& key);
  bool Insert(const std::string& key, base::StringPiece data);
  bool Insert(const std::string& key, scoped_refptr<net::IOBufferWithSize> data);
  bool Remove(const std::string& key);

private:

 bool opened_;
 base::FilePath path_;
 std::unique_ptr<db::Context> db_;

 DISALLOW_COPY_AND_ASSIGN(SchemaDatabase);
};

}

#endif