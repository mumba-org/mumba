// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_WORKSPACE_TABLE_H_
#define MUMBA_HOST_WORKSPACE_TABLE_H_

#include <memory>

#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/files/file_path.h"
#include "base/strings/string_piece.h"
#include "net/base/io_buffer.h"
#include "db/db.h"
#include "core/host/workspace/table.h"

namespace host {
class Database;
class DatabaseContext;

class TableIterator {
public:
  TableIterator(std::unique_ptr<db::Transaction> trans, std::unique_ptr<db::Cursor> cursor);
  ~TableIterator();

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

  DISALLOW_COPY_AND_ASSIGN(TableIterator);
};

class Table : public base::RefCountedThreadSafe<Table> {
public:
  Table(Database* db, size_t index, const std::string& name);

  size_t index() const {
    return index_;
  }

  const std::string& name() const {
    return name_;
  }

  //std::unique_ptr<TableIterator> iterator(db::Context* db) const;
  void Get(db::Context* db, base::StringPiece key, base::Callback<void(base::StringPiece, bool)> cb);
  void Insert(db::Context* db, base::StringPiece key, base::StringPiece data, base::Callback<void(bool)> cb);
  void InsertData(db::Context* db, base::StringPiece key, scoped_refptr<net::IOBufferWithSize> data, base::Callback<void(bool)> cb);
  void Remove(db::Context* db, base::StringPiece key, base::Callback<void(bool)> cb);

private:
  friend class base::RefCountedThreadSafe<Table>;

  ~Table();
  
  Database* db_;
  size_t index_;
  std::string name_;

  DISALLOW_COPY_AND_ASSIGN(Table);
};

}

#endif
