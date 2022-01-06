// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_WORKSPACE_DATABASE_H_
#define MUMBA_HOST_WORKSPACE_DATABASE_H_

#include <memory>
#include <map>

#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/files/file_path.h"
#include "base/strings/string_piece.h"
#include "base/single_thread_task_runner.h"
#include "base/synchronization/waitable_event.h"
#include "net/base/io_buffer.h"
#include "db/db.h"
#include "core/host/workspace/table.h"

namespace host {
class Database;
class Table;

class DatabaseContext : public base::RefCountedThreadSafe<DatabaseContext> {
public:
  DatabaseContext(Database* db, scoped_refptr<base::SingleThreadTaskRunner> io_task_runner, db::Context* context);

  scoped_refptr<base::SingleThreadTaskRunner> io_task_runner() const {
    return io_task_runner_;
  }
  
  std::unique_ptr<TableIterator> GetIterator(const std::string& table_name);

  void Get(const std::string& table_name, base::StringPiece key, base::Callback<void(base::StringPiece, bool)> cb);
  void Insert(const std::string& table_name, base::StringPiece key, base::StringPiece data, base::Callback<void(bool)> cb);
  void Insert(const std::string& table_name, base::StringPiece key, scoped_refptr<net::IOBufferWithSize> data, base::Callback<void(bool)> cb);
  void Remove(const std::string& table_name, base::StringPiece key, base::Callback<void(bool)> cb);

private:
  friend class base::RefCountedThreadSafe<DatabaseContext>;
  friend class Database;
  
  //std::unique_ptr<db::Cursor> CreateCursor(scoped_refptr<Table> table, bool write);
  //std::unique_ptr<db::Transaction> BeginTransaction(bool write);

  ~DatabaseContext();

  void Closing();

  scoped_refptr<Table> GetTable(const std::string& table_name);

  base::Lock db_lock_;

  Database* db_;

  db::Context* context_;

  scoped_refptr<base::SingleThreadTaskRunner> io_task_runner_;

  DISALLOW_COPY_AND_ASSIGN(DatabaseContext);
};

class Database {
public:
  Database();
  ~Database();

  void Open(const base::FilePath& path, size_t table_count, base::Callback<void(bool)> cb, bool sync);
  void Close(bool sync);

  scoped_refptr<DatabaseContext> context() const {
    return context_;
  }

  scoped_refptr<Table> table(size_t index) const {
    DCHECK(index < tables_.size());
    return tables_[index];
  }

  scoped_refptr<Table> table(const std::string& name) const {
    auto found = table_names_.find(name);
    if (found == table_names_.end()) {
      return {};
    }
    return tables_[found->second];
  }

  void SetTable(scoped_refptr<Table> table);

private:

  void OpenImpl(base::Callback<void(bool)> cb, base::WaitableEvent* do_sync);
  void CloseImpl(base::WaitableEvent* do_sync);

  base::FilePath path_;

  size_t table_count_;

  scoped_refptr<DatabaseContext> context_;
  
  std::unique_ptr<db::Context> db_;

  std::map<std::string, int> table_names_;

  std::vector<scoped_refptr<Table>> tables_;

  bool opened_;

  scoped_refptr<base::SingleThreadTaskRunner> io_task_runner_;
  
  DISALLOW_COPY_AND_ASSIGN(Database);
};

}

#endif
