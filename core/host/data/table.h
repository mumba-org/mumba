// Copyright (c) 2022 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_DATA_TABLE_H_
#define MUMBA_HOST_DATA_TABLE_H_

#include <memory>

#include "base/macros.h"
#include "base/uuid.h"
#include "base/strings/string_piece.h"
#include "base/synchronization/lock.h"
#include "core/host/serializable.h"
#include "core/common/proto/objects.pb.h"
#include "storage/storage.h"
#include "storage/db/sqlite3.h"
#include "storage/db/db.h"
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wsign-compare"
#pragma clang diagnostic ignored "-Wignored-qualifiers"
#include "third_party/zetasql/parser/parse_tree.h"
#include "third_party/zetasql/parser/ast_node_kind.h"
#include "third_party/zetasql/parser/parser.h"
#include "third_party/zetasql/public/parse_resume_location.h"
#include "third_party/zetasql/base/status.h"
#pragma clang diagnostic pop

struct sqlite_vcursor;
struct sqlite_vtab;

namespace host {
class SQLiteVTable;

/*
 * An abstract pure virtual cursor that is a interface to the sqlite virtual cursor
 */

class Cursor {
public:
  virtual ~Cursor() = default;
  virtual int Close() = 0;
  virtual int Filter(int index_num, const char *index_str, int argc, csqlite_value **argv) = 0;
  virtual int Next() = 0;
  virtual int Eof() = 0;
  virtual int Column(csqlite_context*, int) = 0;
  virtual int Rowid(csqlite_int64 *row_id) = 0;
};

/*
 * An abstract pure virtual table that is a interface to the sqlite virtual table
 */

class Table {
public:
  virtual ~Table() = default;
  virtual int version() const = 0;
  virtual const std::string& name() const = 0;
  virtual std::string create_table_sql() const = 0;
  virtual std::unique_ptr<Cursor> Open() = 0;
  virtual int BestIndex(csqlite_index_info*) = 0;
  virtual int Disconnect() = 0;
  virtual int Destroy() = 0;
  virtual int Update(int, csqlite_value **, csqlite_int64 *) = 0;
  virtual int Begin() = 0;
  virtual int Sync() = 0;
  virtual int Commit() = 0;
  virtual int Rollback() = 0;
  virtual int Rename(const std::string& name) = 0;
  virtual int Savepoint(int) = 0;
  virtual int Release(int) = 0;
  virtual int RollbackTo(int) = 0;
};

// internal impl that wraps the abstract table and glue with the sqlite virtual table interface
// this is what the system uses to perform the actions
class SQLiteVCursor {
public:
  class Delegate {
  public:
    virtual ~Delegate() = default;
    virtual void OnClose(SQLiteVCursor* cursor) = 0;
  };
  static std::unique_ptr<SQLiteVCursor> Open(SQLiteVTable* vtable, std::unique_ptr<Cursor> cursor);
  
  SQLiteVCursor(SQLiteVTable* vtable, sqlite_vcursor* handle, std::unique_ptr<Cursor> cursor);
  ~SQLiteVCursor() = default;

  SQLiteVTable* vtable() const {
    return vtable_;
  }
  
  sqlite_vcursor* handle() const {
    return handle_;
  }

  int Close(csqlite_vtab_cursor*);
  int Filter(csqlite_vtab_cursor*, int idx_num, const char *idx_str, int argc, csqlite_value **argv);
  int Next(csqlite_vtab_cursor*);
  int Eof(csqlite_vtab_cursor*);
  int Column(csqlite_vtab_cursor*, csqlite_context*, int);
  int Rowid(csqlite_vtab_cursor*, csqlite_int64 *row_id); 

private:

  SQLiteVTable* vtable_;
  sqlite_vcursor* handle_;
  std::unique_ptr<Cursor> cursor_;
  
  DISALLOW_COPY_AND_ASSIGN(SQLiteVCursor);
};

// this register itself as the vtable handler and uses the user provided table to actually deliver the methods

class SQLiteVTable : public SQLiteVCursor::Delegate {
public:
  static std::unique_ptr<SQLiteVTable> Create(storage::Database* db, std::unique_ptr<Table> vtable);
  
  SQLiteVTable(storage::Database* db, std::unique_ptr<Table> vtable);
  ~SQLiteVTable() = default;

  storage::Database* db() const {
    return db_;
  }

  sqlite_vtab* handle() const {
    return handle_;
  }

  void set_handle(sqlite_vtab* handle) {
    handle_ = handle;
  }

  Table* table() const {
    return user_table_.get();
  }  

   // sqlite vtable callbacks
  //int Create(csqlite*, void *pAux, int argc, const char *const*argv, csqlite_vtab **tab, char**);
  //int Connect(csqlite*, void *pAux, int argc, const char *const*argv, csqlite_vtab **tab, char**);
  int BestIndex(csqlite_vtab *tab, csqlite_index_info*);
  int Disconnect(csqlite_vtab *tab);
  int Destroy(csqlite_vtab *tab);
  int Open(csqlite_vtab *tab, csqlite_vtab_cursor **cursor);
  int Update(csqlite_vtab *, int, csqlite_value **, csqlite_int64 *);
  int Begin(csqlite_vtab *tab);
  int Sync(csqlite_vtab *tab);
  int Commit(csqlite_vtab *tab);
  int Rollback(csqlite_vtab *tab);
  int FindFunction(csqlite_vtab *tab, int argc, const char *name,
                   void (**func)(csqlite_context*,int,csqlite_value**),
                   void **args);
  int Rename(csqlite_vtab *tab, const char *znew);
  int Savepoint(csqlite_vtab *tab, int);
  int Release(csqlite_vtab *tab, int);
  int RollbackTo(csqlite_vtab *tab, int);

private:

  void OnClose(SQLiteVCursor* cursor) override;

  storage::Database* db_;
  sqlite_vtab* handle_;
  std::unique_ptr<Table> user_table_;
  std::vector<std::unique_ptr<SQLiteVCursor>> cursors_; 
  csqlite_module callbacks_;
  
  DISALLOW_COPY_AND_ASSIGN(SQLiteVTable);
};

}

#endif