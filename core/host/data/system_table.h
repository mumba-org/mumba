// Copyright (c) 2022 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_DATA_SYSTEM_TABLE_H_
#define MUMBA_HOST_DATA_SYSTEM_TABLE_H_

#include <string>

#include "base/macros.h"
#include "core/host/data/table.h"

namespace host {
class Workspace;
/*
 * Implementation of the virtual table for the system tables.
 * the system tables are actually backed by sqlite, but we are using the key-value mechanism
 * which goes directly over the in-disk (or in-memory) btree.
 *
 * The idea here is to abstract the key-value over the SQL interface in a way theres no need
 * for the user to know the inner implementation of the system tables and be able to use them
 * from a sql POV
 */

class SystemCursor : public Cursor {
public:
  SystemCursor();
  ~SystemCursor() override;

  int Close() override;
  int Filter(int index_num, const char *index_str, int argc, csqlite_value **argv) override;
  int Next() override;
  int Eof() override;
  int Column(csqlite_context*, int) override;
  int Rowid(csqlite_int64 *row_id) override;

private:

  DISALLOW_COPY_AND_ASSIGN(SystemCursor); 
};

class SystemTable : public Table {
public:
  SystemTable(const std::string& name, const std::vector<std::string>& fields);
  ~SystemTable() override;

  int version() const override;
  const std::string& name() const override;
  std::string create_table_sql() const override;
  std::unique_ptr<Cursor> Open() override;
  int BestIndex(csqlite_index_info*) override;
  int Disconnect() override;
  int Destroy() override;
  int Update(int, csqlite_value **, csqlite_int64 *) override;
  int Begin() override;
  int Sync() override;
  int Commit() override;
  int Rollback() override;
  int Rename(const std::string& name) override;
  int Savepoint(int) override;
  int Release(int) override;
  int RollbackTo(int) override;

private:
 scoped_refptr<Workspace> workspace_;
 int version_;
 std::string name_;
 std::vector<std::string> fields_;

 DISALLOW_COPY_AND_ASSIGN(SystemTable);
};

}

#endif