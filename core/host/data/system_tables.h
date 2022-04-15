// Copyright (c) 2022 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_DATA_SYSTEM_TABLES_H_
#define MUMBA_HOST_DATA_SYSTEM_TABLES_H_

#include "base/macros.h"
#include "core/host/data/system_table.h"
#include "core/host/data/table.h"

namespace host {

// a manager of the basic system tables
// this is to be owned by workspaces and binded at the main
// system database

class SystemTables {
public:
  SystemTables();
  ~SystemTables();
  
  bool Init(storage::Database* db);

private:

  void InitOnDbThread();

  storage::Database* db_;
  std::vector<std::unique_ptr<SQLiteVTable>> tables_;

  DISALLOW_COPY_AND_ASSIGN(SystemTables);
};

}

#endif