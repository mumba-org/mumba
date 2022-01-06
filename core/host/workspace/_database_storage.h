// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_WORKSPACE_DATABASE_STORAGE_H_
#define MUMBA_HOST_WORKSPACE_DATABASE_STORAGE_H_

#include <memory>
#include <map>

#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/files/file_path.h"
#include "base/strings/string_piece.h"
#include "net/base/io_buffer.h"
//#include "db/db.h"
#include "core/host/workspace/table.h"
#include "core/host/workspace/storage_layer.h"

namespace host {
class Database;

class DatabaseStorage : public StorageLayer {
public:
  
  enum SystemTables {
    kDomainTable = 0,
    kProtoTable = 1,
    kContainerTable = 2,
    kContainerSourceTable = 3,
    kRecordTable = 4,
    kMaxTables = 5
  };

  DatabaseStorage(const base::FilePath& path);
  ~DatabaseStorage() override;

  size_t database_count() const {
    return databases_.size();
  }

  bool HasDatabase(const std::string& name) const {
    auto it = database_names_.find(name);
    if (it == database_names_.end()) {
      return false;
    }
    return true;
  }

  Database* database(size_t index) const {
    DCHECK(index < database_count());
    return databases_[index].get();
  }

  Database* database(const std::string& name) const {
    auto it = database_names_.find(name);
    if (it == database_names_.end()) {
      return nullptr;
    }
    return databases_[it->second].get();
  }

  bool LoadDatabases();
  void UnloadDatabases();
  bool CreateDatabase(const std::string& name);
  void AddDatabase(const std::string& name, std::unique_ptr<Database> db);
  void RemoveDatabase(const std::string& name);
  void RemoveDatabaseAt(size_t index);

  const base::FilePath& path() const override;
  size_t total_size() override;
  bool Create() override;
  bool IsEmpty() const override;
  bool Empty() override;
  
private:
  
  bool LoadSystemDatabase(bool create);

  base::FilePath path_;

  std::map<std::string, size_t> database_names_;

  std::vector<std::unique_ptr<Database>> databases_;

  DISALLOW_COPY_AND_ASSIGN(DatabaseStorage);
};

}

#endif
