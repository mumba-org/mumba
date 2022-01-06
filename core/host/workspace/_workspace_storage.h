// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_WORKSPACE_WORKSPACE_STORAGE_H_
#define MUMBA_HOST_WORKSPACE_WORKSPACE_STORAGE_H_

#include <string>
#include <memory>

#include "base/macros.h"
#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/files/file_path.h"
#include "base/strings/string_piece.h"

namespace host {
class DatabaseStorage;
class ContainerStorage;
class DomainStorage;
/*
 * Deal with the storage backend of a given Workspace
 */
class WorkspaceStorage {
public:
  WorkspaceStorage(const base::FilePath& root_dir);
  ~WorkspaceStorage();

  const base::FilePath& root_dir() const {
    return root_dir_;
  }

  const base::FilePath& volume_dir() const;
  const base::FilePath& domain_dir() const;
  const base::FilePath& data_dir() const;

  // all databases. at least one: "system"
  DatabaseStorage* db_storage() const {
    return db_storage_.get();
  }

  // the directory for container repos
  ContainerStorage* container_storage() const {
    return container_storage_.get();
  }

  // the directory for shell repos
  DomainStorage* domain_storage() const {
    return domain_storage_.get();
  }

  size_t total_size() const;

  // generic init. will trigger create of empty
  bool Init();
  void Shutdown();
    // to be called in the first run. IsEmpty() must be true
  bool Create();
  bool IsEmpty() const;
  bool Empty();

private:

  base::FilePath root_dir_;
  std::unique_ptr<DatabaseStorage> db_storage_;
  std::unique_ptr<ContainerStorage> container_storage_;
  std::unique_ptr<DomainStorage> domain_storage_;
  
  DISALLOW_COPY_AND_ASSIGN(WorkspaceStorage);
};

}

#endif