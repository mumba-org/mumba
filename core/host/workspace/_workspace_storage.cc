// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/workspace/workspace_storage.h"

#include "core/host/workspace/database_storage.h"
#include "core/host/workspace/domain_storage.h"
#include "core/host/workspace/container_storage.h"

namespace host {

namespace {

const char kDATA_DIR[] = "data";
const char kCONTAINER_DIR[] = "containers";

}

WorkspaceStorage::WorkspaceStorage(const base::FilePath& root_dir): 
  root_dir_(root_dir),
  db_storage_(new DatabaseStorage(root_dir.AppendASCII(kDATA_DIR))),
  container_storage_(new ContainerStorage(root_dir.AppendASCII(kCONTAINER_DIR))),
  domain_storage_(new DomainStorage(root_dir.AppendASCII(kDOMAIN_DIR))) {

}

WorkspaceStorage::~WorkspaceStorage() {

}

const base::FilePath& WorkspaceStorage::volume_dir() const {
  return container_storage_->path();
}

const base::FilePath& WorkspaceStorage::domain_dir() const {
  return domain_storage_->path();
}

const base::FilePath& WorkspaceStorage::data_dir() const {
  return db_storage_->path();
}

bool WorkspaceStorage::Init() {
  if (IsEmpty()) {
    return Create();
  }

  // else we just need to load the databases
  return db_storage_->LoadDatabases();
}

void WorkspaceStorage::Shutdown() {
  db_storage_->UnloadDatabases();
}

bool WorkspaceStorage::Create() {
  if (!IsEmpty()) {
    return false;
  }

  return db_storage_->Create() && 
    container_storage_->Create() && 
    domain_storage_->Create();
}

bool WorkspaceStorage::IsEmpty() const {
  return db_storage_->IsEmpty() && 
    container_storage_->IsEmpty() && 
    domain_storage_->IsEmpty();
}

bool WorkspaceStorage::Empty() {
  if (IsEmpty()) {
    return true;
  }
  return db_storage_->Empty() && 
    container_storage_->Empty() && 
    domain_storage_->Empty();
}

size_t WorkspaceStorage::total_size() const {
  return db_storage_->total_size() + 
    container_storage_->total_size() +
    domain_storage_->total_size();
}

}