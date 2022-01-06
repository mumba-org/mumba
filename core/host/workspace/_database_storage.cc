// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/workspace/database_storage.h"

#include "base/bind.h"
#include "base/callback.h"
#include "base/location.h"
#include "base/files/file_util.h"
#include "base/files/file_enumerator.h"
#include "base/strings/utf_string_conversions.h"
#include "core/host/workspace/database.h"

namespace host {

namespace {
  void Noop(bool result) {}
}

DatabaseStorage::DatabaseStorage(const base::FilePath& path): 
  path_(path) {

}

DatabaseStorage::~DatabaseStorage() {

}

const base::FilePath& DatabaseStorage::path() const {
  return path_;
}

size_t DatabaseStorage::total_size() {
  return static_cast<size_t>(ComputeDirectorySize(path_));
}

bool DatabaseStorage::IsEmpty() const {
  return !base::DirectoryExists(path_);
}

bool DatabaseStorage::Empty() {
  return base::DeleteFile(path_, true);
}

bool DatabaseStorage::Create() {
  
  if (!base::CreateDirectory(path_)) {
    return false;
  }

  if (!LoadSystemDatabase(true)) {
    return false;
  }

  return true;
}

bool DatabaseStorage::LoadDatabases() {
  base::FileEnumerator databases(path_, false, base::FileEnumerator::FILES, FILE_PATH_LITERAL("*.db"));
  for (base::FilePath db_file = databases.Next(); !db_file.empty(); db_file = databases.Next()) {
    // TODO: max tables only work for system db. FIX
    std::unique_ptr<Database> db = std::make_unique<Database>();
    DLOG(INFO) << "opening  " << db_file << " with name '" << db_file.BaseName().RemoveExtension().value() << "'";
  
    //if (!db->Open(db_file, kMaxTables)) {
    //  LOG(ERROR) << "DatabaseStorage: failed to load DB file at '" << db_file << "'";
    //  continue;
    //}
    db->Open(db_file, kMaxTables, base::Bind(&Noop), true);
 #if defined(OS_WIN)   
    AddDatabase(base::UTF16ToASCII(db_file.BaseName().RemoveExtension().value()), std::move(db));
  #elif defined(OS_POSIX)
    AddDatabase(db_file.BaseName().RemoveExtension().value(), std::move(db));
   #endif 
  }
  LoadSystemDatabase(false);
  return true;
}

void DatabaseStorage::UnloadDatabases() {
  for (auto it = database_names_.begin(); it != database_names_.end(); ++it) {
    size_t index = it->second;
    databases_.erase(databases_.begin() + index);
    database_names_.erase(it);
  }
}

bool DatabaseStorage::CreateDatabase(const std::string& name) {
  base::FilePath db_file = path_.AppendASCII(name + ".db");
  std::unique_ptr<Database> db = std::make_unique<Database>();
  //if (!db->Open(db_file, kMaxTables)) {
  //  LOG(ERROR) << "DatabaseStorage: failed to create DB file at '" << db_file << "'";
  //  return false;
  //}
  db->Open(db_file, kMaxTables, base::Bind(&Noop), true);
  AddDatabase(name, std::move(db));
  return true;
}

void DatabaseStorage::AddDatabase(const std::string& name, std::unique_ptr<Database> db) {
  size_t index = databases_.size();
  database_names_.emplace(std::make_pair(name, index));
  databases_.insert(databases_.begin() + index, std::move(db));
}

void DatabaseStorage::RemoveDatabase(const std::string& name) {
  size_t index_to_delete = 0;
  bool found = false;
  auto name_it = database_names_.find(name);
  if (name_it != database_names_.end()) {
    index_to_delete = name_it->second;
    database_names_.erase(name_it);
    found = true;
  }
  if (found) {
    std::unique_ptr<Database> db = std::move(databases_[index_to_delete]);
    db->Close(true);
    db.reset();
    databases_.erase(databases_.begin() + index_to_delete);
  }
}

void DatabaseStorage::RemoveDatabaseAt(size_t index) {
  bool found = false;
  
  for (auto it = database_names_.begin(); it != database_names_.end(); ++it) {
    if (it->second == index) {
      found = true;
      database_names_.erase(it);
      break;
    }
  }

  if (found) {
    std::unique_ptr<Database> db = std::move(databases_[index]);
    db->Close(true);
    db.reset();
    databases_.erase(databases_.begin() + index);
  }
}

bool DatabaseStorage::LoadSystemDatabase(bool create) {
  if (create) {
    if (!CreateDatabase("system")) {
      return false;
    }
  }
  Database* db = database("system");
  if (!db) {
    return false;
  }
  // now add the tables
  db->SetTable(new Table(db, kDomainTable, "shell"));
  db->SetTable(new Table(db, kProtoTable, "proto"));
  db->SetTable(new Table(db, kContainerTable, "container"));
  db->SetTable(new Table(db, kContainerSourceTable, "source"));
  db->SetTable(new Table(db, kRecordTable, "record"));
  return true;
}

}