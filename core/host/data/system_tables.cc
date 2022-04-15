// Copyright (c) 2022 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/data/system_tables.h"

#include "core/host/share/share_database.h"
#include "storage/db/db.h"

namespace host {

SystemTables::SystemTables(): 
  db_(nullptr) {

  
}

SystemTables::~SystemTables() {
  
}

bool SystemTables::Init(storage::Database* db) {
  db_ = db;

  db->task_runner()->PostTask(
    FROM_HERE, 
    base::BindOnce(&SystemTables::InitOnDbThread, 
    base::Unretained(this)));
 
  return true;
}

void SystemTables::InitOnDbThread() {
  // domains
  tables_.push_back(SQLiteVTable::Create(db_, std::make_unique<SystemTable>("domain", std::vector<std::string>({"uuid", "name", "status"}))));
  // applications
  tables_.push_back(SQLiteVTable::Create(db_, std::make_unique<SystemTable>("application", std::vector<std::string>({"uuid", "domain", "name", "url", "initial_bounds", "window_mode", "window_disposition", "fullscreen", "headless"}))));
  // bundles
  tables_.push_back(SQLiteVTable::Create(db_, std::make_unique<SystemTable>("bundle", std::vector<std::string>({"uuid," "name", "path", "src_path", "size", "hash"}))));
  // repos
  tables_.push_back(SQLiteVTable::Create(db_, std::make_unique<SystemTable>("repo", std::vector<std::string>({"uuid", "type", "name", "address", "address_format", "address_format_version", "bytes public_key", "pk_crypto_format", "root_tree", "creator", "share_count"}))));
  // routes
  tables_.push_back(SQLiteVTable::Create(db_, std::make_unique<SystemTable>("route", std::vector<std::string>({"uuid", "name", "type", "transport_type", "rpc_method_type", "content_type", "title", "url", "fullname", "path", "content_size", "content_hash_sha1"}))));
  // services (rpc)
  tables_.push_back(SQLiteVTable::Create(db_, std::make_unique<SystemTable>("service", std::vector<std::string>({"uuid", "name", "type", "state", "custom_type", "id", "scheme", "version", "discoverable", "host", "port"}))));
  // shares  
  tables_.push_back(SQLiteVTable::Create(db_, std::make_unique<SystemTable>("share", std::vector<std::string>({"uuid", "name", "type", "state", "transport", "manifest", "creator", "domain", "address", "root_hash", "public_key", "pk_crypto_format", "piece_count", "piece_length", "size"}))));
  // schemas
  tables_.push_back(SQLiteVTable::Create(db_, std::make_unique<SystemTable>("schema", std::vector<std::string>({"id", "package", "name", "filename", "root_hash", "content", "content_lenght"}))));
  // identities
  tables_.push_back(SQLiteVTable::Create(db_, std::make_unique<SystemTable>("identity", std::vector<std::string>({"id", "name", "login", "description"}))));
  // workspace
  tables_.push_back(SQLiteVTable::Create(db_, std::make_unique<SystemTable>("workspace", std::vector<std::string>({"uuid," "name", "path", "status"}))));
}

}