// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/share/share_database.h"
#include "storage/db/db.h"
#include "storage/torrent.h"

namespace host {

scoped_refptr<ShareDatabase> ShareDatabase::Open(Delegate* delegate) {
  storage::Database* db = storage::Database::Open(delegate->torrent());
  return new ShareDatabase(delegate, db, false);
}

scoped_refptr<ShareDatabase> ShareDatabase::Create(Delegate* delegate, const std::vector<std::string>& keyspaces) {
  storage::Database* db = storage::Database::Create(delegate->torrent(), keyspaces);
  return new ShareDatabase(delegate, db, false);  
}

// static 
scoped_refptr<ShareDatabase> ShareDatabase::CreateMemory(Delegate* delegate, const std::vector<std::string>& keyspaces) {
  std::unique_ptr<storage::Database> db = storage::Database::CreateMemory(keyspaces);
  return new ShareDatabase(delegate, std::move(db), true);
}

ShareDatabase::ShareDatabase(
  Delegate* delegate, 
  std::unique_ptr<storage::Database> db,
  bool in_memory): 
    delegate_(delegate),
    owned_impl_(std::move(db)),
    type_(ShareDatabaseType::kKEY_VALUE),
    in_memory_(in_memory) {
  impl_ = owned_impl_.get();
}

ShareDatabase::ShareDatabase(Delegate* delegate, storage::Database* db, bool in_memory): 
  delegate_(delegate),
  impl_(db),
  type_(ShareDatabaseType::kKEY_VALUE),
  in_memory_(in_memory) {

}

ShareDatabase::~ShareDatabase() {

}

bool ShareDatabase::CreateTables(const std::vector<std::string>& keyspaces) {
  return impl_->CreateTables(keyspaces);
}

bool ShareDatabase::Init() {
  return impl_->Init();
}

void ShareDatabase::Open() {
  delegate_->OpenDatabaseSync();
}

void ShareDatabase::Close() {
  return impl_->Close(); 
}

storage::Transaction* ShareDatabase::Begin(bool write) {
  return impl_->Begin(write);
}

storage::Transaction* ShareDatabase::BeginRead() {
  return impl_->BeginRead();
}

storage::Transaction* ShareDatabase::BeginWrite() {
  return impl_->BeginWrite();
}

bool ShareDatabase::Get(storage::Transaction* tr, const std::string& keyspace, base::StringPiece key, std::string* value) {
  return impl_->Get(tr, keyspace, key, value);
}

bool ShareDatabase::Put(storage::Transaction* tr, const std::string& keyspace, base::StringPiece key, base::StringPiece value) {
  return impl_->Put(tr, keyspace, key, value); 
}

bool ShareDatabase::Delete(storage::Transaction* tr, const std::string& keyspace, base::StringPiece key) {
  return impl_->Delete(tr, keyspace, key);  
}

bool ShareDatabase::EraseAll(storage::Transaction* tr) {
  return impl_->EraseAll(tr);   
}

bool ShareDatabase::Check() {
  return impl_->Check();     
}

int ShareDatabase::CountItems(storage::Transaction* tr, const std::string& keyspace) {
  return impl_->Count(tr, keyspace);
}

bool ShareDatabase::CreateKeyspace(const std::string& keyspace) {
  return impl_->CreateKeyspace(keyspace);
}

bool ShareDatabase::DropKeyspace(const std::string& keyspace) {
  return impl_->DropKeyspace(keyspace);
}

void ShareDatabase::GetKeyspaceList(std::vector<std::string>* out, bool include_hidden) {
  impl_->GetKeyspaceList(out, include_hidden);
}

bool ShareDatabase::ExecuteStatement(const std::string& stmt) {
  return impl_->ExecuteStatement(stmt); 
}

bool ShareDatabase::Checkpoint(int* result_code) {
  return impl_->Checkpoint(result_code);   
}

bool ShareDatabase::readonly() const {
  return impl_->readonly();   
}

bool ShareDatabase::is_closed() const {
  return impl_->is_closed();
}

const base::UUID& ShareDatabase::id() const {
  return impl_->id();
}

int ShareDatabase::table_count() const {
  return impl_->table_count();
}

}