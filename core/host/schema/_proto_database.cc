// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/schema/schema_database.h"
#include "base/files/file_util.h"
#include "db/db.h"

namespace host {

SchemaDatabaseIterator::SchemaDatabaseIterator(std::unique_ptr<db::Transaction> trans, 
  std::unique_ptr<db::Cursor> cursor): 
    trans_(std::move(trans)),
    cursor_(std::move(cursor)),
    done_(false) {

}

SchemaDatabaseIterator::~SchemaDatabaseIterator() {
  trans_->Commit();
}

bool SchemaDatabaseIterator::Seek(const std::string& key) {
  DCHECK(key.size() > 0);
  bool match;
  int seek = cursor_->SeekTo(key, db::Seek::EQ, &match);
  return (seek == 0 || match);
}

base::StringPiece SchemaDatabaseIterator::Get() {
  return cursor_->GetData();
}

base::StringPiece SchemaDatabaseIterator::GetKey() {
  bool valid = false;
  db::KeyValuePair kv = db::DecodeKV(cursor_->GetData(), &valid);
  if (valid) {
    return kv.first;
  }
  return base::StringPiece();
}

base::StringPiece SchemaDatabaseIterator::GetValue() {
  bool valid = false;
  db::KeyValuePair kv = db::DecodeKV(cursor_->GetData(), &valid);
  if (valid) {
    return kv.second;
  }
  return base::StringPiece();
}

bool SchemaDatabaseIterator::HasNext() {
  return !cursor_->IsEof();
}

bool SchemaDatabaseIterator::Next() {
  bool has_next = !cursor_->IsEof();
  if (has_next) {
    cursor_->Next();
  } else {
    done_ = true;
  }
  return has_next && !done_;
}

void SchemaDatabaseIterator::First() {
  cursor_->First();
  if (done_)
   done_ = false;
}

void SchemaDatabaseIterator::Last() {
  cursor_->Last();
  done_ = true;
}

void SchemaDatabaseIterator::Previous() {
  cursor_->Previous();
  if (done_)
   done_ = false;
}

SchemaDatabase::SchemaDatabase(): 
  opened_(false) {
  
}

SchemaDatabase::~SchemaDatabase() {
  if (db_ && opened_) {
    db_->Close();
  }
}

bool SchemaDatabase::Open(const base::FilePath& path) {
  path_ = path;
  if (!base::PathExists(path)) {
    db_ = db::Create(path, kMaxTables);
  } else {
    db_ = db::Open(path, kMaxTables, false);
  }

  return opened_ = db_ ? true : false;
}

void SchemaDatabase::Close() {
  if (db_) {
    db_->Close();
    opened_ = false;
  }
}

std::unique_ptr<SchemaDatabaseIterator> SchemaDatabase::iterator() const {
  return std::make_unique<SchemaDatabaseIterator>(
    db_->BeginTransaction(false),
    db_->CreateCursor(false, kSchemaTable));
}

base::StringPiece SchemaDatabase::Get(const std::string& key) {
  base::StringPiece result;
  std::unique_ptr<db::Transaction> trans = db_->BeginTransaction(true);
  if (trans) {
    std::unique_ptr<db::Cursor> cursor = db_->CreateCursor(false, kSchemaTable);
    if (!cursor->GetValue(key, &result)) {
      LOG(ERROR) << "failed to get value for key " << key;
    }
    trans->Commit();
  }
  return result;
}

bool SchemaDatabase::Insert(const std::string& key, base::StringPiece data) {
  DCHECK(key.size() > 0);
  DCHECK(data.size() > 0);
  bool result = false;
  auto kv = std::make_pair(base::StringPiece(key), data);
  std::unique_ptr<db::Transaction> trans = db_->BeginTransaction(true);
  if (trans) {
    std::unique_ptr<db::Cursor> cursor = db_->CreateCursor(true, kSchemaTable);
    result = cursor->Insert(kv);
    if (result) {
      trans->Commit();
    } else {
      trans->Rollback();
    }
    return result;
  } else {
    LOG(ERROR) << "insert: failed to create transaction";
  }
  return result;
}

bool SchemaDatabase::Insert(const std::string& key, scoped_refptr<net::IOBufferWithSize> data) {
  return Insert(key, base::StringPiece(data->data(), data->size()));
}

bool SchemaDatabase::Remove(const std::string& key) {
  bool result = false;
  bool match = false;
  std::unique_ptr<db::Transaction> trans = db_->BeginTransaction(true);
  if (trans) {
    std::unique_ptr<db::Cursor> cursor = db_->CreateCursor(false, kSchemaTable);
    int seek = cursor->SeekTo(base::StringPiece(key), db::Seek::EQ, &match);
    if (seek == 0 || match) {
      result = cursor->Delete();
    }
    trans->Commit();
    return result;
  }
  return result;
}

}