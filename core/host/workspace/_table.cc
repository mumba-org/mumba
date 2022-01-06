// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/workspace/table.h"

#include "core/host/workspace/database.h"
#include "db/db.h"

namespace host {

TableIterator::TableIterator(
  std::unique_ptr<db::Transaction> trans, 
  std::unique_ptr<db::Cursor> cursor): 
    trans_(std::move(trans)),
    cursor_(std::move(cursor)),
    done_(false) {

}

TableIterator::~TableIterator() {
  trans_->Commit();
}

bool TableIterator::Seek(const std::string& key) {
  DCHECK(key.size() > 0);
  bool match;
  int seek = cursor_->SeekTo(key, db::Seek::EQ, &match);
  return (seek == 0 || match);
}

base::StringPiece TableIterator::Get() {
  return cursor_->GetData();
}

base::StringPiece TableIterator::GetKey() {
  bool valid = false;
  db::KeyValuePair kv = db::DecodeKV(cursor_->GetData(), &valid);
  if (valid) {
    return kv.first;
  }
  return base::StringPiece();
}

base::StringPiece TableIterator::GetValue() {
  bool valid = false;
  db::KeyValuePair kv = db::DecodeKV(cursor_->GetData(), &valid);
  if (valid) {
    return kv.second;
  }
  return base::StringPiece();
}

bool TableIterator::HasNext() {
  return !cursor_->IsEof();
}

bool TableIterator::Next() {
  bool has_next = !cursor_->IsEof();
  if (has_next) {
    cursor_->Next();
  } else {
    done_ = true;
  }
  return has_next && !done_;
}

void TableIterator::First() {
  cursor_->First();
  if (done_)
   done_ = false;
}

void TableIterator::Last() {
  cursor_->Last();
  done_ = true;
}

void TableIterator::Previous() {
  cursor_->Previous();
  if (done_)
   done_ = false;
}

Table::Table(Database* db, size_t index, const std::string& name): 
  db_(db),
  index_(index), 
  name_(name) {

}

Table::~Table() {

}

// std::unique_ptr<TableIterator> Table::iterator(db::Context* db) const {
//   return std::make_unique<TableIterator>(
//     db->BeginTransaction(false),
//     db->CreateCursor(false, index_));
// }

void Table::Get(db::Context* db, base::StringPiece key, base::Callback<void(base::StringPiece, bool)> cb) {
  base::StringPiece data;
  bool result = true;
  std::unique_ptr<db::Transaction> trans = db->BeginTransaction(true);
  if (trans) {
    std::unique_ptr<db::Cursor> cursor = db->CreateCursor(false, index_);
    if (!cursor->GetValue(key, &data)) {
      LOG(ERROR) << "failed to get value for key " << key;
      result = false;
    }
    trans->Commit();
  }
  std::move(cb).Run(data, result);
}

void Table::Insert(db::Context* db, base::StringPiece key, base::StringPiece data, base::Callback<void(bool)> cb) {
  DCHECK(key.size() > 0);
  DCHECK(data.size() > 0);
  bool result = false;
  auto kv = std::make_pair(key, data);
  std::unique_ptr<db::Transaction> trans = db->BeginTransaction(true);
  if (trans) {
    std::unique_ptr<db::Cursor> cursor = db->CreateCursor(true, index_);
    result = cursor->Insert(kv);
    if (result) {
      trans->Commit();
    } else {
      trans->Rollback();
    }
    std::move(cb).Run(result);
    return;
  } else {
    LOG(ERROR) << "insert: failed to create transaction";
  }
  std::move(cb).Run(result);
}

void Table::InsertData(db::Context* db, base::StringPiece key, scoped_refptr<net::IOBufferWithSize> data, base::Callback<void(bool)> cb) {
  Insert(db, key, base::StringPiece(data->data(), data->size()), std::move(cb));
}

void Table::Remove(db::Context* db, base::StringPiece key, base::Callback<void(bool)> cb) {
  bool result = false;
  bool match = false;
  std::unique_ptr<db::Transaction> trans = db->BeginTransaction(true);
  if (trans) {
    std::unique_ptr<db::Cursor> cursor = db->CreateCursor(false, index_);
    int seek = cursor->SeekTo(key, db::Seek::EQ, &match);
    if (seek == 0 || match) {
      result = cursor->Delete();
    }
    trans->Commit();
    std::move(cb).Run(result);
    return;
  }
  std::move(cb).Run(result);
}

}