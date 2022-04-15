// Copyright (c) 2022 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/data/system_table.h"

#include "core/host/workspace/workspace.h"

namespace host {

SystemCursor::SystemCursor() {
  
}

SystemCursor::~SystemCursor() {

}

int SystemCursor::Close() {
  return 0;
}

int SystemCursor::Filter(int index_num, const char *index_str, int argc, csqlite_value **argv) {
  DLOG(INFO) << "SystemCursor::Filter";
  return 0;
}

int SystemCursor::Next() {
  DLOG(INFO) << "SystemCursor::Next";
  return 0;
}

int SystemCursor::Eof() {
  DLOG(INFO) << "SystemCursor::Eof";
  return 0;
}

int SystemCursor::Column(csqlite_context*, int) {
  DLOG(INFO) << "SystemCursor::Column";
  return 0;
}

int SystemCursor::Rowid(csqlite_int64 *row_id) {
  DLOG(INFO) << "SystemCursor::Rowid";
  return 0;
}

SystemTable::SystemTable(const std::string& name, const std::vector<std::string>& fields): 
  version_(0), 
  name_(name),
  fields_(fields) {

}

SystemTable::~SystemTable() {

}

int SystemTable::version() const {
  return version_;
}

const std::string& SystemTable::name() const {
  return name_;
}

std::string SystemTable::create_table_sql() const {
  std::string field_list;
  size_t count = 0;
  for (const auto& field : fields_) {
    std::string field_desc;
    field_desc = count < (fields_.size() - 1) ? field + "," : field;
    field_list += field_desc;
    count++;
  }
  return "CREATE TABLE " + name_ + "(" + field_list + ")";
}

std::unique_ptr<Cursor> SystemTable::Open() {
  DLOG(INFO) << "SystemTable::Open";
  return std::make_unique<SystemCursor>();
}

int SystemTable::BestIndex(csqlite_index_info*) {
  DLOG(INFO) << "SystemTable::BestIndex";
  return 0;
}

int SystemTable::Disconnect() {
  DLOG(INFO) << "SystemTable::Disconnect";
  return 0;
}

int SystemTable::Destroy() {
  DLOG(INFO) << "SystemTable::Destroy";
  return 0;
}

int SystemTable::Update(int, csqlite_value **, csqlite_int64 *) {
  DLOG(INFO) << "SystemTable::Update";
  return 0;
}

int SystemTable::Begin() {
  DLOG(INFO) << "SystemTable::Begin";
  return 0;
}

int SystemTable::Sync() {
  DLOG(INFO) << "SystemTable::Sync";
  return 0;
}

int SystemTable::Commit() {
  DLOG(INFO) << "SystemTable::Commit";
  return 0;
}

int SystemTable::Rollback() {
  DLOG(INFO) << "SystemTable::Rollback";
  return 0;
}

int SystemTable::Rename(const std::string& name) {
  DLOG(INFO) << "SystemTable::Rename";
  return 0;
}

int SystemTable::Savepoint(int) {
  DLOG(INFO) << "SystemTable::Savepoint";
  return 0;
}

int SystemTable::Release(int) {
  DLOG(INFO) << "SystemTable::Release";
  return 0;
}

int SystemTable::RollbackTo(int) {
  DLOG(INFO) << "SystemTable::RollbackTo";
  return 0;
}

}