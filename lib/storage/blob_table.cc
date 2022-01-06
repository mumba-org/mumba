// Copyright 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "storage/blob_table.h"
#include "storage/backend/storage_entry.h"

namespace storage {

BlobTable::BlobTable(StorageEntry* entry, const std::string& name):
  entry_(entry),
  name_(name) {

}

BlobTable::~BlobTable() {
  // 
  entry_ = nullptr;
}

std::string BlobTable::Name() const {
  return name_;
}

std::string BlobTable::FullName() const {
  return name_;
}

int BlobTable::NumColumns() const {
  return 0;
}

const zetasql::Column* BlobTable::GetColumn(int i) const {
  return nullptr;
}

const zetasql::Column* BlobTable::FindColumnByName(const std::string& name) const {
  return nullptr;
}

bool BlobTable::IsValueTable() const {
  return true;
}

int64_t BlobTable::GetSerializationId() const {
  return 0;
}

zetasql_base::StatusOr<std::unique_ptr<zetasql::EvaluatorTableIterator>>
  BlobTable::CreateEvaluatorTableIterator(absl::Span<const int> column_idxs) const {
    return zetasql_base::Status();
}

}