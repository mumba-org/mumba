// Copyright 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_STORAGE_BLOB_TABLE_
#define MUMBA_STORAGE_BLOB_TABLE_

#include <memory>
#include <string>

#include "base/macros.h"
#include "storage/storage_export.h"
#include "zetasql/public/catalog.h"
#include "zetasql/base/status.h"

namespace storage {
class StorageEntry;

class STORAGE_EXPORT BlobTable : public zetasql::Table {
public:
  BlobTable(StorageEntry* entry, const std::string& name);
  ~BlobTable() override;

  std::string Name() const override;
  std::string FullName() const override;

  int NumColumns() const override;
  const zetasql::Column* GetColumn(int i) const override;

  const zetasql::Column* FindColumnByName(const std::string& name) const override;
  bool IsValueTable() const override;
  int64_t GetSerializationId() const override;

  zetasql_base::StatusOr<std::unique_ptr<zetasql::EvaluatorTableIterator>>
   CreateEvaluatorTableIterator(absl::Span<const int> column_idxs) const override;
  
private:
  StorageEntry* entry_;
  std::string name_;

  DISALLOW_COPY_AND_ASSIGN(BlobTable);
};

}

#endif