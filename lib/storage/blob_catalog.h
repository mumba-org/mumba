// Copyright 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_STORAGE_BLOB_CATALOG_
#define MUMBA_STORAGE_BLOB_CATALOG_

#include <memory>
#include <string>

#include "base/macros.h"
#include "zetasql/public/catalog.h"
#include "storage/catalog.h"
#include "google/protobuf/descriptor.h"
#include "zetasql/public/builtin_function.h"
#include "zetasql/public/constant.h"
#include "zetasql/public/function.h"
#include "zetasql/public/procedure.h"
#include "zetasql/public/table_valued_function.h"
#include "zetasql/public/type.h"
#include "zetasql/public/value.h"
#include "zetasql/base/ret_check.h"
#include "zetasql/base/status.h"
#include "storage/storage_export.h"
#include "absl/types/span.h"

namespace storage {
class StorageEntry;

class STORAGE_EXPORT BlobCatalog : public Catalog {
public:
  BlobCatalog(const std::string& name, StorageEntry* entry);
  ~BlobCatalog() override;

  std::string FullName() const override { return name_; }

  bool Init() override;

  zetasql_base::Status GetTable(const std::string& name, const zetasql::Table** table,
                        const FindOptions& options = FindOptions()) override;

  zetasql_base::Status GetModel(const std::string& name, const zetasql::Model** model,
                        const FindOptions& options = FindOptions()) override;

  zetasql_base::Status GetFunction(const std::string& name, const zetasql::Function** function,
                           const FindOptions& options = FindOptions()) override;

  zetasql_base::Status GetTableValuedFunction(
      const std::string& name, const zetasql::TableValuedFunction** function,
      const FindOptions& options = FindOptions()) override;

  zetasql_base::Status GetProcedure(
      const std::string& name,
      const zetasql::Procedure** procedure,
      const FindOptions& options = FindOptions()) override;

  zetasql_base::Status GetType(const std::string& name, const zetasql::Type** type,
                       const FindOptions& options = FindOptions()) override;

  zetasql_base::Status GetCatalog(const std::string& name, zetasql::Catalog** catalog,
                          const FindOptions& options = FindOptions()) override;

  zetasql_base::Status GetConstant(const std::string& name, const zetasql::Constant** constant,
                           const FindOptions& options = FindOptions()) override;

  std::string SuggestTable(const absl::Span<const std::string>& mistyped_path) override;
  std::string SuggestFunction(
      const absl::Span<const std::string>& mistyped_path) override;
  std::string SuggestTableValuedFunction(
      const absl::Span<const std::string>& mistyped_path) override;
  std::string SuggestConstant(
      const absl::Span<const std::string>& mistyped_path) override;

  void Close() override;

private:
  std::string name_;
  StorageEntry* entry_;

  DISALLOW_COPY_AND_ASSIGN(BlobCatalog);
};

}

#endif