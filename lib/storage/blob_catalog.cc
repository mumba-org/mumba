// Copyright 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "storage/blob_catalog.h"
#include "storage/db/db.h"
#include "storage/backend/storage_entry.h"

namespace storage {

BlobCatalog::BlobCatalog(
  const std::string& name, 
  StorageEntry* entry): 
  name_(name),
  entry_(entry) {

}

BlobCatalog::~BlobCatalog() {
  
}

bool BlobCatalog::Init() {
  return true;
}

zetasql_base::Status BlobCatalog::GetTable(
  const std::string& name, 
  const zetasql::Table** table,
  const FindOptions& options) {
  return zetasql_base::Status();
}

zetasql_base::Status BlobCatalog::GetModel(
  const std::string& name, 
  const zetasql::Model** model,
  const FindOptions& options) {
  return zetasql_base::Status();
}

zetasql_base::Status BlobCatalog::GetFunction(
  const std::string& name, 
  const zetasql::Function** function,
  const FindOptions& options) {
  return zetasql_base::Status();
}

zetasql_base::Status BlobCatalog::GetTableValuedFunction(
  const std::string& name, 
  const zetasql::TableValuedFunction** function,
  const FindOptions& options) {
  return zetasql_base::Status();
}

zetasql_base::Status BlobCatalog::GetProcedure(
  const std::string& name,
  const zetasql::Procedure** procedure,
  const FindOptions& options) { 
  return zetasql_base::Status();
}

zetasql_base::Status BlobCatalog::GetType(
  const std::string& name, 
  const zetasql::Type** type,
  const FindOptions& options) {
  return zetasql_base::Status();
}

zetasql_base::Status BlobCatalog::GetCatalog(
  const std::string& name, 
  zetasql::Catalog** catalog,
  const FindOptions& options) {
  return zetasql_base::Status();
}

zetasql_base::Status BlobCatalog::GetConstant(
  const std::string& name, 
  const zetasql::Constant** constant,
  const FindOptions& options) {
  return zetasql_base::Status();
}

std::string BlobCatalog::SuggestTable(const absl::Span<const std::string>& mistyped_path) {
  return std::string();
}

std::string BlobCatalog::SuggestFunction(const absl::Span<const std::string>& mistyped_path)  {
  return std::string();
}

std::string BlobCatalog::SuggestTableValuedFunction(const absl::Span<const std::string>& mistyped_path)  {
  return std::string();
}

std::string BlobCatalog::SuggestConstant(const absl::Span<const std::string>& mistyped_path) {
  return std::string();
}

void BlobCatalog::Close() {
  entry_->Close();
}

}