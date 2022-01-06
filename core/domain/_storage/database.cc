// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/domain/storage/database.h"

#include "core/shared/domain/storage/parquet/parquet_database_backend.h"

namespace domain {

Database::Database(int id, const base::FilePath& db_path, bool in_memory):
  id_(id),
  state_(kUndefined),
  backend_(new ParquetDatabaseBackend(id, db_path, in_memory)) {
}

Database::~Database() {

}

bool Database::in_memory() const {
  return backend_->in_memory();
}

void Database::Initialize(const base::Callback<void(int, int)>& result) {
  backend_->Initialize(result);
}

void Database::Shutdown() {
  backend_->Shutdown();
}

}