// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_NAMESPACE_SQLITE_DATABASE_BACKEND_H_
#define MUMBA_DOMAIN_NAMESPACE_SQLITE_DATABASE_BACKEND_H_

#include "base/macros.h"
#include "base/files/file_path.h"
#include "base/callback.h"
#include "base/single_thread_task_runner.h"
#include "core/shared/domain/storage/database_backend.h"

namespace domain {

class ParquetDatabaseBackend : public DatabaseBackend {
public:
  ParquetDatabaseBackend(int db_id, const base::FilePath& path, bool in_memory);
  ~ParquetDatabaseBackend() override;

  bool in_memory() const override;

  void Initialize(const base::Callback<void(int, int)>& callback) override;
  void Shutdown() override;

  void CheckDatabase(const base::Callback<void(int)>& callback) override;

private:

  int InitializeImpl();
  int CheckDatabaseImpl();
  void ShutdownImpl();

  int db_id_;

  base::FilePath path_;

  bool in_memory_;

  //scoped_refptr<base::SequencedTaskRunner> background_task_runner_;

  bool connected_;

  DISALLOW_COPY_AND_ASSIGN(ParquetDatabaseBackend);
};

}

#endif