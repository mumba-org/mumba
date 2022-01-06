// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/domain/storage/parquet/parquet_database_backend.h"

#include "base/bind.h"
#include "base/task_scheduler/post_task.h"
#include "base/threading/thread_task_runner_handle.h"
#include "base/sequenced_task_runner.h"
#include "base/task_scheduler/post_task.h"
#include "net/base/net_errors.h"
#include "core/domain/domain_thread.h"

namespace domain {

ParquetDatabaseBackend::ParquetDatabaseBackend(
  int db_id,
  const base::FilePath& path, 
  bool in_memory):
 db_id_(db_id),
 path_(path),
 in_memory_(in_memory),
 //db_(nullptr),
 //background_task_runner_(
 // base::CreateSequencedTaskRunnerWithTraits(
 //           { base::MayBlock(), 
 //             base::TaskPriority::BACKGROUND })),
 connected_(false) {

}

ParquetDatabaseBackend::~ParquetDatabaseBackend() {
  
}

bool ParquetDatabaseBackend::in_memory() const {
  return in_memory_;
}

void ParquetDatabaseBackend::Initialize(const base::Callback<void(int, int)>& callback) {
  base::PostTaskWithTraitsAndReplyWithResult(
    FROM_HERE,
    { base::MayBlock() },
    base::Bind(&ParquetDatabaseBackend::InitializeImpl, base::Unretained(this)),
    base::Bind(callback, db_id_));
}

void ParquetDatabaseBackend::Shutdown() {

  if (!connected_) {
    return;
  }

  base::PostTaskWithTraits(
    FROM_HERE,
    { base::MayBlock() },
    base::BindOnce(&ParquetDatabaseBackend::ShutdownImpl, 
      base::Unretained(this)));
}

void ParquetDatabaseBackend::CheckDatabase(const base::Callback<void(int)>& callback) {
  base::PostTaskWithTraitsAndReplyWithResult(
    FROM_HERE,
    { base::MayBlock() },
    base::BindOnce(&ParquetDatabaseBackend::CheckDatabaseImpl, base::Unretained(this)),
    base::BindOnce(callback));
}

int ParquetDatabaseBackend::InitializeImpl() {
 return 0;
}

void ParquetDatabaseBackend::ShutdownImpl() {
}

int ParquetDatabaseBackend::CheckDatabaseImpl() {
  return 0;
}

}
