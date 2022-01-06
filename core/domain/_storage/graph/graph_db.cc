// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/domain/storage/graph/graph_db.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/stat.h>
#include <unistd.h>
#include "base/task_scheduler/post_task.h"
#include "core/domain/domain_thread.h"

namespace domain {

std::unique_ptr<GraphDb> GraphDb::Open(int id, const base::FilePath& path, bool in_memory) {
  return std::make_unique<GraphDb>(id, path, in_memory);
}

GraphDb::GraphDb(int id, const base::FilePath& path, bool in_memory): 
  id_(id),
  path_(path),
  in_memory_(in_memory),
  graph_db_(nullptr),
  background_task_runner_(
      base::CreateSingleThreadTaskRunnerWithTraits(
        { base::MayBlock(), 
          base::TaskPriority::BACKGROUND })),
  open_(false) {

 }

GraphDb::~GraphDb() {
  if (open_) {
    ShutdownImpl();
  }
}
  
void GraphDb::Initialize(const base::Callback<void(int)>& callback) {
 //base::PostTaskWithTraitsAndReplyWithResult(
  base::PostTaskAndReplyWithResult(
    background_task_runner_.get(),
    FROM_HERE,
  //  { base::MayBlock() },
    base::BindOnce(&GraphDb::InitializeImpl, base::Unretained(this)),
    base::BindOnce(callback));
}

void GraphDb::Shutdown() {
  background_task_runner_->PostTask(
  //base::PostTaskWithTraits(
    FROM_HERE,
  //  { base::MayBlock() },
    base::BindOnce(&GraphDb::ShutdownImpl,
      base::Unretained(this)));
}

void GraphDb::Count(const base::Callback<void(size_t)>& callback) const {
  background_task_runner_->PostTask(
  //base::PostTaskWithTraits(
  FROM_HERE,
  //  { base::MayBlock() },
    base::BindOnce(&GraphDb::CountImpl,
      base::Unretained(this),
      callback));
}

GraphDbTransaction GraphDb::Begin(bool write) const {
  //DCHECK(background_task_runner_ == base::ThreadTaskRunner::Get());
  // TODO: check flags
  graph_txn_t handle = graph_txn_begin(graph_db_, nullptr, write ? 0 : DB_RDONLY);
  return GraphDbTransaction(handle);
}

void GraphDb::Sync(bool force) {
  background_task_runner_->PostTask(
  //base::PostTaskWithTraits(
    FROM_HERE,
  //  { base::MayBlock() },
    base::BindOnce(&GraphDb::SyncImpl,
      base::Unretained(this),
      force));
}

void GraphDb::Updated() {
  background_task_runner_->PostTask(
  //base::PostTaskWithTraits(
    FROM_HERE,
  //  { base::MayBlock() },
    base::BindOnce(&GraphDb::UpdatedImpl,
      base::Unretained(this)));
}

void GraphDb::Remap() {
  background_task_runner_->PostTask(
  //base::PostTaskWithTraits(
    FROM_HERE,
  //  { base::MayBlock() },
    base::BindOnce(&GraphDb::RemapImpl,
      base::Unretained(this)));
}

void GraphDb::Execute(const base::Callback<void(GraphDbTransaction*)>& batch, bool write) const {
  background_task_runner_->PostTask(
  //base::PostTaskWithTraits(
  FROM_HERE,
  //  { base::MayBlock() },
    base::BindOnce(&GraphDb::ExecuteImpl,
      base::Unretained(this),
      batch,
      write));
}

int GraphDb::InitializeImpl() {
  graph_db_ = graph_open(path_.value().c_str(), O_RDWR | O_CREAT, 0664, 0);
  if (graph_db_) {
    open_ = true;
  } else {
    LOG(ERROR) << "error opening graph db";
  }
  return (graph_db_ ? 0 : -1);
}

void GraphDb::ShutdownImpl() {
  graph_close(graph_db_);  
}

void GraphDb::SyncImpl(bool force) {
  graph_sync(graph_db_, force ? 1 : 0);
}

void GraphDb::UpdatedImpl() {
  graph_updated(graph_db_);
}

void GraphDb::RemapImpl() {
  graph_remap(graph_db_); 
}

void GraphDb::CountImpl(const base::Callback<void(size_t)>& callback) const {
  size_t count = graph_size(graph_db_);
  callback.Run(count);
}

void GraphDb::ExecuteImpl(const base::Callback<void(GraphDbTransaction*)>& batch, bool write) const {
  auto trans = Begin(write);
  batch.Run(&trans);
  trans.Commit();
}

}