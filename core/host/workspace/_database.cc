// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/workspace/database.h"

#include "base/files/file_util.h"
#include "base/task_scheduler/post_task.h"
#include "base/synchronization/waitable_event.h"
#include "core/host/workspace/table.h"

namespace host {

DatabaseContext::DatabaseContext(Database* db, scoped_refptr<base::SingleThreadTaskRunner> io_task_runner, db::Context* context): 
  db_(db),
  context_(context),
  io_task_runner_(io_task_runner) {

}

DatabaseContext::~DatabaseContext() {
  
}

// void DatabaseContext::Execute(scoped_refptr<Table> table, base::Closure task) {
//   io_task_runner_->PostTask(
//     FROM_HERE, 
//     base::Bind(std::move(task), this));
// }

void DatabaseContext::Closing() {
  DCHECK(io_task_runner_->BelongsToCurrentThread());
  io_task_runner_ = nullptr;
  db_ = nullptr;
}

// std::unique_ptr<db::Cursor> DatabaseContext::CreateCursor(bool write, int table) {
//   //base::AutoLock lock(db_lock_);
//   DCHECK(io_task_runner_->BelongsToCurrentThread());
//   return db_->CreateCursor(write, table);
// }

// std::unique_ptr<db::Transaction> DatabaseContext::BeginTransaction(bool write) {
//   //base::AutoLock lock(db_lock_);
//   DCHECK(io_task_runner_->BelongsToCurrentThread());
//   return db_->BeginTransaction(write);
// }

std::unique_ptr<TableIterator> DatabaseContext::GetIterator(const std::string& table_name) {
  DCHECK(io_task_runner_->BelongsToCurrentThread());
  scoped_refptr<Table> table = GetTable(table_name);
  if (!table) {
    return {};
  }
  return std::make_unique<TableIterator>(
    context_->BeginTransaction(false),
    context_->CreateCursor(false, table->index()));
}

void DatabaseContext::Get(const std::string& table_name, base::StringPiece key, base::Callback<void(base::StringPiece, bool)> cb) {
  scoped_refptr<Table> table = GetTable(table_name);
  if (!table) {
    std::move(cb).Run(base::StringPiece(), false);
    return;
  }
  io_task_runner_->PostTask(
     FROM_HERE, 
     base::Bind(&Table::Get, 
      table, 
      base::Unretained(context_), 
      key, 
      base::Passed(std::move(cb))));
}

void DatabaseContext::Insert(const std::string& table_name, base::StringPiece key, base::StringPiece data, base::Callback<void(bool)> cb) {
  scoped_refptr<Table> table = GetTable(table_name);
  if (!table) {
    std::move(cb).Run(false);
    return;
  }
  io_task_runner_->PostTask(
     FROM_HERE, 
     base::Bind(&Table::Insert, table, base::Unretained(context_), key, data, base::Passed(std::move(cb))));
}

void DatabaseContext::Insert(const std::string& table_name, base::StringPiece key, scoped_refptr<net::IOBufferWithSize> data, base::Callback<void(bool)> cb) {
  scoped_refptr<Table> table = GetTable(table_name);
  if (!table) {
    std::move(cb).Run(false);
    return;
  }
  io_task_runner_->PostTask(
     FROM_HERE, 
     base::Bind(&Table::InsertData, table, base::Unretained(context_), key, data, base::Passed(std::move(cb))));
}

void DatabaseContext::Remove(const std::string& table_name, base::StringPiece key, base::Callback<void(bool)> cb) {
  scoped_refptr<Table> table = GetTable(table_name);
  if (!table) {
    std::move(cb).Run(false);
    return;
  }
  io_task_runner_->PostTask(
     FROM_HERE, 
     base::Bind(&Table::Remove, table, base::Unretained(context_), key, base::Passed(std::move(cb))));
}

scoped_refptr<Table> DatabaseContext::GetTable(const std::string& table_name) {
  db_lock_.Acquire();
  scoped_refptr<Table> table = db_->table(table_name);
  db_lock_.Release();
  return table;
}

Database::Database(): 
  opened_(false),
  io_task_runner_(
    base::CreateSingleThreadTaskRunnerWithTraits(
      { base::MayBlock() })) {

}

Database::~Database() {

}

void Database::Open(const base::FilePath& path, size_t table_count, base::Callback<void(bool)> cb, bool sync) {
  path_ = path;
  table_count_ = table_count;
  if (sync) {
    base::WaitableEvent do_sync{base::WaitableEvent::ResetPolicy::MANUAL, base::WaitableEvent::InitialState::NOT_SIGNALED};
    io_task_runner_->PostTask(
      FROM_HERE, 
      base::Bind(&Database::OpenImpl, 
        base::Unretained(this), 
        base::Passed(std::move(cb)),
        base::Unretained(&do_sync)));
    do_sync.Wait();
    opened_ = db_ ? true : false;
  } else {
    io_task_runner_->PostTask(
      FROM_HERE, 
      base::Bind(&Database::OpenImpl, 
        base::Unretained(this), 
        base::Passed(std::move(cb)),
        nullptr));
  }
}

void Database::Close(bool sync) {
  if (sync) {
    base::WaitableEvent do_sync{base::WaitableEvent::ResetPolicy::MANUAL, base::WaitableEvent::InitialState::NOT_SIGNALED};
    io_task_runner_->PostTask(
        FROM_HERE, 
        base::Bind(&Database::CloseImpl, 
          base::Unretained(this), 
          base::Unretained(&do_sync)));
    do_sync.Wait();
  } else {
    io_task_runner_->PostTask(
        FROM_HERE, 
        base::Bind(&Database::CloseImpl, 
          base::Unretained(this), 
          nullptr));
  }
}

void Database::SetTable(scoped_refptr<Table> table) {
  table_names_.emplace(std::make_pair(table->name(), table->index()));
  tables_.insert(tables_.begin() + table->index(), table);
}

void Database::OpenImpl(base::Callback<void(bool)> cb, base::WaitableEvent* do_sync) {
  if (!base::PathExists(path_)) {
    db_ = db::Create(path_, table_count_);
  } else {
    db_ = db::Open(path_, table_count_, false);
  }

  if (db_) {
    context_ = new DatabaseContext(this, io_task_runner_, db_.get());
    opened_ = true;
    std::move(cb).Run(true);
    if (do_sync) {
      do_sync->Signal();
    }
    return;
  }

  std::move(cb).Run(false);

  if (do_sync) {
    do_sync->Signal();
  }
}

void Database::CloseImpl(base::WaitableEvent* do_sync) {
  if (db_) {
    context_->Closing();
    db_->Close();
    opened_ = false;
    context_ = nullptr;
  }
  if (do_sync) {
    do_sync->Signal();
  }
}

}