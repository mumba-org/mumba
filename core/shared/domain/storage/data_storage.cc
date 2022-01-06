// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/domain/storage/data_storage.h"

#include "core/shared/domain/storage/storage_context.h"

namespace domain {

DataStorage::DataStorage(scoped_refptr<StorageContext> context): context_(context) {

}

DataStorage::~DataStorage() {
  
}

// void DataStorage::Open(const base::UUID& id, base::Callback<void(int)> cb) {
//   context_->DataOpen(id, std::move(cb));
// }

void DataStorage::Close(const std::string& db_name, base::Callback<void(int)> cb) {
  const auto& task_runner = context_->GetMainTaskRunner();
  if (task_runner->RunsTasksInCurrentSequence()) {
    context_->DataClose(db_name, std::move(cb));
  } else {
    task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(&StorageContext::DataClose,
        context_,
        db_name,
        base::Passed(std::move(cb))));
  }
}

// void DataStorage::Create(const base::UUID& id, base::Callback<void(int)> cb) {
//   context_->DataCreate(id, std::move(cb));
// }

void DataStorage::Drop(const std::string& db_name, base::Callback<void(int)> cb) {
  const auto& task_runner = context_->GetMainTaskRunner();
  if (task_runner->RunsTasksInCurrentSequence()) {
    context_->DataDrop(db_name, std::move(cb));
  } else {
    task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(&StorageContext::DataDrop,
        context_,
        db_name, 
        base::Passed(std::move(cb))));
  }
}

void DataStorage::CreateKeyspace(const std::string& db_name, const std::string& keyspace, base::Callback<void(int)> cb) {
  const auto& task_runner = context_->GetMainTaskRunner();
  if (task_runner->RunsTasksInCurrentSequence()) {
    context_->DataCreateKeyspace(db_name, keyspace, std::move(cb));
  } else {
    task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(&StorageContext::DataCreateKeyspace,
        context_,
        db_name,
        keyspace,
        base::Passed(std::move(cb))));
  }
}

void DataStorage::DeleteKeyspace(const std::string& db_name, const std::string& keyspace, base::Callback<void(int)> cb) {
  const auto& task_runner = context_->GetMainTaskRunner();
  if (task_runner->RunsTasksInCurrentSequence()) {
    context_->DataDeleteKeyspace(db_name, keyspace, std::move(cb));
  } else {
    task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(&StorageContext::DataDeleteKeyspace,
        context_,
        db_name,
        keyspace,
        base::Passed(std::move(cb))));
  }
}

void DataStorage::ListKeyspaces(const std::string& db_name, base::Callback<void(int, int, const std::vector<std::string>&)> cb) {
  const auto& task_runner = context_->GetMainTaskRunner();
  if (task_runner->RunsTasksInCurrentSequence()) {
    context_->DataListKeyspaces(db_name, std::move(cb));
  } else {
    task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(&StorageContext::DataListKeyspaces,
        context_,
        db_name,
        base::Passed(std::move(cb))));
  }
}

void DataStorage::Put(const std::string& db_name, const std::string& keyspace, const std::string& key, int64_t size, mojo::ScopedSharedBufferHandle data, base::Callback<void(int)> cb) {
  const auto& task_runner = context_->GetMainTaskRunner();
  if (task_runner->RunsTasksInCurrentSequence()) {
    context_->DataPut(db_name, keyspace, key, size, std::move(data), std::move(cb));
  } else {
    task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(&StorageContext::DataPut,
        context_,
        db_name,
        keyspace,
        key,
        size,
        base::Passed(std::move(data)),
        base::Passed(std::move(cb))));
  }
}

void DataStorage::Get(const std::string& db_name, const std::string& keyspace, const std::string& key, int64_t size, mojo::ScopedSharedBufferHandle data, base::Callback<void(int)> cb) {
  const auto& task_runner = context_->GetMainTaskRunner();
  if (task_runner->RunsTasksInCurrentSequence()) {
    context_->DataGet(db_name, keyspace, key, size, std::move(data), std::move(cb));
  } else {
    task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(&StorageContext::DataGet,
        context_,
        db_name,
        keyspace,
        key,
        size,
        base::Passed(std::move(data)),
        base::Passed(std::move(cb))));
  }
}

void DataStorage::GetOnce(const std::string& db_name, const std::string& keyspace, const std::string& key, base::Callback<void(int, mojo::ScopedSharedBufferHandle, int)> cb) {
  const auto& task_runner = context_->GetMainTaskRunner();
  if (task_runner->RunsTasksInCurrentSequence()) {
    context_->DataGetOnce(db_name, keyspace, key, std::move(cb));
  } else {
    task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(&StorageContext::DataGetOnce,
        context_,
        db_name,
        keyspace,
        key,
        base::Passed(std::move(cb))));
  }
}

void DataStorage::Delete(const std::string& db_name, const std::string& keyspace, const std::string& key, base::Callback<void(int)> cb) {
  const auto& task_runner = context_->GetMainTaskRunner();
  if (task_runner->RunsTasksInCurrentSequence()) {
    context_->DataDelete(db_name, keyspace, key, std::move(cb)); 
  } else {
    task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(&StorageContext::DataDelete,
        context_,
        db_name,
        keyspace,
        key,
        base::Passed(std::move(cb))));
  }
}

void DataStorage::DeleteAll(const std::string& db_name, const std::string& keyspace, base::Callback<void(int)> cb) {
  const auto& task_runner = context_->GetMainTaskRunner();
  if (task_runner->RunsTasksInCurrentSequence()) {
    context_->DataDeleteAll(db_name, keyspace, std::move(cb));
  } else {
    task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(&StorageContext::DataDeleteAll,
        context_,
        db_name,
        keyspace,
        base::Passed(std::move(cb))));
  }
}

}