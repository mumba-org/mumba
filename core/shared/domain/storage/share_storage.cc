// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/domain/storage/share_storage.h"

#include "core/shared/domain/storage/storage_context.h"

namespace domain {

ShareStorage::ShareStorage(scoped_refptr<StorageContext> context): 
  context_(context) {

}

ShareStorage::~ShareStorage() {
  
}

void ShareStorage::CreateShareWithPath(common::mojom::StorageType type, const std::string& name, std::vector<std::string> keyspaces, const std::string& source_path, base::Callback<void(int)> cb) {
  const auto& task_runner = context_->GetMainTaskRunner();
  if (task_runner->RunsTasksInCurrentSequence()) {
    context_->ShareCreateWithPath(type, name, std::move(keyspaces), source_path, std::move(cb));
  } else {
    task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(&StorageContext::ShareCreateWithPath,
        context_,
        type,
        name,
        base::Passed(std::move(keyspaces)), 
        source_path,
        base::Passed(std::move(cb))));
  }
}

void ShareStorage::CreateShareWithInfohash(common::mojom::StorageType type, const std::string& name, std::vector<std::string> keyspaces, const std::string& infohash, base::Callback<void(int)> cb) {
  const auto& task_runner = context_->GetMainTaskRunner();
  if (task_runner->RunsTasksInCurrentSequence()) {
    context_->ShareCreateWithInfohash(type, name, std::move(keyspaces), infohash, std::move(cb));
  } else {
    task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(&StorageContext::ShareCreateWithInfohash,
        context_,
        type,
        name,
        base::Passed(std::move(keyspaces)), 
        infohash,
        base::Passed(std::move(cb))));
  }
}

void ShareStorage::AddShare(const base::UUID& id, const std::string& url, base::Callback<void(int)> cb) {
  const auto& task_runner = context_->GetMainTaskRunner();
  if (task_runner->RunsTasksInCurrentSequence()) {
    context_->ShareAdd(id, url, std::move(cb));
  } else {
    task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(&StorageContext::ShareAdd,
        context_,
        id, 
        url, 
        base::Passed(std::move(cb))));
  }
}

void ShareStorage::OpenShare(common::mojom::StorageType type, const std::string& name, bool create_if_not_exists, base::Callback<void(int)> cb) {
  const auto& task_runner = context_->GetMainTaskRunner();
  if (task_runner->RunsTasksInCurrentSequence()) {
    context_->ShareOpen(type, name, create_if_not_exists, std::move(cb));
  } else {
    task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(&StorageContext::ShareOpen,
        context_,
        type,
        name,
        create_if_not_exists,
        base::Passed(std::move(cb))));
  }
}

void ShareStorage::ShareExists(const std::string& name, base::Callback<void(int)> cb) {
  const auto& task_runner = context_->GetMainTaskRunner();
  if (task_runner->RunsTasksInCurrentSequence()) {
    context_->ShareExists(name, std::move(cb));
  } else {
    task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(&StorageContext::ShareExists,
        context_,
        name,
        base::Passed(std::move(cb))));
  }
}

void ShareStorage::ReadShare(const base::UUID& id, int64_t offset, int64_t size, mojo::ScopedSharedBufferHandle data, base::Callback<void(int)> cb) {
  const auto& task_runner = context_->GetMainTaskRunner();
  if (task_runner->RunsTasksInCurrentSequence()) {
    context_->ShareRead(id, offset, size, std::move(data), std::move(cb));
  } else {
    task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(&StorageContext::ShareRead,
        context_,
        id,
        offset,
        size,
        base::Passed(std::move(data)), 
        base::Passed(std::move(cb))));
  }
}

void ShareStorage::WriteShare(const base::UUID& id, int64_t offset, int64_t size, mojo::ScopedSharedBufferHandle data, base::Callback<void(int)> cb) {
  const auto& task_runner = context_->GetMainTaskRunner();
  if (task_runner->RunsTasksInCurrentSequence()) {
    context_->ShareWrite(id, offset, size, std::move(data), std::move(cb));
  } else {
    task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(&StorageContext::ShareWrite,
        context_,
        id, 
        offset, 
        size, 
        base::Passed(std::move(data)), 
        base::Passed(std::move(cb))));
  }
}

void ShareStorage::CloseShare(const std::string& name, base::Callback<void(int)> cb) {
  const auto& task_runner = context_->GetMainTaskRunner();
  if (task_runner->RunsTasksInCurrentSequence()) {
    context_->ShareClose(name, std::move(cb));
  } else {
    task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(&StorageContext::ShareClose,
        context_,
        name,
        base::Passed(std::move(cb))));
  }
}

void ShareStorage::DeleteShare(const base::UUID& id, base::Callback<void(int)> cb) {
  const auto& task_runner = context_->GetMainTaskRunner();
  if (task_runner->RunsTasksInCurrentSequence()) {
    context_->ShareDelete(id, std::move(cb));
  } else {
    task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(&StorageContext::ShareDelete,
        context_,
        id,
        base::Passed(std::move(cb))));
  }
}

void ShareStorage::ShareShare(const base::UUID& id, base::Callback<void(int)> cb) {
  const auto& task_runner = context_->GetMainTaskRunner();
  if (task_runner->RunsTasksInCurrentSequence()) {
    context_->ShareShare(id, std::move(cb));
  } else {
    task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(&StorageContext::ShareShare,
        context_,
        id,
        base::Passed(std::move(cb))));
  }
}

void ShareStorage::UnshareShare(const base::UUID& id, base::Callback<void(int)> cb) {
  const auto& task_runner = context_->GetMainTaskRunner();
  if (task_runner->RunsTasksInCurrentSequence()) {
    context_->ShareUnshare(id, std::move(cb));
  } else {
    task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(&StorageContext::ShareUnshare,
        context_,
        id,
        base::Passed(std::move(cb))));
  }
}

void ShareStorage::SubscribeShare(const base::UUID& id, base::Callback<void(int)> cb) {
  const auto& task_runner = context_->GetMainTaskRunner();
  if (task_runner->RunsTasksInCurrentSequence()) {
    context_->ShareSubscribe(id, std::move(cb));
  } else {
    task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(&StorageContext::ShareSubscribe,
        context_,
        id,
        base::Passed(std::move(cb))));
  }
}

void ShareStorage::UnsubscribeShare(const base::UUID& id, base::Callback<void(int)> cb) {
  const auto& task_runner = context_->GetMainTaskRunner();
  if (task_runner->RunsTasksInCurrentSequence()) {
    context_->ShareUnsubscribe(id, std::move(cb));
  } else {
    task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(&StorageContext::ShareUnsubscribe,
      context_,
      id,
      base::Passed(std::move(cb))));
  }
}

}