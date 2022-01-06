// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/domain/storage/file_storage.h"

#include "core/shared/domain/storage/storage_context.h"

namespace domain {

FileStorage::FileStorage(scoped_refptr<StorageContext> context): context_(context) {

}

FileStorage::~FileStorage() {
  
}

void FileStorage::CreateFile(const std::string& share_name, const std::string& file, base::Callback<void(int)> cb) {
  const auto& task_runner = context_->GetMainTaskRunner();
  if (task_runner->RunsTasksInCurrentSequence()) {
    context_->FileCreate(share_name, file, std::move(cb));
  } else {
    task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(&StorageContext::FileCreate, 
        context_, 
        share_name, 
        file, 
        base::Passed(std::move(cb))));
  }
}

void FileStorage::AddFile(const std::string& share_name, const std::string& file, const std::string& path, base::Callback<void(int)> cb) {
  const auto& task_runner = context_->GetMainTaskRunner();
  if (task_runner->RunsTasksInCurrentSequence()) {
    context_->FileAdd(share_name, file, path, std::move(cb));
  } else {
    task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(&StorageContext::FileAdd, 
        context_, 
        share_name,
        file,
        path,
        base::Passed(std::move(cb))));
  }
}

void FileStorage::OpenFile(const std::string& share_name, const std::string& file, base::Callback<void(int)> cb) {
  const auto& task_runner = context_->GetMainTaskRunner();
  if (task_runner->RunsTasksInCurrentSequence()) {
    context_->FileOpen(share_name, file, std::move(cb));
  } else {
    task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(&StorageContext::FileOpen, 
        context_, 
        share_name,
        file,
        base::Passed(std::move(cb))));
  }
}

void FileStorage::DeleteFile(const std::string& share_name, const std::string& file, base::Callback<void(int)> cb) {
  const auto& task_runner = context_->GetMainTaskRunner();
  if (task_runner->RunsTasksInCurrentSequence()) {
    context_->FileDelete(share_name, file, std::move(cb));
  } else {
    task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(&StorageContext::FileDelete, 
        context_, 
        share_name,
        file,
        base::Passed(std::move(cb))));
  }
}

void FileStorage::RenameFile(const std::string& share_name, const std::string& input, const std::string& output, base::Callback<void(int)> cb) {
  const auto& task_runner = context_->GetMainTaskRunner();
  if (task_runner->RunsTasksInCurrentSequence()) {
    context_->FileRename(share_name, input, output, std::move(cb));
  } else {
    task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(&StorageContext::FileRename, 
        context_, 
        share_name,
        input,
        output,
        base::Passed(std::move(cb))));
  }
}

void FileStorage::ReadFileOnce(const std::string& share_name, const std::string& file, int64_t offset, int64_t size, base::Callback<void(int, mojo::ScopedSharedBufferHandle, int)> cb) {
  const auto& task_runner = context_->GetMainTaskRunner();
  if (task_runner->RunsTasksInCurrentSequence()) {
    context_->FileReadOnce(share_name, file, offset, size, std::move(cb));
  } else {
    task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(&StorageContext::FileReadOnce, 
        context_, 
        share_name,
        file,
        offset,
        size,
        base::Passed(std::move(cb))));
  }
}

void FileStorage::ReadFile(const std::string& share_name, const std::string& file, int64_t offset, int64_t size, mojo::ScopedSharedBufferHandle data, base::Callback<void(int)> cb) {
  const auto& task_runner = context_->GetMainTaskRunner();
  if (task_runner->RunsTasksInCurrentSequence()) {
    context_->FileRead(share_name, file, offset, size, std::move(data), std::move(cb));
  } else {
    task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(&StorageContext::FileRead, 
        context_, 
        share_name,
        file,
        offset,
        size,
        base::Passed(std::move(data)),
        base::Passed(std::move(cb))));
  }
}

void FileStorage::WriteFileOnce(const std::string& share_name, const std::string& file, int64_t offset, int64_t size, std::vector<uint8_t> data, base::Callback<void(int, int)> cb) {
  const auto& task_runner = context_->GetMainTaskRunner();
  if (task_runner->RunsTasksInCurrentSequence()) {
    context_->FileWriteOnce(share_name, file, offset, size, std::move(data), std::move(cb));
  } else {
    task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(&StorageContext::FileWriteOnce, 
        context_, 
        share_name,
        file,
        offset,
        size,
        base::Passed(std::move(data)),
        base::Passed(std::move(cb))));
  }
}

void FileStorage::WriteFile(const std::string& share_name, const std::string& file, int64_t offset, int64_t size, mojo::ScopedSharedBufferHandle data, base::Callback<void(int)> cb) {
  const auto& task_runner = context_->GetMainTaskRunner();
  if (task_runner->RunsTasksInCurrentSequence()) {
    context_->FileWrite(share_name, file, offset, size, std::move(data), std::move(cb));
  } else {
    task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(&StorageContext::FileWrite, 
        context_, 
        share_name,
        file,
        offset,
        size,
        base::Passed(std::move(data)),
        base::Passed(std::move(cb))));
  }
}

void FileStorage::CloseFile(const std::string& share_name, const std::string& file, base::Callback<void(int)> cb) {
  const auto& task_runner = context_->GetMainTaskRunner();
  if (task_runner->RunsTasksInCurrentSequence()) {
    context_->FileClose(share_name, file, std::move(cb));
  } else {
    task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(&StorageContext::FileClose, 
        context_, 
        share_name,
        file,
        base::Passed(std::move(cb))));
  } 
}

void FileStorage::ListFiles(const std::string& share_name, base::Callback<void(std::vector<common::mojom::ShareStorageEntryPtr>)> callback) {
  const auto& task_runner = context_->GetMainTaskRunner();
  if (task_runner->RunsTasksInCurrentSequence()) {
    context_->FileList(share_name, std::move(callback));
  } else {
    task_runner->PostTask(
      FROM_HERE, 
      base::BindOnce(&StorageContext::FileList, 
        context_, 
        share_name,
        base::Passed(std::move(callback))));
  }   
}

}