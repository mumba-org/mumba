// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/domain/storage/cache/cache_filesystem_backend.h"

#include "base/bind.h"
#include "base/threading/thread_task_runner_handle.h"
#include "base/sequenced_task_runner.h"
#include "base/task_scheduler/post_task.h"
#include "data/buffer.h"
#include "core/shared/domain/storage/namespace.h"
#include "core/domain/domain_thread.h"
#include "net/base/net_errors.h"

namespace domain {

CacheFilesystemBackend::CacheFilesystemBackend(
  int fs_id,
  const base::UUID& namespace_id, 
  const base::FilePath& namespace_path,
  bool in_memory):
    namespace_path_(namespace_path),
    fs_id_(fs_id),
    namespace_id_(namespace_id),
    in_memory_(in_memory),
    background_task_runner_(
      base::CreateSingleThreadTaskRunnerWithTraits(
        { base::MayBlock(), 
          base::TaskPriority::BACKGROUND })) {
  
}

CacheFilesystemBackend::~CacheFilesystemBackend() {

}

void CacheFilesystemBackend::Initialize(const base::Callback<void(int, int)>& callback) {
  background_task_runner_->PostTask(
    FROM_HERE,
    base::BindOnce(&CacheFilesystemBackend::InitializeImpl,
      base::Unretained(this), 
      callback));
}

void CacheFilesystemBackend::Shutdown() {
  background_task_runner_->PostTask(
    FROM_HERE,
    base::BindOnce(&CacheFilesystemBackend::ShutdownImpl,
      base::Unretained(this)));
}

int CacheFilesystemBackend::id() const {
 return fs_id_;
}

// FilesystemType CacheFilesystemBackend::type() const {
//   return FilesystemType::kCache;
// }

int32_t CacheFilesystemBackend::GetFileCount() const {
  return backend_->GetEntryCount();
}

bool CacheFilesystemBackend::in_memory() const {
  return backend_->GetCacheType() == net::CacheType::MEMORY_CACHE;
}

void CacheFilesystemBackend::InitializeImpl(const base::Callback<void(int, int)>& callback) {

  int result = disk_cache::CreateCacheBackend(
      in_memory_ ? net::MEMORY_CACHE : net::DISK_CACHE,
      net::CACHE_BACKEND_SIMPLE, // this or block?
      namespace_path_,
      0/* int max_bytes*/, // TODO: this will probably limit to 80 MB
                           //       we need to use something real here
      false/* force */,
      &log_,
      &backend_,
      base::Bind(callback, fs_id_));

  if (result != net::ERR_IO_PENDING) {
    DomainThread::PostTask(
      DomainThread::UI, 
      FROM_HERE, 
      base::Bind(callback, fs_id_, result));
    //callback.Run(result, fs_id_);
    //caller_thread_task_runner_->PostTask(FROM_HERE, base::Bind(callback, result, fs_id_));
    //caller_thread_task_runner_ = nullptr;
  }

}

void CacheFilesystemBackend::ShutdownImpl() {
  backend_.reset();
}

}