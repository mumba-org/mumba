// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_NAMESPACE_CACHE_CACHE_FILESYSTEM_BACKEND_H_
#define MUMBA_DOMAIN_NAMESPACE_CACHE_CACHE_FILESYSTEM_BACKEND_H_

#include "base/macros.h"
#include "base/callback.h"
#include "base/files/file_path.h"
#include "base/single_thread_task_runner.h"
#include "core/shared/domain/storage/filesystem_backend.h"
#include "net/log/net_log.h"
#include "net/disk_cache/disk_cache.h"
#include "net/disk_cache/cache_util.h"

namespace domain {

class CacheFilesystemBackend : public FilesystemBackend {
public:
  CacheFilesystemBackend(
    int fs_id,
    const base::UUID& namespace_id, 
    const base::FilePath& namespace_path,
    bool in_memory);
  
  ~CacheFilesystemBackend() override;

  void Initialize(const base::Callback<void(int, int)>& callback) override;
  void Shutdown() override;

  int id() const override;
  //FilesystemType type() const override;
  int32_t GetFileCount() const override;
  bool in_memory() const override;

private:

  void InitializeImpl(const base::Callback<void(int, int)>& callback);
  void ShutdownImpl();

  base::FilePath namespace_path_;

  int fs_id_;

  base::UUID namespace_id_;

  bool in_memory_;

  std::unique_ptr<disk_cache::Backend> backend_;

  scoped_refptr<base::SingleThreadTaskRunner> background_task_runner_;

  net::NetLog log_;

  DISALLOW_COPY_AND_ASSIGN(CacheFilesystemBackend);
};

}


#endif