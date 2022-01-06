// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_STORAGE_MANAGER_H_
#define MUMBA_DOMAIN_STORAGE_MANAGER_H_

#include "base/macros.h"
#include "base/single_thread_task_runner.h"
#include "base/synchronization/waitable_event.h"
#include "base/files/file_path.h"
#include "core/shared/common/content_export.h"
#include "core/shared/common/mojom/storage.mojom.h"

namespace domain {
class StorageContext;
class StorageDispatcher;

struct CONTENT_EXPORT StoragePolicy {
  size_t filesystem_image_size = 0;
  size_t total_size_allowed = 0;
  static StoragePolicy Default();
};

class CONTENT_EXPORT StorageManager {
public:
  class Delegate {
  public:
    virtual ~Delegate() {}
    virtual void OnStorageManagerInit(bool result) = 0;
  };

  StorageManager(Delegate* delegate, const base::FilePath& path);
  ~StorageManager();

  void Initialize(
    StorageDispatcher* dispatcher, 
    scoped_refptr<base::SingleThreadTaskRunner> main_task_runner,
    scoped_refptr<base::SingleThreadTaskRunner> io_task_runner, 
    StoragePolicy policy = StoragePolicy::Default());
  
  void Shutdown();
  
  const StoragePolicy& policy() const {
    return policy_;
  }

  StorageDispatcher* storage_dispatcher() const {
    return storage_dispatcher_;
  }

  const scoped_refptr<base::SingleThreadTaskRunner>& main_task_runner() const {
    return main_task_runner_;
  }

  const scoped_refptr<base::SingleThreadTaskRunner>& io_task_runner() const {
    return io_task_runner_;
  }

  const base::FilePath& GetStoragePath();
  void GetTotalAllocatedSize(base::Callback<void(int64_t)> callback);

  scoped_refptr<StorageContext> CreateContext(base::Callback<void(scoped_refptr<StorageContext>)> cb = base::Callback<void(scoped_refptr<StorageContext>)>());
  scoped_refptr<StorageContext> GetOrCreateContext();
  scoped_refptr<StorageContext> GetContext(int id);
  void DestroyContext(int id);

private:

  void InitializeImpl();

  void NotifyInit(bool result) const;

  void DispatchContextCreation(scoped_refptr<StorageContext> context, 
    base::Callback<void(scoped_refptr<StorageContext>)> cb);

  void OnContextCreate(
    scoped_refptr<StorageContext> context,
    base::Callback<void(scoped_refptr<StorageContext>)> cb,
    common::mojom::StorageContextPtr shared_context);

  base::FilePath storage_path_;

  Delegate* delegate_;

  //common::mojom::StorageDispatcherHost* storage_dispatcher_host_;
  StorageDispatcher* storage_dispatcher_;

  scoped_refptr<base::SingleThreadTaskRunner> main_task_runner_;

  scoped_refptr<base::SingleThreadTaskRunner> io_task_runner_;
  
  //scoped_refptr<base::SequencedTaskRunner> background_task_runner_;

  StoragePolicy policy_;

  std::unordered_map<int, scoped_refptr<StorageContext>> contexts_;
  
  DISALLOW_COPY_AND_ASSIGN(StorageManager);
};

}

#endif