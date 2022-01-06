// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_STORAGE_MANAGER_H_
#define MUMBA_DOMAIN_STORAGE_MANAGER_H_

#include "base/macros.h"
#include "base/single_thread_task_runner.h"
#include "base/synchronization/waitable_event.h"
//#include "disk/disk.h"
//#include "disk/disk_manager.h"
#include "core/shared/domain/storage/namespace.h"

namespace domain {
class NamespaceManager;
//class MountManager;

struct StoragePolicy {
  size_t filesystem_image_size = 0;
  size_t total_size_allowed = 0;
  static StoragePolicy Default();
};

class StorageManager {
public:
  class Delegate {
  public:
    virtual ~Delegate() {}
    virtual void OnStorageManagerInit(bool result) = 0;
  };

  StorageManager(Delegate* delegate, const base::FilePath& path);
  ~StorageManager();

  void Initialize(disk::DiskManager* manager, StoragePolicy policy = StoragePolicy::Default());
  void Shutdown();
  
  const StoragePolicy& policy() const {
    return policy_;
  }

  NamespaceManager* namespace_manager() const {
    return namespace_manager_.get();
  }

  disk::Disk* disk() const {
    return disk_;
  }

  //MountManager* mount_manager() const {
  //  return mount_manager_.get();
  //}

  const base::FilePath& GetStoragePath();
  size_t GetTotalAllocatedSize() const;

  // Namespaces
  size_t GetNamespaceAllocatedSize(const std::string& namespace_id) const;
  size_t GetNamespaceCount() const;
  bool HasNamespaceAtMount(const std::string& name) const;
  bool HasNamespace(const base::UUID& namespace_id) const;
  Namespace* CreateNamespace(bool in_memory);
  Namespace* GetNamespace(const base::UUID& namespace_id) const;
  //Namespace* GetNamespaceNamed(const std::string& name) const;
  bool LoadNamespace(const std::string& namespace_id);
  bool UnloadNamespace(const std::string& namespace_id);
  bool DropNamespace(const std::string& namespace_id);

  Namespace* GetNamespaceAtMount(const std::string& point) const;
  bool Mount(const std::string& point, const base::UUID& target_ds);
  bool Unmount(const std::string& point);

private:

  void InitializeImpl(disk::DiskManager* manager);

  void NotifyInit(bool result) const;

  void CreateTestNamespace();
  void CreateHelloConcept(Namespace* ns);

  void OnCreateNamespace(Namespace* ns);

  base::FilePath storage_path_;

  Delegate* delegate_;

  scoped_refptr<base::SequencedTaskRunner> origin_task_runner_;
  
  scoped_refptr<base::SequencedTaskRunner> background_task_runner_;

  std::unique_ptr<NamespaceManager> namespace_manager_;

  disk::Disk* disk_;

  //std::unique_ptr<MountManager> mount_manager_;

  StoragePolicy policy_;
  
  DISALLOW_COPY_AND_ASSIGN(StorageManager);
};

}

#endif