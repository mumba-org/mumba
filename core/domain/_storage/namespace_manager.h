// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_NAMESPACE_NAMESPACE_MANAGER_H_
#define MUMBA_DOMAIN_NAMESPACE_NAMESPACE_MANAGER_H_

#include <memory>
#include <string>
#include <unordered_map>

#include "base/macros.h"
#include "base/memory/weak_ptr.h"
#include "base/files/file_path.h"
//#include "disk/disk.h"
#include "core/shared/domain/storage/namespace.h"
#include "core/shared/domain/storage/mount_info.h"

namespace domain {

using Namespaces = std::unordered_map<base::UUID, std::unique_ptr<Namespace>>;
using NamespaceIterator = Namespaces::iterator;
using NamespaceConstIterator = Namespaces::const_iterator;

class NamespaceManager {
public:
  NamespaceManager(const base::FilePath& namespaces_path);
  ~NamespaceManager();

  void Initialize(disk::Disk* disk, scoped_refptr<base::TaskRunner> reply_to);
  void Shutdown();

  const base::FilePath& namespaces_path() const {
    return namespaces_path_;
  }

  disk::Disk* disk() const { 
    return disk_; 
  }

  NamespaceIterator namespaces_begin() {
    return namespaces_.begin();
  }

  NamespaceConstIterator namespaces_begin() const {
    return namespaces_.begin(); 
  }

  NamespaceIterator namespaces_end() {
    return namespaces_.begin();
  }

  NamespaceConstIterator namespaces_end() const {
    return namespaces_.begin(); 
  }

  size_t namespace_count() const {
    return namespaces_.size();
  }

  //Namespace* CreateNamespace(const std::string& name, bool in_memory);
  Namespace* CreateNamespace(bool in_memory, base::Callback<void(Namespace*)> on_init, scoped_refptr<base::TaskRunner> reply_to);
  Namespace* GetNamespaceById(const base::UUID& id) const;
  Namespace* GetNamespaceAtMount(const std::string& point) const;
  Namespace* GetNamespaceAt(size_t index) const;
  void AddNamespace(std::unique_ptr<Namespace> ns);
  std::unique_ptr<Namespace> RemoveNamespace(const base::UUID& namespace_id);

  bool Mount(const std::string& point, const base::UUID& target_ds);
  bool Unmount(const std::string& point);

private:
  
  bool AddNamespaceFromPath(const base::FilePath& dir, scoped_refptr<base::TaskRunner> reply_to);
  void OnNamespaceInit(Namespace* ds);

  Namespaces namespaces_;

  base::FilePath namespaces_path_;

  disk::Disk* disk_;

  std::unordered_map<std::string, MountInfo*> mounts_;

  base::WeakPtrFactory<NamespaceManager> weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(NamespaceManager);
};

}

#endif