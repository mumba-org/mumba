// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/domain/storage/namespace_manager.h"

#include "base/optional.h"
#include "base/bind.h"
#include "base/files/file_enumerator.h"
#include "base/strings/utf_string_conversions.h"
#include "core/shared/domain/storage/namespace.h"
#include "core/shared/domain/storage/namespace_builder.h"
#include "base/uuid.h"

namespace domain {

NamespaceManager::NamespaceManager(const base::FilePath& namespaces_path):
  namespaces_path_(namespaces_path),
  disk_(nullptr),
  weak_factory_(this) {

}

NamespaceManager::~NamespaceManager() {
  for (auto mount_it = mounts_.begin(); mount_it != mounts_.end(); mount_it++) {
    delete mount_it->second;
  }
  mounts_.clear();
}

void NamespaceManager::Initialize(disk::Disk* disk, scoped_refptr<base::TaskRunner> reply_to) {
  disk_ = disk;

  base::FileEnumerator dir_enum(namespaces_path_, false, base::FileEnumerator::DIRECTORIES);
  
  for (base::FilePath dir = dir_enum.Next(); !dir.empty(); dir = dir_enum.Next()) {
    if (!AddNamespaceFromPath(dir, reply_to)) {
      LOG(ERROR) << "failed to add namespace " << dir;
    }
  }

}

void NamespaceManager::Shutdown() {
  namespaces_.clear();
}

// Namespace* NamespaceManager::CreateNamespace(const std::string& name, bool in_memory) {
//   NamespaceBuilder builder(name, namespaces_path_);
//   if (!builder.Init()) { return nullptr; }
//   if (!builder.CreateDatabase(in_memory)) { return nullptr; }
//   if (!builder.CreateFilesystem(in_memory)) { return nullptr; }
//   std::unique_ptr<Namespace> namespace = builder.Build(this, in_memory);
//   if (!namespace) {
//     return nullptr;
//   }
//   namespace->Initialize();
//   Namespace* namespace_ref = namespace.get();
//   AddNamespace(std::move(namespace));
//   return namespace_ref;
// }

Namespace* NamespaceManager::CreateNamespace(bool in_memory, 
  base::Callback<void(Namespace*)> on_init, 
  scoped_refptr<base::TaskRunner> reply_to) {
  
  NamespaceBuilder builder(namespaces_path_);
  if (!builder.Init()) { return nullptr; }
  if (!builder.CreateDatabase(in_memory)) { return nullptr; }
  if (!builder.CreateFilesystem(in_memory)) { return nullptr; }
  std::unique_ptr<Namespace> ns = builder.Build(this, in_memory);
  if (!ns) {
    return nullptr;
  }
  ns->Initialize(base::Bind(on_init, base::Unretained(ns.get())), reply_to);
  Namespace* namespace_ref = ns.get();
  AddNamespace(std::move(ns));
  return namespace_ref;
}

Namespace* NamespaceManager::GetNamespaceById(const base::UUID& id) const {
  auto it = namespaces_.find(id);
  if (it != namespaces_.end()) {
    return it->second.get();
  }
  return nullptr;
}

Namespace* NamespaceManager::GetNamespaceAt(size_t index) const {
  size_t counter = 0;
  if (index >= namespace_count()) {
    return nullptr;
  }

  for (const auto& elem : namespaces_) {
    if (index == counter) {
      return elem.second.get();
    }
    counter++;
  }
  return nullptr;
}

// Namespace* NamespaceManager::GetNamespaceByName(const std::string& name) const {
//   for (auto it = namespaces_.begin(); it != namespaces_.end(); ++it) {
//     if (it->second->name() == name) {
//       return it->second.get();
//     }
//   }
//   return nullptr;
// }

void NamespaceManager::AddNamespace(std::unique_ptr<Namespace> ns) {
  namespaces_.emplace(std::make_pair(ns->id(), std::move(ns)));
}

std::unique_ptr<Namespace> NamespaceManager::RemoveNamespace(const base::UUID& namespace_id) {
  auto it = namespaces_.find(namespace_id);
  if (it != namespaces_.end()) {
    return std::move(it->second);
  }
  return {};
}

bool NamespaceManager::AddNamespaceFromPath(const base::FilePath& dir, scoped_refptr<base::TaskRunner> reply_to) {
#if defined(OS_WIN)  
  std::string uuid_str = base::UTF16ToASCII(dir.BaseName().value());
#elif defined(OS_POSIX)
  std::string uuid_str = dir.BaseName().value();
#endif
  bool ok = false;
  base::UUID id = base::UUID::from_string(uuid_str, &ok);

  if (!ok) {
    LOG(ERROR) << "couldnt convert '" << uuid_str << "' to uuid";
    return false;
  }

  std::unique_ptr<Namespace> ns(new Namespace(this, id, false));
  
  Namespace* handle = ns.get();
  
  //AddNamespace(std::move(ns));
  namespaces_.emplace(std::make_pair(id, std::move(ns)));

  handle->Initialize(
    base::Bind(&NamespaceManager::OnNamespaceInit, 
      base::Unretained(this),
      base::Unretained(handle)),
    reply_to);

  return true;
}

Namespace* NamespaceManager::GetNamespaceAtMount(const std::string& point) const {
  auto mount_it = mounts_.find(point);
  
  if (mount_it == mounts_.end())
    return nullptr;

  auto ds_it = namespaces_.find(mount_it->second->ns);
  if (ds_it == namespaces_.end())
    return nullptr;

  return ds_it->second.get();
}

bool NamespaceManager::Mount(const std::string& point, const base::UUID& target_ds) {
  auto ds_it = namespaces_.find(target_ds);
 
  if (ds_it == namespaces_.end())
    return false;

  MountInfo* info = new MountInfo{};
  info->mount_point = point;
  info->ns = target_ds;
  info->mounted_time = base::TimeTicks::Now();

  ds_it->second->set_mounted_at(info);
  mounts_.emplace(std::make_pair(point, info));

  return true;
}

bool NamespaceManager::Unmount(const std::string& point) {
  auto mount_it = mounts_.find(point);
  
  if (mount_it == mounts_.end())
    return false;

  auto ds_it = namespaces_.find(mount_it->second->ns);
  if (ds_it == namespaces_.end())
    return false;

  ds_it->second->set_mounted_at(nullptr);
  delete mount_it->second;
  mounts_.erase(mount_it);

  return true;
}

void NamespaceManager::OnNamespaceInit(Namespace* ds) {
  //DLOG(INFO) << "NamespaceManager::OnNamespaceInit: ns " << ds->id().to_string() << " init";
}

}