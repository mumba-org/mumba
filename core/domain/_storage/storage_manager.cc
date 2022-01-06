// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/domain/storage/storage_manager.h"

#include "base/task_scheduler/post_task.h"
#include "base/threading/sequenced_task_runner_handle.h"
//#include "core/shared/domain/storage/mount/mount_manager.h"
#include "core/shared/domain/storage/namespace_manager.h"
//#include "core/shared/domain/storage/sqlite/sqlite3.h"
////#include "disk/disk_current.h"
//#include "disk/disk.h"
//#include "disk/disk_manager.h"

namespace domain {

// static 
StoragePolicy StoragePolicy::Default() {
  return StoragePolicy();
}

StorageManager::StorageManager(Delegate* delegate, const base::FilePath& path):
 storage_path_(path),
 delegate_(delegate),
 background_task_runner_(
      base::CreateSequencedTaskRunnerWithTraits(
        { base::MayBlock(), 
          base::TaskPriority::BACKGROUND })) {
  
}

StorageManager::~StorageManager() {

}

void StorageManager::Initialize(disk::DiskManager* manager, StoragePolicy policy) {
  //DLOG(INFO) << "StorageManager::Initialize";
  DCHECK(base::SequencedTaskRunnerHandle::IsSet());
  origin_task_runner_ = base::SequencedTaskRunnerHandle::Get();
  
  policy_ = policy;

  namespace_manager_.reset(new NamespaceManager(storage_path_.AppendASCII("namespaces")));
  
  background_task_runner_->PostTask(
    FROM_HERE,
    base::BindOnce(&StorageManager::InitializeImpl, 
      base::Unretained(this), 
      base::Unretained(manager)));
}

void StorageManager::Shutdown() {
 
}

const base::FilePath& StorageManager::GetStoragePath() {
  return storage_path_; 
}

size_t StorageManager::GetTotalAllocatedSize() const {
  return 0;
}

  // Namespaces
size_t StorageManager::GetNamespaceAllocatedSize(const std::string& namespace_id) const {
  return 0;
}

size_t StorageManager::GetNamespaceCount() const {
  return 0;
}

bool StorageManager::HasNamespaceAtMount(const std::string& name) const {
  return false;
}

bool StorageManager::HasNamespace(const base::UUID& namespace_id) const {
  return false;
}

Namespace* StorageManager::CreateNamespace(bool in_memory) {
  return namespace_manager_->CreateNamespace(in_memory, 
    base::Bind(&StorageManager::OnCreateNamespace, base::Unretained(this)),
    background_task_runner_);
}

Namespace* StorageManager::GetNamespace(const base::UUID& namespace_id) const {
  return namespace_manager_->GetNamespaceById(namespace_id);
}

// Namespace* StorageManager::GetNamespaceNamed(const std::string& name) const {
//   return namespace_manager_->GetNamespaceByName(name);
// }

bool StorageManager::LoadNamespace(const std::string& namespace_id) {
  return false;
}

bool StorageManager::UnloadNamespace(const std::string& namespace_id) {
  return false;
}

bool StorageManager::DropNamespace(const std::string& namespace_id) {
  return false;
}

Namespace* StorageManager::GetNamespaceAtMount(const std::string& point) const {
  return namespace_manager_->GetNamespaceAtMount(point);
}

bool StorageManager::Mount(const std::string& point, const base::UUID& target_ds) {
  return namespace_manager_->Mount(point, target_ds);
}

bool StorageManager::Unmount(const std::string& point) {
  return namespace_manager_->Unmount(point);
}

void StorageManager::InitializeImpl(disk::DiskManager* manager) {
  //DLOG(INFO) << "StorageManager::InitializeImpl";
  
  disk_ = manager->OpenDisk(storage_path_.BaseName().value());

  if (!disk_) {
    LOG(ERROR) << "failed to load disk at " << storage_path_;
    origin_task_runner_->PostTask(
      FROM_HERE, 
      base::BindOnce(&StorageManager::NotifyInit, base::Unretained(this), false));
    return; 
  }

  namespace_manager_->Initialize(disk_, background_task_runner_);
  //CreateTestNamespace();
  //DLOG(INFO) << "StorageManager::InitializeImpl: setting result";
  origin_task_runner_->PostTask(
      FROM_HERE, 
      base::BindOnce(&StorageManager::NotifyInit, base::Unretained(this), true));
  //DLOG(INFO) << "StorageManager::InitializeImpl end";
}

void StorageManager::NotifyInit(bool result) const {
  //DLOG(INFO) << "StorageManager::NotifyInit";
  DCHECK(delegate_);
  delegate_->OnStorageManagerInit(result);

  //DLOG(INFO) << "StorageManager::NotifyInit end";
  
}

void StorageManager::CreateTestNamespace() {
  Namespace* module = nullptr;
  // we are creating a ns here just for test
  //LOG(INFO) << "ns count: " << namespace_manager_->namespace_count();

  if (namespace_manager_->namespace_count() > 0) {
    module = namespace_manager_->GetNamespaceAt(0);
    if (!module) {
      LOG(INFO) << "odd. namespace_manager_->GetNamespaceAt(0) returned null when namespace count > 0";  
    }
  }
  
  //for (auto it = namespace_manager_->namespaces_begin(); it != namespace_manager_->namespaces_end(); it++) {
  //  LOG(INFO) << "iterating namespace " << it->first.to_string();
  //  test = it->second.get();
  //  if (test) {
  //    LOG(INFO) << "namespace " << it->first.to_string() << " found. reusing";
  //    break;
  //  } else {
  //    LOG(INFO) << "odd. the pointer for the namespace " << it->first.to_string() << " is null";
  //  }
  //}

  if (!module) {
    LOG(INFO) << "no namespace found. creating a new one";
   
    module = namespace_manager_->CreateNamespace(
      true, 
      base::Bind(&StorageManager::CreateHelloConcept, base::Unretained(this)),
      background_task_runner_);
  }
 
  if (!module) {
    //DLOG(ERROR) << "creation of the namespace 'module' failed";
    return;
  }

  namespace_manager_->Mount("module", module->id());
}

void StorageManager::CreateHelloConcept(Namespace* ns) {
  DCHECK(ns);
  if (!ns->initialized()) {
    LOG(ERROR) << "namespace not initialized yet. cant add the concept";
    return;
  }
  //ConceptNode* hello_concept = ns->CreateConcept("hello", "module");
  //hello_concept->up();
}

void StorageManager::OnCreateNamespace(Namespace* ns) {
  //LOG(INFO) << "StorageManager::OnCreateNamespace. ds: " << (ns ? ns->id().to_string() : "null");
}

}