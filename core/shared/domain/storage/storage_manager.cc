// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/domain/storage/storage_manager.h"

#include "base/task_scheduler/post_task.h"
#include "base/threading/sequenced_task_runner_handle.h"
#include "core/shared/common/mojom/storage.mojom.h"
#include "core/domain/domain_main_thread.h"
#include "core/shared/domain/storage/storage_context.h"
#include "core/shared/domain/storage/storage_dispatcher.h"

namespace domain {

// static 
StoragePolicy StoragePolicy::Default() {
  return StoragePolicy();
}

StorageManager::StorageManager(Delegate* delegate, const base::FilePath& path):
 storage_path_(path),
 delegate_(delegate),
 storage_dispatcher_(nullptr) {//,
// main_task_runner_(base::ThreadTaskRunnerHandle::Get()) {//,
 //background_task_runner_(
 //     base::CreateSequencedTaskRunnerWithTraits(
 //       { base::MayBlock(), 
 //         base::TaskPriority::BACKGROUND })) {
  
}

StorageManager::~StorageManager() {

}

void StorageManager::Initialize(
  StorageDispatcher* dispatcher, 
  scoped_refptr<base::SingleThreadTaskRunner> main_task_runner,
  scoped_refptr<base::SingleThreadTaskRunner> io_task_runner, 
  StoragePolicy policy) {
  //DCHECK(base::SequencedTaskRunnerHandle::IsSet());
  //origin_task_runner_ = base::SequencedTaskRunnerHandle::Get();
  
  policy_ = policy;
  main_task_runner_ = main_task_runner;
  io_task_runner_ = io_task_runner;
  storage_dispatcher_ = dispatcher;
  storage_dispatcher_->set_storage_manager(this);

  //background_task_runner_->PostTask(
  //  FROM_HERE,
  //  base::BindOnce(&StorageManager::InitializeImpl, 
  //    base::Unretained(this)));
  InitializeImpl();
}

void StorageManager::Shutdown() {
 
}

scoped_refptr<StorageContext> StorageManager::CreateContext(base::Callback<void(scoped_refptr<StorageContext>)> cb) {
  scoped_refptr<StorageContext> context = scoped_refptr<StorageContext>(new StorageContext(this));
  if (!main_task_runner_->BelongsToCurrentThread()) {
    main_task_runner_->PostTask(FROM_HERE, base::BindOnce(&StorageManager::DispatchContextCreation, base::Unretained(this), context, base::Passed(std::move(cb))));
  }
  else {
    DispatchContextCreation(context, std::move(cb));
  }
  return context;
}

scoped_refptr<StorageContext> StorageManager::GetContext(int id) {
  auto it = contexts_.find(id);
  if (it != contexts_.end()) {
    return it->second;
  }
  return scoped_refptr<StorageContext>();
}

scoped_refptr<StorageContext> StorageManager::GetOrCreateContext() {
  for (auto it = contexts_.begin(); it != contexts_.end(); ++it) {
    // return any
    return it->second;
  }
  return CreateContext();
}

void StorageManager::DestroyContext(int id) {
  auto it = contexts_.find(id);
  if (it != contexts_.end()) {
    contexts_.erase(it);
  }
}

const base::FilePath& StorageManager::GetStoragePath() {
  return storage_path_; 
}

void StorageManager::GetTotalAllocatedSize(base::Callback<void(int64_t)> callback) {
  scoped_refptr<StorageContext> context = GetOrCreateContext();
  context->GetAllocatedSize(std::move(callback));
}

void StorageManager::OnContextCreate(scoped_refptr<StorageContext> context, base::Callback<void(scoped_refptr<StorageContext>)> cb, common::mojom::StorageContextPtr shared_context) {
  int id = shared_context->id;
  context->set_shared_context(std::move(shared_context));
  contexts_.emplace(std::make_pair(id, context));
  if (!cb.is_null()) {
    std::move(cb).Run(context);
  }
}

void StorageManager::InitializeImpl() {
  //DLOG(INFO) << "StorageManager::InitializeImpl: setting result";
  //origin_task_runner_->PostTask(
    //  FROM_HERE, 
  //    base::BindOnce(&StorageManager::NotifyInit, base::Unretained(this), true));
  NotifyInit(true);
}

void StorageManager::DispatchContextCreation(scoped_refptr<StorageContext> context, base::Callback<void(scoped_refptr<StorageContext>)> cb) {
  common::mojom::StorageParametersPtr params = common::mojom::StorageParameters::New();
  
  storage_dispatcher_->GetStorageDispatcherHostInterface()->ContextCreate(
    std::move(params), 
    base::Bind(&StorageManager::OnContextCreate, 
      base::Unretained(this), 
      context, 
      base::Passed(std::move(cb))));
}

void StorageManager::NotifyInit(bool result) const {
  DCHECK(delegate_);
  delegate_->OnStorageManagerInit(result);  
}

}