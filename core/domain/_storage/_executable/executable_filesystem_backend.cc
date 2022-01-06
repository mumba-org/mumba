// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/domain/storage/executable/executable_filesystem_backend.h"

#include "base/bind.h"
#include "base/threading/thread_task_runner_handle.h"
#include "base/sequenced_task_runner.h"
#include "base/task_scheduler/post_task.h"
#include "data/buffer.h"
#include "core/shared/domain/storage/namespace.h"
#include "core/domain/domain_thread.h"
#include "net/base/net_errors.h"

namespace domain {

ExecutableFilesystemBackend::ExecutableFilesystemBackend(
  int fs_id,
  const std::string& namespace_id, 
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

ExecutableFilesystemBackend::~ExecutableFilesystemBackend() {

}

void ExecutableFilesystemBackend::Initialize(const base::Callback<void(int, int)>& callback) {
  
}

void ExecutableFilesystemBackend::Shutdown() {
  
}

int ExecutableFilesystemBackend::id() const {
 return fs_id_;
}

FilesystemType ExecutableFilesystemBackend::type() const {
  return FilesystemType::kExecutable;
}

int32_t ExecutableFilesystemBackend::GetFileCount() const {
  return 0;
}

bool ExecutableFilesystemBackend::in_memory() const {
  return in_memory_;
}

void ExecutableFilesystemBackend::InitializeImpl(const base::Callback<void(int, int)>& callback) {

}

void ExecutableFilesystemBackend::ShutdownImpl() {
  
}

}