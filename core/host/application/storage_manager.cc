// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/application/storage_manager.h"

#include "base/memory/ref_counted.h"
#include "core/host/workspace/workspace.h"
#include "core/host/application/storage_context.h"

namespace host {

StorageManager::StorageManager(scoped_refptr<Workspace> workspace): workspace_(workspace) {
  
}

StorageManager::~StorageManager() {
  
}

scoped_refptr<StorageContext> StorageManager::CreateContext(Domain* shell) {
  int context_id = context_seq_.GetNext() + 1;
  scoped_refptr<StorageContext> context(new StorageContext(context_id, workspace_, shell));
  contexts_.emplace(std::make_pair(context_id, context));
  return context;
}

scoped_refptr<StorageContext> StorageManager::GetContext(int context_id) {
  auto it = contexts_.find(context_id);
  if (it == contexts_.end()) {
    return scoped_refptr<StorageContext>();
  }
  return it->second;
}

void StorageManager::DestroyContext(int context_id) {
  auto it = contexts_.find(context_id);
  if (it != contexts_.end()) {
    contexts_.erase(it);
  }

}

}
