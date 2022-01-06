// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/domain/storage/storage_index.h"

#include "base/task_scheduler/post_task.h"
#include "net/base/net_errors.h"
#include "core/shared/domain/storage/storage_context.h"

namespace domain {

// namespace {

// void ResolveUUID(base::WaitableEvent* event, base::UUID* id, base::UUID reply, int r) {
//   if (r == net::OK) {
//     *id = std::move(reply);
//   }
//   if (event) {
//     event->Signal();
//   }
// }

// }

StorageIndex::StorageIndex(scoped_refptr<StorageContext> context): 
  context_(context) {

}

StorageIndex::~StorageIndex() {
  
}

//bool StorageIndex::ResolveId(const std::string& address, base::UUID* id) {
  //base::WaitableEvent event{ base::WaitableEvent::ResetPolicy::MANUAL, 
  //                           base::WaitableEvent::InitialState::NOT_SIGNALED };
  //base::PostTaskWithTraits(
  //  FROM_HERE, 
  //  { base::MayBlock(), base::WithBaseSyncPrimitives() },
  //  base::Bind(&StorageIndex::ResolveIdAsync, base::Unretained(this), address, 
  //    base::Bind(&ResolveUUID, base::Unretained(&event), base::Unretained(id))));
  //event.Wait();
//  return id->IsNull();
//}

void StorageIndex::ResolveIdAsync(const std::string& address, base::Callback<void(base::UUID, int)> callback) {
  context_->IndexResolveId(address, std::move(callback));
}

}