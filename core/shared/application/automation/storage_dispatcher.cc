// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/application/automation/storage_dispatcher.h"

#include "services/service_manager/public/cpp/interface_provider.h"
#include "ipc/ipc_sync_channel.h"

namespace application {

// static 
void StorageDispatcher::Create(automation::StorageRequest request, PageInstance* page_instance) {
   new StorageDispatcher(std::move(request), page_instance);
}

StorageDispatcher::StorageDispatcher(automation::StorageRequest request, PageInstance* page_instance): 
  application_id_(-1),
  page_instance_(page_instance),
  binding_(this) {
  
}

StorageDispatcher::StorageDispatcher(PageInstance* page_instance): 
  application_id_(-1),
  page_instance_(page_instance),
  binding_(this) {
  
}

StorageDispatcher::~StorageDispatcher() {

}

void StorageDispatcher::Init(IPC::SyncChannel* channel) {
  channel->GetRemoteAssociatedInterface(&storage_client_ptr_);
}

void StorageDispatcher::Bind(automation::StorageAssociatedRequest request) {
  //DLOG(INFO) << "StorageDispatcher::Bind (application)";
  binding_.Bind(std::move(request));  
}

void StorageDispatcher::Register(int32_t application_id) {
  application_id_ = application_id;
}

void StorageDispatcher::ClearDataForOrigin(const std::string& origin, const std::vector<automation::StorageType>& storage_types) {}
void StorageDispatcher::GetUsageAndQuota(const std::string& origin, int64_t usage, int64_t quota, std::vector<automation::UsageForTypePtr> usage_breakdown) {}
void StorageDispatcher::TrackCacheStorageForOrigin(const std::string& origin) {}
void StorageDispatcher::TrackIndexedDBForOrigin(const std::string& origin) {}
void StorageDispatcher::UntrackCacheStorageForOrigin(const std::string& origin) {}
void StorageDispatcher::UntrackIndexedDBForOrigin(const std::string& origin) {}

void StorageDispatcher::OnWebFrameCreated(blink::WebLocalFrame* web_frame) {

}

}