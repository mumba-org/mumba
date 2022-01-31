// Copyright (c) 2022 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/domain/collection/collection_dispatcher.h"

#include <string>

#include "base/files/file.h"
#include "base/memory/weak_ptr.h"
#include "base/metrics/histogram_macros.h"
#include "base/task_scheduler/post_task.h"
#include "base/threading/thread_task_runner_handle.h"
#include "base/time/time.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "mojo/public/cpp/system/simple_watcher.h"
#include "mojo/public/cpp/system/data_pipe.h"
#include "mojo/public/cpp/system/data_pipe_utils.h"
#include "net/base/completion_once_callback.h"
#include "net/base/io_buffer.h"
#include "net/log/net_log_with_source.h"
#include "services/network/public/cpp/resource_request_body.h"
#include "services/network/public/mojom/chunked_data_pipe_getter.mojom.h"
#include "services/network/test_chunked_data_pipe_getter.h"
#include "services/network/chunked_data_pipe_upload_data_stream.h"
#include "services/network/data_pipe_element_reader.h"
#include "services/network/loader_util.h"
#include "services/network/public/cpp/features.h"
#include "services/network/public/cpp/net_adapters.h"
#include "services/network/public/cpp/resource_request.h"
#include "services/network/public/cpp/resource_response.h"
#include "services/network/public/mojom/url_loader_factory.mojom.h"

namespace domain {

CollectionDispatcher::CollectionDispatcher():
 weak_ptr_factory_(this) {

}

CollectionDispatcher::~CollectionDispatcher() {

}

void CollectionDispatcher::Initialize(scoped_refptr<base::SingleThreadTaskRunner> task_runner) {
  task_runner_ = task_runner;
}

void CollectionDispatcher::AddEntry(common::mojom::CollectionEntryPtr entry, AddEntryCallback callback) {
  collection_dispatcher_->AddEntry(std::move(entry), std::move(callback));
}

void CollectionDispatcher::AddEntryByAddress(common::mojom::CollectionEntryDescriptorPtr descriptor, AddEntryByAddressCallback callback) {
  collection_dispatcher_->AddEntryByAddress(std::move(descriptor), std::move(callback));
}

void CollectionDispatcher::RemoveEntry(const std::string& address, RemoveEntryCallback callback) {
  collection_dispatcher_->RemoveEntry(address, std::move(callback));
}

void CollectionDispatcher::RemoveEntryByUUID(const std::string& uuid, RemoveEntryByUUIDCallback callback) {
  collection_dispatcher_->RemoveEntryByUUID(uuid, std::move(callback));
}

void CollectionDispatcher::LookupEntry(const std::string& query, LookupEntryCallback callback) {
  collection_dispatcher_->LookupEntry(query, std::move(callback));
}

void CollectionDispatcher::LookupEntryByName(const std::string& name, LookupEntryByNameCallback callback) {
  collection_dispatcher_->LookupEntryByName(name, std::move(callback));
}

void CollectionDispatcher::LookupEntryByUUID(const std::string& uuid, LookupEntryByUUIDCallback callback) {
  collection_dispatcher_->LookupEntryByUUID(uuid, std::move(callback));
}

void CollectionDispatcher::HaveEntry(const std::string& address, HaveEntryCallback callback) {
  collection_dispatcher_->HaveEntry(address, std::move(callback));
}

void CollectionDispatcher::HaveEntryByName(const std::string& name, HaveEntryByNameCallback callback) {
  collection_dispatcher_->HaveEntryByName(name, std::move(callback));
}

void CollectionDispatcher::HaveEntryByUUID(const std::string& uuid, HaveEntryByUUIDCallback callback) {
  collection_dispatcher_->HaveEntryByUUID(uuid, std::move(callback));
}

void CollectionDispatcher::ListEntries(ListEntriesCallback callback) {
  collection_dispatcher_->ListEntries(std::move(callback));
}

void CollectionDispatcher::GetEntryCount(GetEntryCountCallback callback) {
  collection_dispatcher_->GetEntryCount(std::move(callback));
}

void CollectionDispatcher::AddWatcher(common::mojom::CollectionWatcherPtr subscriber, AddWatcherCallback callback) {
  collection_dispatcher_->AddWatcher(std::move(subscriber), std::move(callback));
}

void CollectionDispatcher::RemoveWatcher(int32_t subscriber_id) {
  collection_dispatcher_->RemoveWatcher(subscriber_id);
}

}