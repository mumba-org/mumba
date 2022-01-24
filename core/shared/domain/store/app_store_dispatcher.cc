// Copyright (c) 2022 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/domain/store/app_store_dispatcher.h"

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

AppStoreDispatcher::AppStoreDispatcher():
 weak_ptr_factory_(this) {

}

AppStoreDispatcher::~AppStoreDispatcher() {

}

void AppStoreDispatcher::Initialize(scoped_refptr<base::SingleThreadTaskRunner> task_runner) {
  task_runner_ = task_runner;
}

void AppStoreDispatcher::AddEntry(common::mojom::AppStoreEntryPtr entry, AddEntryCallback callback) {
  app_store_dispatcher_->AddEntry(std::move(entry), std::move(callback));
}

void AppStoreDispatcher::AddEntryByAddress(common::mojom::AppStoreEntryDescriptorPtr descriptor, AddEntryByAddressCallback callback) {
  app_store_dispatcher_->AddEntryByAddress(std::move(descriptor), std::move(callback));
}

void AppStoreDispatcher::RemoveEntry(const std::string& address, RemoveEntryCallback callback) {
  app_store_dispatcher_->RemoveEntry(address, std::move(callback));
}

void AppStoreDispatcher::RemoveEntryByUUID(const std::string& uuid, RemoveEntryByUUIDCallback callback) {
  app_store_dispatcher_->RemoveEntryByUUID(uuid, std::move(callback));
}

void AppStoreDispatcher::LookupEntry(const std::string& query, LookupEntryCallback callback) {
  app_store_dispatcher_->LookupEntry(query, std::move(callback));
}

void AppStoreDispatcher::LookupEntryByName(const std::string& name, LookupEntryByNameCallback callback) {
  app_store_dispatcher_->LookupEntryByName(name, std::move(callback));
}

void AppStoreDispatcher::LookupEntryByUUID(const std::string& uuid, LookupEntryByUUIDCallback callback) {
  app_store_dispatcher_->LookupEntryByUUID(uuid, std::move(callback));
}

void AppStoreDispatcher::HaveEntry(const std::string& address, HaveEntryCallback callback) {
  app_store_dispatcher_->HaveEntry(address, std::move(callback));
}

void AppStoreDispatcher::HaveEntryByName(const std::string& name, HaveEntryByNameCallback callback) {
  app_store_dispatcher_->HaveEntryByName(name, std::move(callback));
}

void AppStoreDispatcher::HaveEntryByUUID(const std::string& uuid, HaveEntryByUUIDCallback callback) {
  app_store_dispatcher_->HaveEntryByUUID(uuid, std::move(callback));
}

void AppStoreDispatcher::ListEntries(ListEntriesCallback callback) {
  app_store_dispatcher_->ListEntries(std::move(callback));
}

void AppStoreDispatcher::GetEntryCount(GetEntryCountCallback callback) {
  app_store_dispatcher_->GetEntryCount(std::move(callback));
}

void AppStoreDispatcher::AddWatcher(common::mojom::AppStoreWatcherPtr subscriber, AddWatcherCallback callback) {
  app_store_dispatcher_->AddWatcher(std::move(subscriber), std::move(callback));
}

void AppStoreDispatcher::RemoveWatcher(int32_t subscriber_id) {
  app_store_dispatcher_->RemoveWatcher(subscriber_id);
}

}