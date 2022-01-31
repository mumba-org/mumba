// Copyright (c) 2022 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/domain/repo/repo_dispatcher.h"

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
#include "services/network/resource_scheduler_client.h"

namespace domain {

RepoDispatcher::RepoDispatcher():
 weak_ptr_factory_(this) {

}

RepoDispatcher::~RepoDispatcher() {

}

void RepoDispatcher::Initialize(scoped_refptr<base::SingleThreadTaskRunner> task_runner) {
  task_runner_ = task_runner;
}

void RepoDispatcher::AddRepo(common::mojom::RepoEntryPtr entry, AddRepoCallback callback) {
  DLOG(INFO) << "RepoDispatcher::AddRepo";
  repo_dispatcher_->AddRepo(std::move(entry), std::move(callback));
}

void RepoDispatcher::AddRepoByAddress(common::mojom::RepoDescriptorPtr descriptor, AddRepoByAddressCallback callback) {
  repo_dispatcher_->AddRepoByAddress(std::move(descriptor), std::move(callback));
}

void RepoDispatcher::RemoveRepo(const std::string& address, RemoveRepoCallback callback) {
  repo_dispatcher_->RemoveRepo(address, std::move(callback));
}

void RepoDispatcher::RemoveRepoByUUID(const std::string& uuid, RemoveRepoByUUIDCallback callback) {
  repo_dispatcher_->RemoveRepoByUUID(uuid, std::move(callback));
}
  
void RepoDispatcher::LookupRepo(const std::string& address, LookupRepoCallback callback) {
  repo_dispatcher_->LookupRepo(address, std::move(callback));
}

void RepoDispatcher::LookupRepoByName(const std::string& name, LookupRepoByNameCallback callback) {
  repo_dispatcher_->LookupRepoByName(name, std::move(callback));
}

void RepoDispatcher::LookupRepoByUUID(const std::string& uuid, LookupRepoByUUIDCallback callback) {
  repo_dispatcher_->LookupRepoByUUID(uuid, std::move(callback));
}

void RepoDispatcher::GetRepoCount(GetRepoCountCallback callback) {
  repo_dispatcher_->GetRepoCount(std::move(callback));
}

void RepoDispatcher::HaveRepo(const std::string& address, HaveRepoCallback callback) {
  repo_dispatcher_->HaveRepo(address, std::move(callback));
}

void RepoDispatcher::HaveRepoByName(const std::string& name, HaveRepoByNameCallback callback) {
  repo_dispatcher_->HaveRepoByName(name, std::move(callback));
}

void RepoDispatcher::HaveRepoByUUID(const std::string& uuid, HaveRepoByUUIDCallback callback) {
  repo_dispatcher_->HaveRepoByUUID(uuid, std::move(callback));
}

void RepoDispatcher::ListRepos(ListReposCallback callback) {
  repo_dispatcher_->ListRepos(std::move(callback));
}

void RepoDispatcher::AddWatcher(common::mojom::RepoWatcherPtr watcher, AddWatcherCallback callback) {
  repo_dispatcher_->AddWatcher(std::move(watcher), std::move(callback));
}

void RepoDispatcher::RemoveWatcher(int32_t watcher_id) {
  repo_dispatcher_->RemoveWatcher(watcher_id);
}

}