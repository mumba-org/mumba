// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/background_fetch/storage/database_task.h"

#include <utility>

#include "core/host/background_fetch/background_fetch_data_manager.h"
#include "core/host/background_fetch/storage/database_helpers.h"
#include "core/host/host_thread.h"

namespace host {

namespace background_fetch {

void DatabaseTask::Finished() {
  DCHECK_CURRENTLY_ON(HostThread::IO);

  data_manager_->OnDatabaseTaskFinished(this);
}

void DatabaseTask::AddDatabaseTask(std::unique_ptr<DatabaseTask> task) {
  data_manager_->AddDatabaseTask(std::move(task));
}

ServiceWorkerContextWrapper* DatabaseTask::service_worker_context() {
  DCHECK(data_manager_->service_worker_context_);
  return data_manager_->service_worker_context_.get();
}

std::set<std::string>& DatabaseTask::ref_counted_unique_ids() {
  return data_manager_->ref_counted_unique_ids_;
}

}  // namespace background_fetch

}  // namespace host
