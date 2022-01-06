// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_BROWSER_BACKGROUND_FETCH_STORAGE_CREATE_METADATA_TASK_H_
#define CONTENT_BROWSER_BACKGROUND_FETCH_STORAGE_CREATE_METADATA_TASK_H_

#include <memory>
#include <string>
#include <vector>

#include "core/host/background_fetch/background_fetch.pb.h"
#include "core/host/background_fetch/storage/database_task.h"
#include "core/shared/common/service_worker/service_worker_status_code.h"
#include "third_party/blink/public/platform/modules/background_fetch/background_fetch.mojom.h"

namespace host {

namespace background_fetch {

// Creates Background Fetch metadata entries in the database.
class CreateMetadataTask : public DatabaseTask {
 public:
  using CreateMetadataCallback =
      base::OnceCallback<void(blink::mojom::BackgroundFetchError,
                              std::unique_ptr<proto::BackgroundFetchMetadata>)>;

  CreateMetadataTask(BackgroundFetchDataManager* data_manager,
                     const BackgroundFetchRegistrationId& registration_id,
                     const std::vector<common::ServiceWorkerFetchRequest>& requests,
                     const common::BackgroundFetchOptions& options,
                     CreateMetadataCallback callback);

  ~CreateMetadataTask() override;

  void Start() override;

 private:
  void DidGetUniqueId(const std::vector<std::string>& data,
                      common::ServiceWorkerStatusCode status);

  void StoreMetadata();

  void DidStoreMetadata(common::ServiceWorkerStatusCode status);

  void InitializeMetadataProto();

  proto::ServiceWorkerFetchRequest CreateServiceWorkerFetchRequestProto(
      const common::ServiceWorkerFetchRequest& request);

  BackgroundFetchRegistrationId registration_id_;
  std::vector<common::ServiceWorkerFetchRequest> requests_;
  common::BackgroundFetchOptions options_;
  CreateMetadataCallback callback_;

  std::unique_ptr<proto::BackgroundFetchMetadata> metadata_proto_;

  base::WeakPtrFactory<CreateMetadataTask> weak_factory_;  // Keep as last.

  DISALLOW_COPY_AND_ASSIGN(CreateMetadataTask);
};

}  // namespace background_fetch

}  // namespace host

#endif  // CONTENT_BROWSER_BACKGROUND_FETCH_STORAGE_CREATE_METADATA_TASK_H_
