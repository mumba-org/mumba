// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/background_fetch/storage/create_metadata_task.h"

#include <utility>

#include "base/strings/string_number_conversions.h"
#include "core/host/background_fetch/storage/database_helpers.h"
#include "core/host/service_worker/service_worker_context_wrapper.h"
#include "core/shared/common/service_worker/service_worker_status_code.h"

namespace host {

namespace background_fetch {

CreateMetadataTask::CreateMetadataTask(
    BackgroundFetchDataManager* data_manager,
    const BackgroundFetchRegistrationId& registration_id,
    const std::vector<common::ServiceWorkerFetchRequest>& requests,
    const common::BackgroundFetchOptions& options,
    CreateMetadataCallback callback)
    : DatabaseTask(data_manager),
      registration_id_(registration_id),
      requests_(requests),
      options_(options),
      callback_(std::move(callback)),
      weak_factory_(this) {}

CreateMetadataTask::~CreateMetadataTask() = default;

void CreateMetadataTask::Start() {
  service_worker_context()->GetRegistrationUserData(
      registration_id_.service_worker_registration_id(),
      {ActiveRegistrationUniqueIdKey(registration_id_.developer_id())},
      base::BindOnce(&CreateMetadataTask::DidGetUniqueId,
                     weak_factory_.GetWeakPtr()));
}

void CreateMetadataTask::DidGetUniqueId(const std::vector<std::string>& data,
                                        common::ServiceWorkerStatusCode status) {
  switch (ToDatabaseStatus(status)) {
    case DatabaseStatus::kNotFound:
      StoreMetadata();
      return;
    case DatabaseStatus::kOk:
      // Can't create a registration since there is already an active
      // registration with the same |developer_id|. It must be deactivated
      // (completed/failed/aborted) first.
      std::move(callback_).Run(
          blink::mojom::BackgroundFetchError::DUPLICATED_DEVELOPER_ID,
          nullptr /* metadata */);
      Finished();  // Destroys |this|.
      return;
    case DatabaseStatus::kFailed:
      std::move(callback_).Run(
          blink::mojom::BackgroundFetchError::STORAGE_ERROR,
          nullptr /* metadata */);
      Finished();  // Destroys |this|.
      return;
  }
}

void CreateMetadataTask::InitializeMetadataProto() {
  metadata_proto_ = std::make_unique<proto::BackgroundFetchMetadata>();
  // Set BackgroundFetchRegistration fields.
  // Upload/Download stats default to correct initial values.
  auto* registration_proto = metadata_proto_->mutable_registration();
  registration_proto->set_unique_id(registration_id_.unique_id());
  registration_proto->set_developer_id(registration_id_.developer_id());

  // Set Options fields.
  auto* options_proto = metadata_proto_->mutable_options();
  options_proto->set_title(options_.title);
  options_proto->set_download_total(options_.download_total);
  for (const auto& icon : options_.icons) {
    auto* icon_definition_proto = options_proto->add_icons();
    icon_definition_proto->set_src(icon.src);
    icon_definition_proto->set_sizes(icon.sizes);
    icon_definition_proto->set_type(icon.type);
  }

  // Set other metadata fields.
  metadata_proto_->set_origin(registration_id_.origin().Serialize());
  metadata_proto_->set_creation_microseconds_since_unix_epoch(
      (base::Time::Now() - base::Time::UnixEpoch()).InMicroseconds());
  metadata_proto_->set_ui_title(options_.title);
}

proto::ServiceWorkerFetchRequest
CreateMetadataTask::CreateServiceWorkerFetchRequestProto(
    const common::ServiceWorkerFetchRequest& request) {
  proto::ServiceWorkerFetchRequest request_proto;
  request_proto.set_url(request.url.spec());
  request_proto.set_method(request.method);
  request_proto.mutable_headers()->insert(request.headers.begin(),
                                          request.headers.end());
  request_proto.mutable_referrer()->set_url(request.referrer.url.spec());
  request_proto.mutable_referrer()->set_policy(request.referrer.policy);
  request_proto.set_is_reload(request.is_reload);

  return request_proto;
}

void CreateMetadataTask::StoreMetadata() {
  std::vector<std::pair<std::string, std::string>> entries;
  entries.reserve(requests_.size() * 2 + 1);

  InitializeMetadataProto();
  std::string serialized_metadata_proto;

  if (!metadata_proto_->SerializeToString(&serialized_metadata_proto)) {
    // TODO(crbug.com/780025): Log failures to UMA.
    std::move(callback_).Run(blink::mojom::BackgroundFetchError::STORAGE_ERROR,
                             nullptr /* metadata */);
    Finished();  // Destroys |this|.
    return;
  }

  entries.emplace_back(
      ActiveRegistrationUniqueIdKey(registration_id_.developer_id()),
      registration_id_.unique_id());
  entries.emplace_back(RegistrationKey(registration_id_.unique_id()),
                       std::move(serialized_metadata_proto));

  // Signed integers are used for request indexes to avoid unsigned gotchas.
  for (int i = 0; i < base::checked_cast<int>(requests_.size()); i++) {
    proto::BackgroundFetchPendingRequest pending_request_proto;
    pending_request_proto.set_unique_id(registration_id_.unique_id());
    pending_request_proto.set_request_index(i);
    *pending_request_proto.mutable_request() =
        CreateServiceWorkerFetchRequestProto(requests_[i]);
    entries.emplace_back(PendingRequestKey(registration_id_.unique_id(), i),
                         pending_request_proto.SerializeAsString());
  }

  service_worker_context()->StoreRegistrationUserData(
      registration_id_.service_worker_registration_id(),
      registration_id_.origin().GetURL(), entries,
      base::BindRepeating(&CreateMetadataTask::DidStoreMetadata,
                          weak_factory_.GetWeakPtr()));
}

void CreateMetadataTask::DidStoreMetadata(common::ServiceWorkerStatusCode status) {
  DCHECK(metadata_proto_);

  switch (ToDatabaseStatus(status)) {
    case DatabaseStatus::kOk:
      break;
    case DatabaseStatus::kFailed:
    case DatabaseStatus::kNotFound:
      std::move(callback_).Run(
          blink::mojom::BackgroundFetchError::STORAGE_ERROR,
          nullptr /* metadata */);
      Finished();  // Destroys |this|.
      return;
  }

  std::move(callback_).Run(blink::mojom::BackgroundFetchError::NONE,
                           std::move(metadata_proto_));
  Finished();  // Destroys |this|.
}
}  // namespace background_fetch

}  // namespace host
