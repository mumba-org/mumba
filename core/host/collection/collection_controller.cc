// Copyright (c) 2022 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/collection/collection_controller.h"

#include "base/base64.h"
#include "base/bind.h"
#include "base/task_scheduler/post_task.h"
#include "net/base/net_errors.h"
#include "core/shared/common/paths.h"
#include "core/host/host_thread.h"
#include "core/host/collection/collection.h"
#include "core/host/collection/collection_entry.h"
#include "core/host/share/share_controller.h"

namespace host {

CollectionController::CollectionController(Collection* collection, ShareController* share_controller):
 store_(collection),
 share_controller_(share_controller) {

}

CollectionController::~CollectionController() {

}
  
void CollectionController::InsertEntryByDHTAddress(const std::string& base64_address, base::Callback<void(int)> callback) {
  std::string decoded_bytes;
  if (!base::Base64Decode(base64_address, &decoded_bytes)) {
    std::move(callback).Run(net::ERR_FAILED);
    return;
  }
  share_controller_->CloneStorageWithDHTAddress(decoded_bytes, base::Bind(&CollectionController::OnStorageCloned,
                                                                          base::Unretained(this),
                                                                          base::Passed(std::move(callback))));
}

void CollectionController::InsertEntryByInfohashAddress(const std::string& infohash, base::Callback<void(int)> callback) {
  share_controller_->CreateShareWithInfohash(infohash, base::Bind(&CollectionController::OnShareCreated,
                                                                   base::Unretained(this),
                                                                   base::Passed(std::move(callback))));
}
  
void CollectionController::InsertEntry(std::unique_ptr<CollectionEntry> entry) {
  store_->InsertEntry(std::move(entry));
}

bool CollectionController::RemoveEntry(CollectionEntry* entry) {
  return store_->RemoveEntry(entry);
}

bool CollectionController::RemoveEntry(const base::UUID& uuid) {
  return store_->RemoveEntry(uuid);
}

bool CollectionController::RemoveEntry(const std::string& address) {
  auto* entry = store_->GetEntryByName(address);
  if (!entry) {
    return false;
  }
  return store_->RemoveEntry(entry);
}

CollectionEntry* CollectionController::LookupEntry(const std::string& address) const {
  return store_->GetEntryByName(address);
}

CollectionEntry* CollectionController::LookupEntryByName(const std::string& name) const {
  return store_->GetEntryByName(name);
}

CollectionEntry* CollectionController::LookupEntryByUUID(const base::UUID& uuid) const {
  return store_->GetEntryById(uuid);
}

bool CollectionController::HaveEntry(const std::string& address) const {
  return store_->EntryExists(address);
}

bool CollectionController::HaveEntryByName(const std::string& name) const {
  return store_->EntryExists(name);
}

bool CollectionController::HaveEntryByUUID(const base::UUID& uuid) const {
  return store_->EntryExists(uuid);
}

std::vector<CollectionEntry*> CollectionController::ListEntries() const {
  std::vector<CollectionEntry*> result;
  const auto& entries = store_->GetEntries();
  for (const auto& entry : entries) {
    result.push_back(entry.get());
  }
  return result;
}

size_t CollectionController::GetEntryCount() const {
  return store_->GetEntryCount();
}

void CollectionController::OnStorageCloned(base::Callback<void(int)> callback, int result) {
  // FIXME: the idea here is to add a CollectionEntry before calling the user callback
  std::move(callback).Run(result);
}

void CollectionController::OnShareCreated(base::Callback<void(int)> callback, int64_t result) {
  // FIXME: the idea here is to add a CollectionEntry before calling the user callback
  std::move(callback).Run(result);
}

}