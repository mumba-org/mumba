// Copyright (c) 2022 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/store/app_store_controller.h"

#include "base/base64.h"
#include "base/bind.h"
#include "base/task_scheduler/post_task.h"
#include "net/base/net_errors.h"
#include "core/shared/common/paths.h"
#include "core/host/host_thread.h"
#include "core/host/store/app_store.h"
#include "core/host/store/app_store_entry.h"
#include "core/host/share/share_controller.h"

namespace host {

AppStoreController::AppStoreController(AppStore* app_store, ShareController* share_controller):
 store_(app_store),
 share_controller_(share_controller) {

}

AppStoreController::~AppStoreController() {

}
  
void AppStoreController::InsertEntryByDHTAddress(const std::string& base64_address, base::Callback<void(int)> callback) {
  std::string decoded_bytes;
  if (!base::Base64Decode(base64_address, &decoded_bytes)) {
    std::move(callback).Run(net::ERR_FAILED);
    return;
  }
  share_controller_->CloneStorageWithDHTAddress(decoded_bytes, base::Bind(&AppStoreController::OnStorageCloned,
                                                                          base::Unretained(this),
                                                                          base::Passed(std::move(callback))));
}

void AppStoreController::InsertEntryByInfohashAddress(const std::string& infohash, base::Callback<void(int)> callback) {
  share_controller_->CreateShareWithInfohash(infohash, base::Bind(&AppStoreController::OnShareCreated,
                                                                   base::Unretained(this),
                                                                   base::Passed(std::move(callback))));
}
  
void AppStoreController::InsertEntry(std::unique_ptr<AppStoreEntry> entry) {
  store_->InsertEntry(std::move(entry));
}

bool AppStoreController::RemoveEntry(AppStoreEntry* entry) {
  return store_->RemoveEntry(entry);
}

bool AppStoreController::RemoveEntry(const base::UUID& uuid) {
  return store_->RemoveEntry(uuid);
}

bool AppStoreController::RemoveEntry(const std::string& address) {
  auto* entry = store_->GetEntryByName(address);
  if (!entry) {
    return false;
  }
  return store_->RemoveEntry(entry);
}

AppStoreEntry* AppStoreController::LookupEntry(const std::string& address) const {
  return store_->GetEntryByName(address);
}

AppStoreEntry* AppStoreController::LookupEntryByName(const std::string& name) const {
  return store_->GetEntryByName(name);
}

AppStoreEntry* AppStoreController::LookupEntryByUUID(const base::UUID& uuid) const {
  return store_->GetEntryById(uuid);
}

bool AppStoreController::HaveEntry(const std::string& address) const {
  return store_->EntryExists(address);
}

bool AppStoreController::HaveEntryByName(const std::string& name) const {
  return store_->EntryExists(name);
}

bool AppStoreController::HaveEntryByUUID(const base::UUID& uuid) const {
  return store_->EntryExists(uuid);
}

std::vector<AppStoreEntry*> AppStoreController::ListEntries() const {
  std::vector<AppStoreEntry*> result;
  const auto& entries = store_->GetEntries();
  for (const auto& entry : entries) {
    result.push_back(entry.get());
  }
  return result;
}

size_t AppStoreController::GetEntryCount() const {
  return store_->GetEntryCount();
}

void AppStoreController::OnStorageCloned(base::Callback<void(int)> callback, int result) {
  // FIXME: the idea here is to add a AppStoreEntry before calling the user callback
  std::move(callback).Run(result);
}

void AppStoreController::OnShareCreated(base::Callback<void(int)> callback, int64_t result) {
  // FIXME: the idea here is to add a AppStoreEntry before calling the user callback
  std::move(callback).Run(result);
}

}