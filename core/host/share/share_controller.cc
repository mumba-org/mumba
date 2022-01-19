// Copyright 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/share/share_controller.h"

#include "base/base64.h"
#include "net/base/net_errors.h"
#include "core/host/share/share_manager.h"

namespace host {

ShareController::ShareController(ShareManager* manager): manager_(manager) {

}

ShareController::~ShareController() {
  
}

void ShareController::CloneStorageWithDHTAddress(const std::string& dht_address_base64, base::Callback<void(int)> callback) {
  std::string bytes;
  if (!base::Base64Decode(dht_address_base64, &bytes)) {
    std::move(callback).Run(net::ERR_FAILED);
    return;
  }
  manager_->CloneStorageWithDHTAddress(bytes, std::move(callback));
}

void ShareController::CreateShareWithPath(const std::string& address) {

}

void ShareController::CreateShareWithInfohash(const std::string& address, base::Callback<void(int64_t)> callback) {

}

void ShareController::RemoveShare(const std::string& address) {

}

void ShareController::RemoveShare(const base::UUID& uuid) {

}

void ShareController::LookupShareByAddress(const std::string& address) {

}

void ShareController::LookupShareByName(const std::string& name) {

}

void ShareController::LookupShareByUUID(const base::UUID& id) {

}

bool ShareController::HaveShareByAddress(const std::string& address) {
  return false;
}

bool ShareController::HaveShareByName(const std::string& name) {
  return false;
}

bool ShareController::HaveShareByUUID(const base::UUID& id) {
  return false;
}

std::vector<Share*> ShareController::ListShares() {
  return std::vector<Share*>();
}

std::vector<Share*> ShareController::ListSharesByDomain(const std::string& domain_name) {
  return std::vector<Share*>();
}

uint32_t ShareController::CountShares() {
  return 0;
}

}