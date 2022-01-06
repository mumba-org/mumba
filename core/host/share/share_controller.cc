// Copyright 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/share/share_controller.h"

namespace host {

ShareController::ShareController(ShareManager* manager): manager_(manager) {

}

ShareController::~ShareController() {
  manager_ = nullptr;
}

void ShareController::AddShare(const std::string& address) {

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