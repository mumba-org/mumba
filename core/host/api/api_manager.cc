// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/api/api_manager.h"

#include "core/host/api/api_service.h"

namespace host {

APIManager::APIManager() {

}

APIManager::~APIManager() {

}

APIService* APIManager::CreateAPIService(Share* share, const std::string& id) {
  auto service = std::make_unique<APIService>(share, id);  
  APIService* service_ref = service.get();
  services_.push_back(std::move(service));
  return service_ref;
}

}