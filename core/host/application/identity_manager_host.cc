// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/application/identity_manager_host.h"

namespace host {

IdentityManagerHost::IdentityManagerHost(): identity_manager_host_binding_(this) {
  
}

IdentityManagerHost::~IdentityManagerHost() {

}

common::mojom::IdentityManagerClient* IdentityManagerHost::GetIdentityManagerClientInterface() {
  return identity_manager_client_interface_.get();
}

void IdentityManagerHost::AddBinding(common::mojom::IdentityManagerHostAssociatedRequest request) {
  identity_manager_host_binding_.Bind(std::move(request));
}

void IdentityManagerHost::IdentityList(IdentityListCallback callback) {

}

void IdentityManagerHost::IdentityGet(const std::string& uuid, IdentityGetCallback callback) {

}

}