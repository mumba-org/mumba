// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/application/host_domain_manager.h"

namespace host {

HostDomainManager::HostDomainManager(): weak_factory_(this) {

}

HostDomainManager::~HostDomainManager() {

}

void HostDomainManager::CreateDomain(const std::string& name) {
  domain_control_->CreateDomain(name);
}

void HostDomainManager::DropDomain(const std::string& name) {
  domain_control_->DropDomain(name);
}

void HostDomainManager::StartDomain(const std::string& name) {
  domain_control_->StartDomain(name);
}

void HostDomainManager::StopDomain(const std::string& name) {
  domain_control_->StopDomain(name);
}

void HostDomainManager::OnCreateDomain(common::mojom::DomainStatus status, common::mojom::DomainHandlePtr info) {
  
}

void HostDomainManager::OnDropDomain(common::mojom::DomainStatus status, common::mojom::DomainHandlePtr info) {

}

void HostDomainManager::OnStartDomain(common::mojom::DomainStatus status, common::mojom::DomainHandlePtr info) {

}

void HostDomainManager::OnStopDomain(common::mojom::DomainStatus status, common::mojom::DomainHandlePtr info) {

}

}