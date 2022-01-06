// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/application/domain_management_service_impl.h"

namespace host {

DomainManagementServiceImpl::DomainManagementServiceImpl(base::WeakPtr<common::mojom::DomainManagementServiceClient> client):
 client_(std::move(client)) {

}

DomainManagementServiceImpl::~DomainManagementServiceImpl() {

}

void DomainManagementServiceImpl::CreateDomain(const std::string& name) {
  LOG(INFO) << "CreateDomain";
  // when we are dealing with real shells, this will only happen
  // after the op in the real shell actually happened
  common::mojom::DomainStatus status = common::mojom::DomainStatus::kOk;
  common::mojom::DomainHandlePtr info;
  client_->OnCreateDomain(status, std::move(info));
}

void DomainManagementServiceImpl::DropDomain(const std::string& name) {
  LOG(INFO) << "DropDomain";
  common::mojom::DomainStatus status = common::mojom::DomainStatus::kOk;
  common::mojom::DomainHandlePtr info;
  client_->OnDropDomain(status, std::move(info));
}

void DomainManagementServiceImpl::StartDomain(const std::string& name) {
  LOG(INFO) << "StartDomain";
  common::mojom::DomainStatus status = common::mojom::DomainStatus::kOk;
  common::mojom::DomainHandlePtr info;
  client_->OnStartDomain(status, std::move(info));
}

void DomainManagementServiceImpl::StopDomain(const std::string& name) {
  LOG(INFO) << "StopDomain";
  common::mojom::DomainStatus status = common::mojom::DomainStatus::kOk;
  common::mojom::DomainHandlePtr info;
  client_->OnStopDomain(status, std::move(info));
}

void DomainManagementServiceImpl::GetDomainState(const std::string& name, GetDomainStateCallback callback) {
  LOG(INFO) << "GetDomainrState";
}

void DomainManagementServiceImpl::GetDomainList(GetDomainListCallback callback) {
  LOG(INFO) << "GetDomainList";
  // mojom::DomainStatus status;
  // mojom::DomainHandlePtr info;
  // client_->OnGetDomains(status, std::move(info));

  // just run the callback will suffice
}

}