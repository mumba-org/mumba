// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_APPLICATION_DOMAIN_MANAGEMENT_SERVICE_IMPL_H_
#define MUMBA_HOST_APPLICATION_DOMAIN_MANAGEMENT_SERVICE_IMPL_H_

#include "base/macros.h"
#include "core/shared/common/mojom/domain_management.mojom.h"
#include "services/service_manager/public/cpp/service_context_ref.h"

namespace host {

class DomainManagementServiceImpl : public common::mojom::DomainManagementService {
public:
  DomainManagementServiceImpl(base::WeakPtr<common::mojom::DomainManagementServiceClient> client);
  ~DomainManagementServiceImpl() override;

  void CreateDomain(const std::string& name) override;
  void DropDomain(const std::string& name) override;
  void StartDomain(const std::string& name) override;
  void StopDomain(const std::string& name) override;
  void GetDomainState(const std::string& name, GetDomainStateCallback callback) override;
  void GetDomainList(GetDomainListCallback callback) override;

private:

  base::WeakPtr<common::mojom::DomainManagementServiceClient> client_;

  DISALLOW_COPY_AND_ASSIGN(DomainManagementServiceImpl);
};

}

#endif