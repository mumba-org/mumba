// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_APPLICATION_HOST_DOMAIN_MANAGER_H_
#define MUMBA_HOST_APPLICATION_HOST_DOMAIN_MANAGER_H_

#include "base/macros.h"
#include "base/memory/weak_ptr.h"
#include "core/host/application/domain_management_service_impl.h"

namespace host {

class HostDomainManager : public common::mojom::DomainManagementServiceClient {
public:
  HostDomainManager();
  ~HostDomainManager() override;

  base::WeakPtr<HostDomainManager> GetWeakPtr() { 
    return weak_factory_.GetWeakPtr();
  }

  void CreateDomain(const std::string& name);
  void DropDomain(const std::string& name);
  void StartDomain(const std::string& name);
  void StopDomain(const std::string& name);

private:

  void OnCreateDomain(common::mojom::DomainStatus status, common::mojom::DomainHandlePtr info) override;
  void OnDropDomain(common::mojom::DomainStatus status, common::mojom::DomainHandlePtr info) override;
  void OnStartDomain(common::mojom::DomainStatus status, common::mojom::DomainHandlePtr info) override;
  void OnStopDomain(common::mojom::DomainStatus status, common::mojom::DomainHandlePtr info) override;
 
  common::mojom::DomainManagementServicePtr domain_control_;

  base::WeakPtrFactory<HostDomainManager> weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(HostDomainManager);
};

}

#endif