// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_APPLICATION_MOJO_DOMAIN_CONTROL_SERVICE_H_
#define MUMBA_HOST_APPLICATION_MOJO_DOMAIN_CONTROL_SERVICE_H_

#include "base/callback.h"
#include "base/macros.h"
#include "base/memory/weak_ptr.h"
#include "mojo/public/cpp/bindings/binding.h"
#include "mojo/public/cpp/system/core.h"
#include "services/service_manager/public/cpp/binder_registry.h"
#include "services/service_manager/public/cpp/connector.h"
#include "services/service_manager/public/cpp/export.h"
#include "services/service_manager/public/cpp/service.h"
#include "services/service_manager/public/cpp/service_context_ref.h"
#include "core/shared/common/mojom/domain_management.mojom.h"

namespace host {

class MojoDomainManagementService : public service_manager::Service {
public:
  // Factory function for use as an embedded service.
  //static std::unique_ptr<service_manager::Service> Create();

  MojoDomainManagementService(base::WeakPtr<common::mojom::DomainManagementServiceClient> client);
  ~MojoDomainManagementService() override;

  // service_manager::Service:
  void OnStart() override;
  void OnBindInterface(const service_manager::BindSourceInfo& source_info,
                       const std::string& interface_name,
                       mojo::ScopedMessagePipeHandle interface_pipe) override;
private:

  void BindDomainRequest(
      common::mojom::DomainManagementServiceRequest request,
      const service_manager::BindSourceInfo& source_info);

  scoped_refptr<base::SequencedTaskRunner> domain_service_runner_;
  service_manager::BinderRegistryWithArgs<const service_manager::BindSourceInfo&> registry_;

  class DomainManagementHandler;
  std::unique_ptr<DomainManagementHandler> domain_management_handler_;
  base::WeakPtr<common::mojom::DomainManagementServiceClient> client_;

  DISALLOW_COPY_AND_ASSIGN(MojoDomainManagementService);
};

}

#endif