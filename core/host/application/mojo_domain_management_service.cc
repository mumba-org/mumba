// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/application/mojo_domain_management_service.h"

#include "base/macros.h"
#include "base/task_scheduler/post_task.h"
#include "base/threading/thread_task_runner_handle.h"
#include "base/time/time.h"
#include "mojo/public/cpp/bindings/strong_binding.h"
#include "core/host/application/domain_management_service_impl.h"
#include "services/service_manager/public/cpp/service_context.h"

namespace host {

class MojoDomainManagementService::DomainManagementHandler : public base::SupportsWeakPtr<DomainManagementHandler> {
public: 
  // Created on the main thread.
  DomainManagementHandler() {}
  // Destroyed on the |domain_service_runner_|.
  ~DomainManagementHandler() {}

  // Called on the |domain_service_runner_|.
  void OnDomainRequest(const service_manager::Identity& remote_identity,
                          base::WeakPtr<common::mojom::DomainManagementServiceClient> client,
                          common::mojom::DomainManagementServiceRequest request) {
    mojo::MakeStrongBinding(
        std::make_unique<DomainManagementServiceImpl>(std::move(client)),
        std::move(request));
  }

 private:

  DISALLOW_COPY_AND_ASSIGN(DomainManagementHandler);
};

// static 
// std::unique_ptr<service_manager::Service> DomainService::Create() {
//   return std::make_unique<DomainService>();
// }

MojoDomainManagementService::MojoDomainManagementService(base::WeakPtr<common::mojom::DomainManagementServiceClient> client):
  domain_service_runner_(base::CreateSequencedTaskRunnerWithTraits(
          {base::MayBlock(), base::TaskShutdownBehavior::BLOCK_SHUTDOWN})),
  client_(std::move(client)) {
  
   registry_.AddInterface<common::mojom::DomainManagementService>(base::Bind(
      &MojoDomainManagementService::BindDomainRequest, base::Unretained(this)));
}

MojoDomainManagementService::~MojoDomainManagementService() {
  domain_service_runner_->DeleteSoon(FROM_HERE, domain_management_handler_.release());
}

// service_manager::Service:
void MojoDomainManagementService::OnStart() {
  domain_management_handler_.reset(new MojoDomainManagementService::DomainManagementHandler());
}

void MojoDomainManagementService::OnBindInterface(
    const service_manager::BindSourceInfo& source_info,
    const std::string& interface_name,
    mojo::ScopedMessagePipeHandle interface_pipe) {
  registry_.BindInterface(interface_name, std::move(interface_pipe),
                          source_info);
}

void MojoDomainManagementService::BindDomainRequest(
  common::mojom::DomainManagementServiceRequest request,
  const service_manager::BindSourceInfo& source_info) {

 domain_service_runner_->PostTask(
      FROM_HERE,
      base::Bind(&MojoDomainManagementService::DomainManagementHandler::OnDomainRequest,
                 domain_management_handler_->AsWeakPtr(), 
                 source_info.identity,
                 base::Passed(std::move(client_)),
                 base::Passed(&request)));
}

}