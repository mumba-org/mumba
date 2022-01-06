// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/application/automation/service_worker_service.h"

#include "core/shared/application/automation/service_worker_automation_dispatcher.h"
#include "services/service_manager/public/cpp/service_context.h"

namespace application {

ServiceWorkerService::ServiceWorkerService(PageInstance* page_instance, blink::WorkerGlobalScope* scope)
    : page_instance_(page_instance),
      scope_(scope) {
  registry_.AddInterface<automation::ServiceWorker>(
      base::Bind(&ServiceWorkerService::Create, base::Unretained(this)));
}

ServiceWorkerService::~ServiceWorkerService() {
  ShutDown();
}

void ServiceWorkerService::OnStart() {}

void ServiceWorkerService::OnBindInterface(
    const service_manager::BindSourceInfo& source_info,
    const std::string& interface_name,
    mojo::ScopedMessagePipeHandle interface_pipe) {
  registry_.BindInterface(interface_name, std::move(interface_pipe));
}

void ServiceWorkerService::ShutDown() {
  if (IsShutDown())
    return;

  shutdown_ = true;
}

bool ServiceWorkerService::IsShutDown() {
  return shutdown_;
}

void ServiceWorkerService::Create(automation::ServiceWorkerRequest request) {
  // This instance cannot service requests if it has already been shut down.
  if (IsShutDown())
    return;

  ServiceWorkerAutomationDispatcher::Create(std::move(request), page_instance_, scope_);
}

}  // namespace application
