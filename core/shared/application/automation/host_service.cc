// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/application/automation/host_service.h"

#include "core/shared/application/automation/host_dispatcher.h"
#include "services/service_manager/public/cpp/service_context.h"

namespace application {

HostService::HostService(PageInstance* page_instance)
    : page_instance_(page_instance) {
  registry_.AddInterface<automation::Host>(
      base::Bind(&HostService::Create, base::Unretained(this)));
}

HostService::~HostService() {
  ShutDown();
}

void HostService::OnStart() {}

void HostService::OnBindInterface(
    const service_manager::BindSourceInfo& source_info,
    const std::string& interface_name,
    mojo::ScopedMessagePipeHandle interface_pipe) {
  registry_.BindInterface(interface_name, std::move(interface_pipe));
}

void HostService::ShutDown() {
  if (IsShutDown())
    return;

  shutdown_ = true;
}

bool HostService::IsShutDown() {
  return shutdown_;
}

void HostService::Create(automation::HostRequest request) {
  // This instance cannot service requests if it has already been shut down.
  if (IsShutDown())
    return;

  HostDispatcher::Create(std::move(request), page_instance_);
}

}  // namespace application
