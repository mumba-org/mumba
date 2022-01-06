// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/application/automation/network_service.h"

#include "core/shared/application/automation/network_dispatcher.h"
#include "services/service_manager/public/cpp/service_context.h"

namespace application {

NetworkService::NetworkService(PageInstance* page_instance)
    : page_instance_(page_instance) {
  registry_.AddInterface<automation::Network>(
      base::Bind(&NetworkService::Create, base::Unretained(this)));
}

NetworkService::~NetworkService() {
  ShutDown();
}

void NetworkService::OnStart() {}

void NetworkService::OnBindInterface(
    const service_manager::BindSourceInfo& source_info,
    const std::string& interface_name,
    mojo::ScopedMessagePipeHandle interface_pipe) {
  registry_.BindInterface(interface_name, std::move(interface_pipe));
}

void NetworkService::ShutDown() {
  if (IsShutDown())
    return;

  shutdown_ = true;
}

bool NetworkService::IsShutDown() {
  return shutdown_;
}

void NetworkService::Create(automation::NetworkRequest request) {
  // This instance cannot service requests if it has already been shut down.
  if (IsShutDown())
    return;

  NetworkDispatcher::Create(std::move(request), page_instance_);
}

}  // namespace application
