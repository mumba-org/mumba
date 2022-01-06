// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/application/automation/target_service.h"

#include "core/shared/application/automation/target_dispatcher.h"
#include "services/service_manager/public/cpp/service_context.h"

namespace application {

TargetService::TargetService(PageInstance* page_instance)
    : page_instance_(page_instance) {
  registry_.AddInterface<automation::Target>(
      base::Bind(&TargetService::Create, base::Unretained(this)));
}

TargetService::~TargetService() {
  ShutDown();
}

void TargetService::OnStart() {}

void TargetService::OnBindInterface(
    const service_manager::BindSourceInfo& source_info,
    const std::string& interface_name,
    mojo::ScopedMessagePipeHandle interface_pipe) {
  registry_.BindInterface(interface_name, std::move(interface_pipe));
}

void TargetService::ShutDown() {
  if (IsShutDown())
    return;

  shutdown_ = true;
}

bool TargetService::IsShutDown() {
  return shutdown_;
}

void TargetService::Create(automation::TargetRequest request) {
  // This instance cannot service requests if it has already been shut down.
  if (IsShutDown())
    return;

  TargetDispatcher::Create(std::move(request), page_instance_);
}

}  // namespace application
