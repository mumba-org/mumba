// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/application/automation/emulation_service.h"

#include "core/shared/application/automation/emulation_dispatcher.h"
#include "services/service_manager/public/cpp/service_context.h"

namespace application {

EmulationService::EmulationService(PageInstance* page_instance)
    : page_instance_(page_instance) {
  registry_.AddInterface<automation::Emulation>(
      base::Bind(&EmulationService::Create, base::Unretained(this)));
}

EmulationService::~EmulationService() {
  ShutDown();
}

void EmulationService::OnStart() {}

void EmulationService::OnBindInterface(
    const service_manager::BindSourceInfo& source_info,
    const std::string& interface_name,
    mojo::ScopedMessagePipeHandle interface_pipe) {
  registry_.BindInterface(interface_name, std::move(interface_pipe));
}

void EmulationService::ShutDown() {
  if (IsShutDown())
    return;

  shutdown_ = true;
}

bool EmulationService::IsShutDown() {
  return shutdown_;
}

void EmulationService::Create(automation::EmulationRequest request) {
  // This instance cannot service requests if it has already been shut down.
  if (IsShutDown())
    return;

  EmulationDispatcher::Create(std::move(request), page_instance_);
}

}  // namespace application