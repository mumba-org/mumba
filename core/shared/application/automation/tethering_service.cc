// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/application/automation/tethering_service.h"

#include "core/shared/application/automation/tethering_dispatcher.h"
#include "services/service_manager/public/cpp/service_context.h"

namespace application {

TetheringService::TetheringService(PageInstance* page_instance)
    : page_instance_(page_instance) {
  registry_.AddInterface<automation::Tethering>(
      base::Bind(&TetheringService::Create, base::Unretained(this)));
}

TetheringService::~TetheringService() {
  ShutDown();
}

void TetheringService::OnStart() {}

void TetheringService::OnBindInterface(
    const service_manager::BindSourceInfo& source_info,
    const std::string& interface_name,
    mojo::ScopedMessagePipeHandle interface_pipe) {
  registry_.BindInterface(interface_name, std::move(interface_pipe));
}

void TetheringService::ShutDown() {
  if (IsShutDown())
    return;

  shutdown_ = true;
}

bool TetheringService::IsShutDown() {
  return shutdown_;
}

void TetheringService::Create(automation::TetheringRequest request) {
  // This instance cannot service requests if it has already been shut down.
  if (IsShutDown())
    return;

  TetheringDispatcher::Create(std::move(request), page_instance_);
}

}  // namespace application
