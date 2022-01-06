// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/application/automation/device_orientation_service.h"

#include "core/shared/application/automation/device_orientation_dispatcher.h"
#include "services/service_manager/public/cpp/service_context.h"

namespace application {

DeviceOrientationService::DeviceOrientationService(PageInstance* page_instance)
    : page_instance_(page_instance) {
  registry_.AddInterface<automation::DeviceOrientation>(
      base::Bind(&DeviceOrientationService::Create, base::Unretained(this)));
}

DeviceOrientationService::~DeviceOrientationService() {
  ShutDown();
}

void DeviceOrientationService::OnStart() {}

void DeviceOrientationService::OnBindInterface(
    const service_manager::BindSourceInfo& source_info,
    const std::string& interface_name,
    mojo::ScopedMessagePipeHandle interface_pipe) {
  registry_.BindInterface(interface_name, std::move(interface_pipe));
}

void DeviceOrientationService::ShutDown() {
  if (IsShutDown())
    return;

  shutdown_ = true;
}

bool DeviceOrientationService::IsShutDown() {
  return shutdown_;
}

void DeviceOrientationService::Create(automation::DeviceOrientationRequest request) {
  // This instance cannot service requests if it has already been shut down.
  if (IsShutDown())
    return;

  DeviceOrientationDispatcher::Create(std::move(request), page_instance_);
}

}  // namespace application
