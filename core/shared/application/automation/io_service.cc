// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/application/automation/io_service.h"

#include "core/shared/application/automation/io_dispatcher.h"
#include "services/service_manager/public/cpp/service_context.h"

namespace application {

IOService::IOService(PageInstance* page_instance)
    : page_instance_(page_instance) {
  registry_.AddInterface<automation::IO>(
      base::Bind(&IOService::Create, base::Unretained(this)));
}

IOService::~IOService() {
  ShutDown();
}

void IOService::OnStart() {}

void IOService::OnBindInterface(
    const service_manager::BindSourceInfo& source_info,
    const std::string& interface_name,
    mojo::ScopedMessagePipeHandle interface_pipe) {
  registry_.BindInterface(interface_name, std::move(interface_pipe));
}

void IOService::ShutDown() {
  if (IsShutDown())
    return;

  shutdown_ = true;
}

bool IOService::IsShutDown() {
  return shutdown_;
}

void IOService::Create(automation::IORequest request) {
  // This instance cannot service requests if it has already been shut down.
  if (IsShutDown())
    return;

  IODispatcher::Create(std::move(request), page_instance_);
}

}  // namespace application
