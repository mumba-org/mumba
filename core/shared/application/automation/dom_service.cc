// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/application/automation/dom_service.h"

#include "core/shared/application/automation/dom_dispatcher.h"
#include "services/service_manager/public/cpp/service_context.h"

namespace application {

DOMService::DOMService(PageInstance* page_instance)
    : page_instance_(page_instance),
      instance_(nullptr) {
  registry_.AddInterface<automation::DOM>(
      base::Bind(&DOMService::Create, base::Unretained(this)));
}

DOMService::~DOMService() {
  ShutDown();
}

void DOMService::OnStart() {}

void DOMService::OnBindInterface(
    const service_manager::BindSourceInfo& source_info,
    const std::string& interface_name,
    mojo::ScopedMessagePipeHandle interface_pipe) {
  registry_.BindInterface(interface_name, std::move(interface_pipe));
}

void DOMService::ShutDown() {
  if (IsShutDown())
    return;

  shutdown_ = true;
}

bool DOMService::IsShutDown() {
  return shutdown_;
}

void DOMService::Create(automation::DOMRequest request) {
  // This instance cannot service requests if it has already been shut down.
  if (IsShutDown())
    return;

  instance_ = DOMDispatcher::Create(std::move(request), page_instance_);
}

}  // namespace application
