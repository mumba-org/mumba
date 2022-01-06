// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/application/automation/page_service.h"

#include "core/shared/application/automation/page_dispatcher.h"
#include "services/service_manager/public/cpp/service_context.h"

namespace application {

PageService::PageService(ApplicationWindowDispatcher* dispatcher, PageInstance* page_instance)
    : page_instance_(page_instance),
      dispatcher_(dispatcher) {
  registry_.AddInterface<automation::Page>(
      base::Bind(&PageService::Create, base::Unretained(this)));
}

PageService::~PageService() {
  ShutDown();
}

void PageService::OnStart() {}

void PageService::OnBindInterface(
    const service_manager::BindSourceInfo& source_info,
    const std::string& interface_name,
    mojo::ScopedMessagePipeHandle interface_pipe) {
  registry_.BindInterface(interface_name, std::move(interface_pipe));
}

void PageService::ShutDown() {
  if (IsShutDown())
    return;

  shutdown_ = true;
}

bool PageService::IsShutDown() {
  return shutdown_;
}

void PageService::Create(automation::PageRequest request) {
  // This instance cannot service requests if it has already been shut down.
  if (IsShutDown())
    return;

  PageDispatcher::Create(std::move(request), dispatcher_, page_instance_);
}

}  // namespace application
