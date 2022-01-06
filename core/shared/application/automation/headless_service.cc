// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/application/automation/headless_service.h"

#include "core/shared/application/automation/headless_dispatcher.h"
#include "services/service_manager/public/cpp/service_context.h"

namespace application {

HeadlessService::HeadlessService(PageInstance* page_instance)
    : page_instance_(page_instance) {
  registry_.AddInterface<automation::Headless>(
      base::Bind(&HeadlessService::Create, base::Unretained(this)));
}

HeadlessService::~HeadlessService() {
  ShutDown();
}

void HeadlessService::OnStart() {}

void HeadlessService::OnBindInterface(
    const service_manager::BindSourceInfo& source_info,
    const std::string& interface_name,
    mojo::ScopedMessagePipeHandle interface_pipe) {
  registry_.BindInterface(interface_name, std::move(interface_pipe));
}

void HeadlessService::ShutDown() {
  if (IsShutDown())
    return;

  shutdown_ = true;
}

bool HeadlessService::IsShutDown() {
  return shutdown_;
}

void HeadlessService::Create(automation::HeadlessRequest request) {
  // This instance cannot service requests if it has already been shut down.
  if (IsShutDown())
    return;

  HeadlessDispatcher::Create(std::move(request), page_instance_);
}

}  // namespace application
