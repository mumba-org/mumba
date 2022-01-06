// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/application/automation/accessibility_service.h"

#include "core/shared/application/automation/accessibility_dispatcher.h"
#include "services/service_manager/public/cpp/service_context.h"

namespace application {

AccessibilityService::AccessibilityService(PageInstance* page_instance)
    : page_instance_(page_instance) {
  registry_.AddInterface<automation::Accessibility>(
      base::Bind(&AccessibilityService::Create, base::Unretained(this)));
}

AccessibilityService::~AccessibilityService() {
  ShutDown();
}

void AccessibilityService::OnStart() {}

void AccessibilityService::OnBindInterface(
    const service_manager::BindSourceInfo& source_info,
    const std::string& interface_name,
    mojo::ScopedMessagePipeHandle interface_pipe) {
  registry_.BindInterface(interface_name, std::move(interface_pipe));
}

void AccessibilityService::ShutDown() {
  if (IsShutDown())
    return;

  shutdown_ = true;
}

bool AccessibilityService::IsShutDown() {
  return shutdown_;
}

void AccessibilityService::Create(automation::AccessibilityRequest request) {
  // This instance cannot service requests if it has already been shut down.
  if (IsShutDown())
    return;

  AccessibilityDispatcher::Create(std::move(request), page_instance_);
}

}  // namespace application
