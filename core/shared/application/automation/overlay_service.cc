// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/application/automation/overlay_service.h"

#include "core/shared/application/automation/overlay_dispatcher.h"
#include "core/shared/application/automation/dom_service.h"
#include "services/service_manager/public/cpp/service_context.h"

namespace application {

OverlayService::OverlayService(
    PageInstance* page_instance,
    DOMService* dom_service)
    : page_instance_(page_instance),
      dom_service_(dom_service) {
  registry_.AddInterface<automation::Overlay>(
      base::Bind(&OverlayService::Create, base::Unretained(this)));
}

OverlayService::~OverlayService() {
  ShutDown();
}

void OverlayService::OnStart() {}

void OverlayService::OnBindInterface(
    const service_manager::BindSourceInfo& source_info,
    const std::string& interface_name,
    mojo::ScopedMessagePipeHandle interface_pipe) {
  registry_.BindInterface(interface_name, std::move(interface_pipe));
}

void OverlayService::ShutDown() {
  if (IsShutDown())
    return;

  shutdown_ = true;
}

bool OverlayService::IsShutDown() {
  return shutdown_;
}

void OverlayService::Create(automation::OverlayRequest request) {
  // This instance cannot service requests if it has already been shut down.
  if (IsShutDown())
    return;

  OverlayDispatcher::Create(std::move(request), page_instance_, dom_service_->dispatcher());
}

}  // namespace application
