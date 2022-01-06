// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/application/automation/css_service.h"

#include "core/shared/application/automation/css_dispatcher.h"
#include "services/service_manager/public/cpp/service_context.h"

namespace application {

CSSService::CSSService(
  AutomationContext* context,
  PageInstance* page_instance)
    : context_(context),
      page_instance_(page_instance),
      dispatcher_(nullptr) {
  registry_.AddInterface<automation::CSS>(
      base::Bind(&CSSService::Create, base::Unretained(this)));
}

CSSService::~CSSService() {
  ShutDown();
}

void CSSService::OnStart() {}

void CSSService::OnBindInterface(
    const service_manager::BindSourceInfo& source_info,
    const std::string& interface_name,
    mojo::ScopedMessagePipeHandle interface_pipe) {
  registry_.BindInterface(interface_name, std::move(interface_pipe));
}

void CSSService::ShutDown() {
  if (IsShutDown())
    return;

  shutdown_ = true;
}

bool CSSService::IsShutDown() {
  return shutdown_;
}

void CSSService::Create(automation::CSSRequest request) {
  // This instance cannot service requests if it has already been shut down.
  if (IsShutDown())
    return;

  dispatcher_= CSSDispatcher::Create(std::move(request), context_, page_instance_);
}

}  // namespace application
