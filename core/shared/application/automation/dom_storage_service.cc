// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/application/automation/dom_storage_service.h"

#include "core/shared/application/automation/dom_storage_dispatcher.h"
#include "services/service_manager/public/cpp/service_context.h"

namespace application {

DOMStorageService::DOMStorageService(PageInstance* page_instance)
    : page_instance_(page_instance) {
  registry_.AddInterface<automation::DOMStorage>(
      base::Bind(&DOMStorageService::Create, base::Unretained(this)));
}

DOMStorageService::~DOMStorageService() {
  ShutDown();
}

void DOMStorageService::OnStart() {}

void DOMStorageService::OnBindInterface(
    const service_manager::BindSourceInfo& source_info,
    const std::string& interface_name,
    mojo::ScopedMessagePipeHandle interface_pipe) {
  registry_.BindInterface(interface_name, std::move(interface_pipe));
}

void DOMStorageService::ShutDown() {
  if (IsShutDown())
    return;

  shutdown_ = true;
}

bool DOMStorageService::IsShutDown() {
  return shutdown_;
}

void DOMStorageService::Create(automation::DOMStorageRequest request) {
  // This instance cannot service requests if it has already been shut down.
  if (IsShutDown())
    return;

  DOMStorageDispatcher::Create(std::move(request), page_instance_);
}

}  // namespace application
