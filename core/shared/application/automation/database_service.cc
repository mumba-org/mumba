// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/application/automation/database_service.h"

#include "core/shared/application/automation/database_dispatcher.h"
#include "services/service_manager/public/cpp/service_context.h"

namespace application {

DatabaseService::DatabaseService(AutomationContext* context, PageInstance* page_instance)
    : context_(context),
      page_instance_(page_instance) {
  registry_.AddInterface<automation::DatabaseInterface>(
      base::Bind(&DatabaseService::Create, base::Unretained(this)));
}

DatabaseService::~DatabaseService() {
  ShutDown();
}

void DatabaseService::OnStart() {}

void DatabaseService::OnBindInterface(
    const service_manager::BindSourceInfo& source_info,
    const std::string& interface_name,
    mojo::ScopedMessagePipeHandle interface_pipe) {
  registry_.BindInterface(interface_name, std::move(interface_pipe));
}

void DatabaseService::ShutDown() {
  if (IsShutDown())
    return;

  shutdown_ = true;
}

bool DatabaseService::IsShutDown() {
  return shutdown_;
}

void DatabaseService::Create(automation::DatabaseInterfaceRequest request) {
  // This instance cannot service requests if it has already been shut down.
  if (IsShutDown())
    return;

  DatabaseDispatcher::Create(std::move(request), context_, page_instance_);
}

}  // namespace application
