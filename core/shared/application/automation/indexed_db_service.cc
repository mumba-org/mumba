// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/application/automation/indexed_db_service.h"

#include "core/shared/application/automation/indexed_db_dispatcher.h"
#include "services/service_manager/public/cpp/service_context.h"

namespace application {

IndexedDBService::IndexedDBService(PageInstance* page_instance)
    : page_instance_(page_instance) {
  registry_.AddInterface<automation::IndexedDB>(
      base::Bind(&IndexedDBService::Create, base::Unretained(this)));
}

IndexedDBService::~IndexedDBService() {
  ShutDown();
}

void IndexedDBService::OnStart() {}

void IndexedDBService::OnBindInterface(
    const service_manager::BindSourceInfo& source_info,
    const std::string& interface_name,
    mojo::ScopedMessagePipeHandle interface_pipe) {
  registry_.BindInterface(interface_name, std::move(interface_pipe));
}

void IndexedDBService::ShutDown() {
  if (IsShutDown())
    return;

  shutdown_ = true;
}

bool IndexedDBService::IsShutDown() {
  return shutdown_;
}

void IndexedDBService::Create(automation::IndexedDBRequest request) {
  // This instance cannot service requests if it has already been shut down.
  if (IsShutDown())
    return;

  IndexedDBDispatcher::Create(std::move(request), page_instance_);
}

}  // namespace application
