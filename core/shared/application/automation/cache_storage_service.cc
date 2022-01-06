// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/application/automation/cache_storage_service.h"

#include "core/shared/application/automation/cache_storage_dispatcher.h"
#include "services/service_manager/public/cpp/service_context.h"

namespace application {

CacheStorageService::CacheStorageService(PageInstance* page_instance)
    : page_instance_(page_instance) {
  registry_.AddInterface<automation::CacheStorage>(
      base::Bind(&CacheStorageService::Create, base::Unretained(this)));
}

CacheStorageService::~CacheStorageService() {
  ShutDown();
}

void CacheStorageService::OnStart() {}

void CacheStorageService::OnBindInterface(
    const service_manager::BindSourceInfo& source_info,
    const std::string& interface_name,
    mojo::ScopedMessagePipeHandle interface_pipe) {
  registry_.BindInterface(interface_name, std::move(interface_pipe));
}

void CacheStorageService::ShutDown() {
  if (IsShutDown())
    return;

  shutdown_ = true;
}

bool CacheStorageService::IsShutDown() {
  return shutdown_;
}

void CacheStorageService::Create(automation::CacheStorageRequest request) {
  // This instance cannot service requests if it has already been shut down.
  if (IsShutDown())
    return;

  CacheStorageDispatcher::Create(std::move(request), page_instance_);
}

}  // namespace application
