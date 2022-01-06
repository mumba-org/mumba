// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/application/module_dispatcher_host.h"

namespace host {

ModuleDispatcherHost::ModuleDispatcherHost(): module_dispatcher_host_binding_(this) {
  
}

ModuleDispatcherHost::~ModuleDispatcherHost() {

}

common::mojom::ModuleDispatcher* ModuleDispatcherHost::GetModuleDispatcherInterface() {
  return module_dispatcher_interface_.get();
}

void ModuleDispatcherHost::AddBinding(common::mojom::ModuleDispatcherHostAssociatedRequest request) {
  // bind here on IO or on UI?
  module_dispatcher_host_binding_.Bind(std::move(request));
}

void ModuleDispatcherHost::Noop() {
  
}

}