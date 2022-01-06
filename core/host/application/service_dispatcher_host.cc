// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/application/service_dispatcher_host.h"

namespace host {

ServiceDispatcherHost::ServiceDispatcherHost(): service_dispatcher_host_binding_(this) {
  
}

ServiceDispatcherHost::~ServiceDispatcherHost() {

}

common::mojom::ServiceDispatcher* ServiceDispatcherHost::GetServiceDispatcherInterface() {
  return service_dispatcher_interface_.get();
}

void ServiceDispatcherHost::AddBinding(common::mojom::ServiceDispatcherClientAssociatedRequest request) {
  // bind here on IO or on UI?
  service_dispatcher_host_binding_.Bind(std::move(request));
}

void ServiceDispatcherHost::BindService(common::mojom::ServiceBindRequestPtr request, BindServiceCallback callback) {

}

}