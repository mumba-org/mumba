// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/application/automation/layer_tree_service.h"

#include "core/shared/application/automation/layer_tree_dispatcher.h"
#include "services/service_manager/public/cpp/service_context.h"

namespace application {

LayerTreeService::LayerTreeService(PageInstance* page_instance)
    : page_instance_(page_instance) {
  registry_.AddInterface<automation::LayerTree>(
      base::Bind(&LayerTreeService::Create, base::Unretained(this)));
}

LayerTreeService::~LayerTreeService() {
  ShutDown();
}

void LayerTreeService::OnStart() {}

void LayerTreeService::OnBindInterface(
    const service_manager::BindSourceInfo& source_info,
    const std::string& interface_name,
    mojo::ScopedMessagePipeHandle interface_pipe) {
  registry_.BindInterface(interface_name, std::move(interface_pipe));
}

void LayerTreeService::ShutDown() {
  if (IsShutDown())
    return;

  shutdown_ = true;
}

bool LayerTreeService::IsShutDown() {
  return shutdown_;
}

void LayerTreeService::Create(automation::LayerTreeRequest request) {
  // This instance cannot service requests if it has already been shut down.
  if (IsShutDown())
    return;

  LayerTreeDispatcher::Create(std::move(request), page_instance_);
}

}  // namespace application
