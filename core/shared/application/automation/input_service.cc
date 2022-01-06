// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/application/automation/input_service.h"

#include "core/shared/application/automation/input_dispatcher.h"
#include "services/service_manager/public/cpp/service_context.h"

namespace application {

InputService::InputService(PageInstance* page_instance)//, blink::WebLocalFrameImpl* frame_impl)
    : page_instance_(page_instance) {//,
      //frame_impl_(frame_impl) {
  registry_.AddInterface<automation::Input>(
      base::Bind(&InputService::Create, base::Unretained(this)));
}

InputService::~InputService() {
  ShutDown();
}

void InputService::OnStart() {}

void InputService::OnBindInterface(
    const service_manager::BindSourceInfo& source_info,
    const std::string& interface_name,
    mojo::ScopedMessagePipeHandle interface_pipe) {
  registry_.BindInterface(interface_name, std::move(interface_pipe));
}

void InputService::ShutDown() {
  if (IsShutDown())
    return;

  shutdown_ = true;
}

bool InputService::IsShutDown() {
  return shutdown_;
}

void InputService::Create(automation::InputRequest request) {
  // This instance cannot service requests if it has already been shut down.
  if (IsShutDown())
    return;

  InputDispatcher::Create(std::move(request), page_instance_);//, frame_impl_);
}

}  // namespace application
