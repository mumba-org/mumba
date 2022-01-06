// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/gpu_service_registry.h"

#include "core/host/gpu/gpu_process_host.h"

namespace host {

void BindInterfaceInGpuProcess(const std::string& interface_name,
                               mojo::ScopedMessagePipeHandle interface_pipe) {
  GpuProcessHost* host = GpuProcessHost::Get();
  return host->BindInterface(interface_name, std::move(interface_pipe));
}

}  // namespace host
