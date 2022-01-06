// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/net/chromium_port_allocator_factory.h"

#include "base/memory/ptr_util.h"
#include "core/host/net/chromium_socket_factory.h"
#include "core/host/net/port_allocator.h"
#include "core/host/net/transport_context.h"

namespace host {

ChromiumPortAllocatorFactory::ChromiumPortAllocatorFactory() = default;
ChromiumPortAllocatorFactory::~ChromiumPortAllocatorFactory() = default;

std::unique_ptr<cricket::PortAllocator>
ChromiumPortAllocatorFactory::CreatePortAllocator(
    scoped_refptr<TransportContext> transport_context) {
  return std::make_unique<PortAllocator>(
      base::WrapUnique(new rtc::BasicNetworkManager()),
      base::WrapUnique(new ChromiumPacketSocketFactory()), transport_context);
}

}
