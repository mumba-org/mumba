// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_NET_CHROMIUM_PORT_ALLOCATOR_FACTORY_H_
#define MUMBA_HOST_NET_CHROMIUM_PORT_ALLOCATOR_FACTORY_H_

#include <memory>
#include <set>

#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "core/host/net/port_allocator_factory.h"

namespace host {

class ChromiumPortAllocatorFactory : public PortAllocatorFactory {
 public:
  ChromiumPortAllocatorFactory();
  ~ChromiumPortAllocatorFactory() override;

   // PortAllocatorFactory interface.
  std::unique_ptr<cricket::PortAllocator> CreatePortAllocator(
      scoped_refptr<TransportContext> transport_context) override;

 private:
  DISALLOW_COPY_AND_ASSIGN(ChromiumPortAllocatorFactory);
};

}

#endif  // REMOTING_PROTOCOL_CHROMIUM_PORT_ALLOCATOR_FACTORY_H_
