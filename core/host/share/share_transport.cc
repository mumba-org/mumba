// Copyright 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/share/share_transport.h"

#include "core/common/protocol/message_serialization.h"

namespace host {

// static 
std::unique_ptr<ShareTransport> ShareTransport::Deserialize(net::IOBuffer* buffer, int size) {
  protocol::ShareTransport share_transport;
  protocol::CompoundBuffer cbuffer;
  cbuffer.Append(buffer, size);
  cbuffer.Lock();
  protocol::CompoundBufferInputStream stream(&cbuffer);
  if (!share_transport.ParseFromZeroCopyStream(&stream)) {
    return {};
  }

  std::unique_ptr<ShareTransport> handle(new ShareTransport(std::move(share_transport)));

  return handle;
} 

}