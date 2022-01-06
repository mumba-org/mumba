// Copyright 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/session/session.h"

#include "core/common/protocol/message_serialization.h"

namespace host {

char Session::kClassName[] = "session";

// static 
std::unique_ptr<Session> Session::Deserialize(net::IOBuffer* buffer, int size) {
  protocol::Session share_proto;
  protocol::CompoundBuffer cbuffer;
  cbuffer.Append(buffer, size);
  cbuffer.Lock();
  protocol::CompoundBufferInputStream stream(&cbuffer);
  if (!session_proto.ParseFromZeroCopyStream(&stream)) {
    return {};
  }

  std::unique_ptr<Session> handle(new Session(std::move(session_proto)));

  return handle;
} 

Session::Session(protocol::Session session_proto): 
  id_(reinterpret_cast<const uint8_t *>(session_proto.uuid().data())),
  session_proto_(std::move(session_proto)),
  managed_(false) {

}

Session::~Session() {

}

}