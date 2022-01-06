// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_NET_PEER_PROTOCOL_H_
#define MUMBA_HOST_NET_PEER_PROTOCOL_H_

namespace host {

enum class PeerProtocol {
  IPC,
  Rpc,
  P2P,
  HTTP
};

}

#endif