// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_NET_MUMBA_MUMBA_PROTOCOL_H_
#define MUMBA_NET_MUMBA_MUMBA_PROTOCOL_H_

#include "base/macros.h"

namespace storage {

enum MumbaOpcode {
  kKOD_HANDSHAKE = 100,
  kKOD_INTERESTED = 101,
  kKOD_UNINTERESTED = 102,
  kKOD_CHOKE = 103,
  kKOD_UNCHOKE = 104,
  kKOD_BITFIELD = 105,
  kKOD_REQUEST = 106,
  kKOD_SUBSCRIPTION = 107,
  kKOD_REVOKE_SUBSCRIPTION = 108
};

// a 'client' or a 'server' role 
class MumbaHandler {
public:
  virtual ~MumbaHandler() {}
  // bit torrent like messages over Quic/HTTP stream
  virtual void OnHandshake() = 0;
  virtual void OnInterested() = 0;
  virtual void OnUninterested() = 0;
  virtual void OnChoke() = 0;
  virtual void OnUnchoke() = 0;
  virtual void OnBitfield() = 0;
  virtual void OnRequest() = 0;
  virtual void OnSubscription() = 0;
  virtual void OnRevokeSubscription() = 0;
};

}

#endif