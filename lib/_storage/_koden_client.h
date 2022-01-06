// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_NET_MUMBA_CLIENT_H_
#define MUMBA_NET_MUMBA_CLIENT_H_

#include "base/macros.h"
#include "storage/koden_protocol.h"
//#include "net/tools/quic/quic_client.h"

namespace storage {

class MumbaClient {//: public QuicClient {
public:
  //MumbaClient(QuicSocketAddress server_address,
  //             const QuicServerId& server_id,
  //             const ParsedQuicVersionVector& supported_versions,
  //             EpollServer* epoll_server,
  //             std::unique_ptr<ProofVerifier> proof_verifier);
  MumbaClient();
  ~MumbaClient();//override;

  void SendHandshake();
  void SendInterested();
  void SendUninterested();
  void SendChoke();
  void SendUnchoke();
  void SendBitfield();
  void SendRequest();
  void SendSubscription();
  void SendRevokeSubscription();

  bool Connect();

private:

  DISALLOW_COPY_AND_ASSIGN(MumbaClient);
};

}

#endif