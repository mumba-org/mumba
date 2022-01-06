// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "storage/koden_client.h"

namespace storage {

MumbaClient::MumbaClient() {
  //QuicSocketAddress server_address,
  //const QuicServerId& server_id,
  //const ParsedQuicVersionVector& supported_versions,
  //EpollServer* epoll_server,
  //std::unique_ptr<ProofVerifier> proof_verifier): 
  //  QuicClient(server_address, server_id, supported_versions, epoll_server, std::move(proof_verifier)) {

}

MumbaClient::~MumbaClient() {

}

bool MumbaClient::Connect() {
  return false;
}

void MumbaClient::SendHandshake() {

}

void MumbaClient::SendInterested() {

}

void MumbaClient::SendUninterested() {

}

void MumbaClient::SendChoke() {

}

void MumbaClient::SendUnchoke() {

}

void MumbaClient::SendBitfield() {

}

void MumbaClient::SendRequest() {

}

void MumbaClient::SendSubscription() {
  
}

void MumbaClient::SendRevokeSubscription() {

}

}