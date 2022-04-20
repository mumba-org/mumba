// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/ethernet/eap_listener.h"

#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <netinet/in.h>

#include <base/bind.h>
#include <base/compiler_specific.h>
#include <base/logging.h>

#include "shill/ethernet/eap_protocol.h"
#include "shill/event_dispatcher.h"
#include "shill/logging.h"
#include "shill/net/io_handler_factory.h"
#include "shill/net/sockets.h"

namespace shill {

const size_t EapListener::kMaxEapPacketLength =
    sizeof(eap_protocol::Ieee8021xHdr) + sizeof(eap_protocol::EapHeader);

EapListener::EapListener(int interface_index)
    : io_handler_factory_(IOHandlerFactory::GetInstance()),
      interface_index_(interface_index),
      sockets_(new Sockets()),
      socket_(-1) {}

EapListener::~EapListener() = default;

bool EapListener::Start() {
  if (!CreateSocket()) {
    LOG(ERROR) << "Could not open EAP listener socket.";
    Stop();
    return false;
  }

  receive_request_handler_.reset(io_handler_factory_->CreateIOReadyHandler(
      socket_, IOHandler::kModeInput,
      base::BindRepeating(&EapListener::ReceiveRequest,
                          base::Unretained(this))));

  return true;
}

void EapListener::Stop() {
  receive_request_handler_.reset();
  socket_closer_.reset();
  socket_ = -1;
}

bool EapListener::CreateSocket() {
  int socket =
      sockets_->Socket(PF_PACKET, SOCK_DGRAM | SOCK_CLOEXEC, htons(ETH_P_PAE));
  if (socket == -1) {
    PLOG(ERROR) << "Could not create EAP listener socket";
    return false;
  }
  socket_ = socket;
  socket_closer_.reset(new ScopedSocketCloser(sockets_.get(), socket_));

  if (sockets_->SetNonBlocking(socket_) != 0) {
    PLOG(ERROR) << "Could not set socket to be non-blocking";
    return false;
  }

  sockaddr_ll socket_address;
  memset(&socket_address, 0, sizeof(socket_address));
  socket_address.sll_family = AF_PACKET;
  socket_address.sll_protocol = htons(ETH_P_PAE);
  socket_address.sll_ifindex = interface_index_;

  if (sockets_->Bind(socket_,
                     reinterpret_cast<struct sockaddr*>(&socket_address),
                     sizeof(socket_address)) != 0) {
    PLOG(ERROR) << "Could not bind socket to interface";
    return false;
  }

  return true;
}

void EapListener::ReceiveRequest(int fd) {
  struct ALIGNAS(1) {
    eap_protocol::Ieee8021xHdr onex_header;
    eap_protocol::EapHeader eap_header;
  } payload;
  sockaddr_ll remote_address;
  memset(&remote_address, 0, sizeof(remote_address));
  socklen_t socklen = sizeof(remote_address);
  int result = sockets_->RecvFrom(
      socket_, &payload, sizeof(payload), 0,
      reinterpret_cast<struct sockaddr*>(&remote_address), &socklen);
  if (result < 0) {
    PLOG(ERROR) << "Socket recvfrom failed";
    Stop();
    return;
  }

  if (result != sizeof(payload)) {
    LOG(INFO) << "Short EAP packet received";
    return;
  }

  if (payload.onex_header.version < eap_protocol::kIeee8021xEapolVersion1 ||
      payload.onex_header.type != eap_protocol::kIIeee8021xTypeEapPacket ||
      payload.eap_header.code != eap_protocol::kEapCodeRequest) {
    LOG(INFO) << "Packet is not a valid EAP request";
    return;
  }

  request_received_callback_.Run();
}

}  // namespace shill
