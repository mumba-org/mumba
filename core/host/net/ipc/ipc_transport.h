// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_IPC_IPC_TRANSPORT_H_
#define MUMBA_HOST_IPC_IPC_TRANSPORT_H_

#include <memory>
#include <string>
#include <vector>

#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/memory/weak_ptr.h"
#include "base/threading/thread_checker.h"
#include "base/timer/timer.h"
#include "crypto/hmac.h"
#include "core/host/net/session_options.h"
#include "core/host/net/signal_strategy.h"
#include "core/host/net/transport.h"
#include "third_party/webrtc/api/peerconnectioninterface.h"

namespace protocol {
class MessagePipe;  
}

namespace host {
class TransportContext;

class IPCTransport : public Transport {
public:
  class EventHandler {
   public:
    virtual void OnIPCTransportConnecting() = 0;
    virtual void OnIPCTransportConnected() = 0;
    virtual void OnIPCTransportError(ErrorCode error) = 0;
    virtual void OnIPCTransportIncomingDataChannel(
        const std::string& name,
        std::unique_ptr<protocol::MessagePipe> pipe) = 0;

   protected:
    virtual ~EventHandler() {}
  };

  IPCTransport(scoped_refptr<TransportContext> transport_context,
               EventHandler* event_handler);
  
  ~IPCTransport() override;

  webrtc::PeerConnectionInterface* peer_connection();

  void Start(Authenticator* authenticator,
             SendTransportInfoCallback send_transport_info_callback) override;

  bool ProcessTransportInfo(buzz::XmlElement* transport_info) override;
  
  void Close(ErrorCode error);

  std::unique_ptr<protocol::MessagePipe> CreateOutgoingChannel(const std::string& name);

private:
  class PeerConnectionWrapper;
  friend class PeerConnectionWrapper;
  
  void OnLocalSessionDescriptionCreated(
    std::unique_ptr<webrtc::SessionDescriptionInterface> description,
    const std::string& error);
  void RequestNegotiation();
  void SendOffer();

  void OnDataChannel(
      rtc::scoped_refptr<webrtc::DataChannelInterface> data_channel);

  scoped_refptr<TransportContext> transport_context_;
  EventHandler* event_handler_ = nullptr;
  crypto::HMAC handshake_hmac_;
  std::unique_ptr<PeerConnectionWrapper> peer_connection_wrapper_;
  
  bool negotiation_pending_ = false;

  base::WeakPtrFactory<IPCTransport> weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(IPCTransport);
};

}

#endif