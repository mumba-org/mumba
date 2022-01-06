// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_NET_HOST_CONTROL_DISPATCHER_H_
#define MUMBA_HOST_NET_HOST_CONTROL_DISPATCHER_H_

#include "base/macros.h"
#include "core/host/net/channel_dispatcher_base.h"
#include "core/host/net/client_stub.h"
//#include "core/host/net/clipboard_stub.h"
//#include "core/host/net/cursor_shape_stub.h"

namespace protocol {
class PairingResponse;  
}

namespace host {
class HostStub;

// HostControlDispatcher dispatches incoming messages on the control
// channel to HostStub or ClipboardStub, and also implements ClientStub and
// CursorShapeStub for outgoing messages.
class HostControlDispatcher : public ChannelDispatcherBase,
                              public ClientStub {
 public:
  HostControlDispatcher();
  ~HostControlDispatcher() override;

  // ClientStub implementation.
  //void SetCapabilities(const Capabilities& capabilities) override;
  void SetPairingResponse(const protocol::PairingResponse& pairing_response) override;
  //void DeliverHostMessage(const ExtensionMessage& message) override;
  //void SetVideoLayout(const VideoLayout& layout) override;

  // ClipboardStub implementation for sending clipboard data to client.
  //void InjectClipboardEvent(const ClipboardEvent& event) override;

  // CursorShapeStub implementation for sending cursor shape to client.
  //void SetCursorShape(const CursorShapeInfo& cursor_shape) override;

  // Sets the ClipboardStub that will be called for each incoming clipboard
  // message. |clipboard_stub| must outlive this object.
  //void set_clipboard_stub(ClipboardStub* clipboard_stub) {
  //  clipboard_stub_ = clipboard_stub;
  //}

  // Sets the HostStub that will be called for each incoming control
  // message. |host_stub| must outlive this object.
  void set_host_stub(HostStub* host_stub) { host_stub_ = host_stub; }

 private:
  void OnIncomingMessage(std::unique_ptr<protocol::CompoundBuffer> buffer) override;

  //ClipboardStub* clipboard_stub_ = nullptr;
  HostStub* host_stub_ = nullptr;

  DISALLOW_COPY_AND_ASSIGN(HostControlDispatcher);
};

}  // namespace host

#endif  // REMOTING_PROTOCOL_HOST_CONTROL_DISPATCHER_H_
