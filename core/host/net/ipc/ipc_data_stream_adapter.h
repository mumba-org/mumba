// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_IPC_IPC_DATA_STREAM_ADAPTER_H_
#define MUMBA_HOST_IPC_IPC_DATA_STREAM_ADAPTER_H_

#include <memory>
#include <string>

#include "base/callback.h"
#include "base/macros.h"
#include "core/common/protocol/message_pipe.h"
#include "third_party/webrtc/api/peerconnectioninterface.h"
#include "third_party/webrtc/rtc_base/refcount.h"

namespace host {
class IPCDataChannel;

// WebrtcDataStreamAdapter implements MessagePipe for WebRTC data channels.
class IPCDataStreamAdapter : public protocol::MessagePipe {
 public:
  explicit IPCDataStreamAdapter(rtc::scoped_refptr<webrtc::DataChannelInterface> channel);
  ~IPCDataStreamAdapter() override;

  // MessagePipe interface.
  void Start(EventHandler* event_handler) override;
  void Send(const google::protobuf::MessageLite& message,
            const base::Closure& done) override;

private:
  
  rtc::scoped_refptr<webrtc::DataChannelInterface> channel_;
  
  EventHandler* event_handler_ = nullptr;
};

}

#endif