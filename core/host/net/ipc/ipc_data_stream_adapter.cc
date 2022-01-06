// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/ipc/ipc_data_stream_adapter.h"

#include <stdint.h>

#include "base/bind.h"
#include "base/callback.h"
#include "base/callback_helpers.h"
#include "base/location.h"
#include "base/macros.h"
#include "base/memory/ptr_util.h"
#include "base/threading/thread_task_runner_handle.h"
#include "net/base/net_errors.h"
#include "core/common/protocol/compound_buffer.h"
#include "core/common/protocol/message_serialization.h"
#include "core/host/ipc/ipc_data_channel.h"
#include "ipc/ipc_channel.h"
#include "ipc/ipc_message.h"

namespace host {

IPCDataStreamAdapter::IPCDataStreamAdapter(rtc::scoped_refptr<webrtc::DataChannelInterface> channel):
 channel_(channel.get()) {

}

IPCDataStreamAdapter::~IPCDataStreamAdapter() {
}

void IPCDataStreamAdapter::Start(EventHandler* event_handler) {
  event_handler_ = event_handler;
}

void IPCDataStreamAdapter::Send(
  const google::protobuf::MessageLite& message,
  const base::Closure& done) {

  //rtc::CopyOnWriteBuffer buffer;
  //buffer.SetSize(message.ByteSize());

  //message.SerializeWithCachedSizesToArray(
  //    reinterpret_cast<uint8_t*>(buffer.data()));

  IPC::Message ipc_message;
  ipc_message.Reserve(message.ByteSize());
  
  message.SerializeWithCachedSizesToArray(reinterpret_cast<uint8_t*>(const_cast<char *>(ipc_message.payload())));
  //message.WriteData(buffer.data(), message.ByteSize());
  
  IPCDataChannel* ipc_channel = static_cast<IPCDataChannel*>(channel_.get());
  if (!ipc_channel->Send(&ipc_message)) {
    LOG(ERROR) << "Send failed on ipc channel";
    channel_->Close();
    return;
  }

  if (!done.is_null())
    done.Run();
}

}
