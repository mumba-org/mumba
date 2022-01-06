// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_IPC_IPC_DATA_CHANNEL_H_
#define MUMBA_HOST_IPC_IPC_DATA_CHANNEL_H_

#include "base/macros.h"
#include "base/callback.h"
#include "base/callback_forward.h"
#include "base/memory/weak_ptr.h"
#include "base/threading/thread_checker.h"
#include "base/time/time.h"
#include "base/timer/timer.h"
#include "mojo/edk/embedder/named_platform_handle.h"
#include "ipc/ipc_listener.h"
#include "third_party/webrtc/api/datachannelinterface.h"

namespace base {
class TimeDelta;
}  // base

namespace IPC {
class Channel;
class Message;
}  // IPC

namespace mojo {
namespace edk {
class PeerConnection;
}
}

namespace host {

class IPCDataChannel : public webrtc::DataChannelInterface,
                       public IPC::Listener {
 public:
  IPCDataChannel();
  ~IPCDataChannel() override;

  void RegisterObserver(webrtc::DataChannelObserver* observer) override;
  void UnregisterObserver() override;
  
  std::string label() const override;
  bool reliable() const override;
  bool ordered() const override;
  uint16_t maxRetransmitTime() const override;
  uint16_t maxRetransmits() const override;
  std::string protocol() const override;
  bool negotiated() const override;

  // Returns the ID from the DataChannelInit, if it was negotiated out-of-band.
  // If negotiated in-band, this ID will be populated once the DTLS role is
  // determined, and until then this will return -1.
  int id() const override;
  DataState state() const override;
  uint32_t messages_sent() const override;
  uint64_t bytes_sent() const override;
  uint32_t messages_received() const override;
  uint64_t bytes_received() const override;

  // Returns the number of bytes of application data (UTF-8 text and binary
  // data) that have been queued using Send but have not yet been processed at
  // the SCTP level. See comment above Send below.
  uint64_t buffered_amount() const override;

  void Close() override;
  bool Send(const webrtc::DataBuffer& buffer) override;
  bool Send(IPC::Message* message);

private:

  void Init(const mojo::edk::NamedPlatformHandle& channel_handle);

  // IPC::Listener implementation.
  bool OnMessageReceived(const IPC::Message& message) override;
  void OnChannelConnected(int32_t peer_pid) override;
  void OnChannelError() override;

  //void CreateChannel(const mojo::edk::NamedPlatformHandle& channel_handle, const base::Callback<void(bool)>& cb);
  //void CloseChannel();

  void AddRef() const override;
  rtc::RefCountReleaseStatus Release() const override;
  
  mojo::edk::NamedPlatformHandle channel_handle_;
  std::unique_ptr<mojo::edk::PeerConnection> peer_connection_;
  std::unique_ptr<IPC::Channel> channel_;
  bool connection_close_pending_;
  mutable volatile int ref_count_ = 0;

  base::WeakPtrFactory<IPCDataChannel> weak_factory_;
  
  DISALLOW_COPY_AND_ASSIGN(IPCDataChannel);
};
  
}

#endif