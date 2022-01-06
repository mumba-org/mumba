// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_IPC_NAMED_IPC_SERVER_H_
#define MUMBA_HOST_IPC_NAMED_IPC_SERVER_H_

#include "base/macros.h"
#include "base/callback.h"
#include "base/callback_forward.h"
#include "base/memory/weak_ptr.h"
#include "base/threading/thread_checker.h"
#include "base/time/time.h"
#include "base/timer/timer.h"
#include "mojo/edk/embedder/named_platform_handle.h"
#include "ipc/ipc_listener.h"
#include "net/base/io_buffer.h"

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
 
class NamedIpcServer : public IPC::Listener {
public:
  static std::unique_ptr<NamedIpcServer> Create(int connection_id);

  NamedIpcServer(int connection_id);
  ~NamedIpcServer() override;

  int connection_id() const {
    return connection_id_;
  }

  bool Init(const mojo::edk::NamedPlatformHandle& channel_handle);

private:
  // IPC::Listener implementation.
  bool OnMessageReceived(const IPC::Message& message) override;
  void OnChannelConnected(int32_t peer_pid) override;
  void OnChannelError() override;

  void CreateChannel(const mojo::edk::NamedPlatformHandle& channel_handle, const base::Callback<void(bool)>& cb);
  void CloseChannel();

  //void OnClientQueryRequest(const std::string& request);
  void OnClientControlRequest(const std::string& request);
  //void OnQueryReply(std::string buf);
  //void OnQueryReplyOnIOThread(std::string buf);
  void OnControlReply(int code);
  void OnControlReplyOnIOThread(int code);

  int connection_id_;

  // Tracks whether the connection is in the process of being closed.
  bool connection_close_pending_ = false;

  // Timeout for disconnecting the IPC channel if there is no client activity.
  //base::TimeDelta initial_connect_timeout_;

  // Used to detect timeouts and disconnect the IPC channel.
  //base::OneShotTimer timer_;

  // Used to signal that the IPC channel has been connected.
//  base::Closure connect_callback_;

  // Used to signal that the IPC channel should be disconnected.
 // base::Closure done_callback_;

  // Used to pass a security key request on to the remote client.
  //SecurityKeyAuthHandler::SendMessageCallback message_callback_;
  mojo::edk::NamedPlatformHandle channel_handle_;

  // Used for sending/receiving security key messages between processes.
  std::unique_ptr<mojo::edk::PeerConnection> peer_connection_;
  std::unique_ptr<IPC::Channel> ipc_channel_;

  // Ensures SecurityKeyIpcServerImpl methods are called on the same thread.
  //base::ThreadChecker thread_checker_;

  base::WeakPtrFactory<NamedIpcServer> weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(NamedIpcServer);
};

}

#endif