// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/ipc/ipc_data_channel.h"

#include "base/callback.h"
#include "base/callback_helpers.h"
#include "base/location.h"
#include "base/strings/utf_string_conversions.h"
#include "base/threading/thread_checker.h"
#include "base/threading/thread_task_runner_handle.h"
#include "base/timer/timer.h"
#include "ipc/ipc_channel.h"
#include "ipc/ipc_message.h"
#include "ipc/ipc_message_macros.h"
#include "mojo/edk/embedder/embedder.h"
#include "mojo/edk/embedder/named_platform_handle.h"
#include "mojo/edk/embedder/named_platform_handle_utils.h"
#include "mojo/edk/embedder/peer_connection.h"
#include "core/common/client_messages.h"
#include "core/host/host_thread.h"
#include "third_party/webrtc/rtc_base/copyonwritebuffer.h"

namespace host {

IPCDataChannel::IPCDataChannel(): 
  connection_close_pending_(true),
  weak_factory_(this) {
  Init(mojo::edk::NamedPlatformHandle("/tmp/hello_ipc"));
}

IPCDataChannel::~IPCDataChannel() {

}

void IPCDataChannel::RegisterObserver(webrtc::DataChannelObserver* observer) {

}

void IPCDataChannel::UnregisterObserver() {

}

std::string IPCDataChannel::label() const {
  return std::string();
}

bool IPCDataChannel::reliable() const {
  return true;
}

bool IPCDataChannel::ordered() const {
  return true;
}

uint16_t IPCDataChannel::maxRetransmitTime() const {
  return 0;
}

uint16_t IPCDataChannel::maxRetransmits() const {
  return 0;
}

std::string IPCDataChannel::protocol() const {
  return std::string("ipc");
}

bool IPCDataChannel::negotiated() const {
  return false;
}

int IPCDataChannel::id() const {
  return -1;
}

IPCDataChannel::DataState IPCDataChannel::state() const {
  return static_cast<DataState>(0);
}

uint32_t IPCDataChannel::messages_sent() const {
  return 0;
}

uint64_t IPCDataChannel::bytes_sent() const {
  return 0;
}

uint32_t IPCDataChannel::messages_received() const {
  return 0;
}

uint64_t IPCDataChannel::bytes_received() const {
  return 0;
}

uint64_t IPCDataChannel::buffered_amount() const {
  return 0;
}

void IPCDataChannel::Close() {
  if (channel_) {
    channel_->Close();
    connection_close_pending_ = false;
  }
  peer_connection_.reset();
}

bool IPCDataChannel::Send(const webrtc::DataBuffer& buffer) {
  IPC::Message ipc_message;
  ipc_message.Reserve(buffer.size());
  ipc_message.WriteData(buffer.data.data<char>(), buffer.size());
  return channel_->Send(&ipc_message);
}

bool IPCDataChannel::Send(IPC::Message* message) {
  return channel_->Send(message);
}

void IPCDataChannel::Init(const mojo::edk::NamedPlatformHandle& channel_handle) {
  base::ThreadRestrictions::SetIOAllowed(true);
 
  mojo::edk::CreateServerHandleOptions options;
#if defined(OS_WIN)
  options.enforce_uniqueness = false;
  // Create a named pipe owned by the current user (the LocalService account
  // (SID: S-1-5-19) when running in the network process) which is available to
  // all authenticated users.
  // presubmit: allow wstring
  std::wstring user_sid;
  if (!base::win::GetUserSidString(&user_sid)) {
    //cb.Run(false);
    return;
  }
  std::string user_sid_utf8 = base::WideToUTF8(user_sid);
  options.security_descriptor = base::UTF8ToUTF16(base::StringPrintf(
      "O:%sG:%sD:(A;;GA;;;AU)", user_sid_utf8.c_str(), user_sid_utf8.c_str()));

#endif  // defined(OS_WIN)
  peer_connection_ = std::make_unique<mojo::edk::PeerConnection>();
  channel_ = IPC::Channel::CreateServer(
      peer_connection_
          ->Connect(mojo::edk::ConnectionParams(
              mojo::edk::TransportProtocol::kLegacy,
              mojo::edk::CreateServerHandle(channel_handle, options)))
          .release(),
      this, base::ThreadTaskRunnerHandle::Get());

  if (!channel_->Connect()) {
    channel_.reset();
    //cb.Run(false);
    return;
  }
  // It is safe to use base::Unretained here as |timer_| will be stopped and
  // this task will be removed when this instance is being destroyed.  All
  // methods must execute on the same thread (due to |thread_Checker_| so
  // the posted task and D'Tor can not execute concurrently.
  //timer_.Start(FROM_HERE, initial_connect_timeout_,
  //             base::Bind(&NamedIpcServer::OnChannelError,
  //                        base::Unretained(this)));
  //cb.Run(true);
}

void IPCDataChannel::AddRef() const {
  rtc::AtomicOps::Increment(&ref_count_);
}

rtc::RefCountReleaseStatus IPCDataChannel::Release() const {
  if (rtc::AtomicOps::Decrement(&ref_count_) == 0) {
    delete this;
    return rtc::RefCountReleaseStatus::kDroppedLastRef;
  }
  return rtc::RefCountReleaseStatus::kOtherRefsRemained;
}

bool IPCDataChannel::OnMessageReceived(const IPC::Message& message) {
  if (connection_close_pending_) {
    LOG(WARNING) << "IPC Message ignored because channel is being closed.";
    return false;
  }

  bool handled = true;
  // IPC_BEGIN_MESSAGE_MAP(NamedIpcServer, message)
  //   IPC_MESSAGE_HANDLER(ClientMsg_Request, OnClientRequest)
  //   IPC_MESSAGE_UNHANDLED(handled = false)
  // IPC_END_MESSAGE_MAP()

  CHECK(handled) << "Received unexpected IPC type: " << message.type();
  return handled;
}

void IPCDataChannel::OnChannelConnected(int32_t peer_pid) {
  //channel_->Send(new ClientHostMsg_ConnectionReady());
}

void IPCDataChannel::OnChannelError() {
  Close();
  
  HostThread::PostTask(
    HostThread::IO,
    FROM_HERE,
    base::BindOnce(
      &IPCDataChannel::Init,
      weak_factory_.GetWeakPtr(),
      channel_handle_));
}

}