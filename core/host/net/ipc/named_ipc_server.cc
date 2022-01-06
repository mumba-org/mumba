// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/net/ipc/named_ipc_server.h"

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
#include "core/host/host_controller.h"

namespace host {

namespace {

void CreateChannelResult(bool r) {} 

} 

// static 
std::unique_ptr<NamedIpcServer> NamedIpcServer::Create(int connection_id) {
  return base::WrapUnique(new NamedIpcServer(connection_id));
}

NamedIpcServer::NamedIpcServer(int connection_id): 
  connection_id_(connection_id),
  connection_close_pending_(false),
  //connect_callback_(connect_callback),
  //done_callback_(done_callback),
  //message_callback_(message_callback),
  weak_factory_(this) {

}

NamedIpcServer::~NamedIpcServer() {
  CloseChannel();
}

bool NamedIpcServer::Init(const mojo::edk::NamedPlatformHandle& channel_handle) {
  channel_handle_ = channel_handle;
  CreateChannel(channel_handle_, 
    base::Bind(&CreateChannelResult));
  return true;
}

bool NamedIpcServer::OnMessageReceived(const IPC::Message& message) {
  if (connection_close_pending_) {
    LOG(WARNING) << "IPC Message ignored because channel is being closed.";
    return false;
  }

  bool handled = true;
  IPC_BEGIN_MESSAGE_MAP(NamedIpcServer, message)
 //   IPC_MESSAGE_HANDLER(ClientMsg_QueryRequest, OnClientQueryRequest)
    IPC_MESSAGE_HANDLER(ClientMsg_ControlRequest, OnClientControlRequest)
    IPC_MESSAGE_UNHANDLED(handled = false)
  IPC_END_MESSAGE_MAP()

  CHECK(handled) << "Received unexpected IPC type: " << message.type();
  return handled;
}

void NamedIpcServer::OnChannelConnected(int32_t peer_pid) {
  LOG(INFO) << "NamedIpcServer::OnChannelConnected";
  // if (!connect_callback_.is_null()) {
  //   base::ResetAndReturn(&connect_callback_).Run();
  // }

// #if defined(OS_WIN)
//   DWORD peer_session_id;
//   if (!ProcessIdToSessionId(peer_pid, &peer_session_id)) {
//     PLOG(ERROR) << "ProcessIdToSessionId() failed";
//     connection_close_pending_ = true;
//   } else if (peer_session_id != client_session_details_->desktop_session_id()) {
//     LOG(ERROR) << "Ignoring connection attempt from outside remoted session.";
//     connection_close_pending_ = true;
//   }
//   if (connection_close_pending_) {
//     ipc_channel_->Send(
//         new ChromotingNetworkToRemoteSecurityKeyMsg_InvalidSession());

//     base::ThreadTaskRunnerHandle::Get()->PostTask(
//         FROM_HERE, base::Bind(&NamedIpcServer::OnChannelError,
//                               weak_factory_.GetWeakPtr()));
//     return;
//   }
// #else   // !defined(OS_WIN)
//   CHECK_EQ(client_session_details_->desktop_session_id(), UINT32_MAX);
// #endif  // !defined(OS_WIN)

  // Reset the timer to give the client a chance to send the request.
  //timer_.Start(FROM_HERE, initial_connect_timeout_,
  //             base::Bind(&NamedIpcServer::OnChannelError,
  //                        base::Unretained(this)));

  ipc_channel_->Send(new ClientHostMsg_ConnectionReady());
}

void NamedIpcServer::OnChannelError() {
  LOG(INFO) << "NamedIpcServer::OnChannelError";
  
  CloseChannel();
  
  HostThread::PostTask(
    HostThread::IO,
    FROM_HERE,
    base::BindOnce(
      &NamedIpcServer::CreateChannel,
      weak_factory_.GetWeakPtr(),
      channel_handle_,
      base::Bind(&CreateChannelResult)));

  //if (!connect_callback_.is_null()) {
  //  base::ResetAndReturn(&connect_callback_).Run();
  //}
  //if (!done_callback_.is_null()) {
    // Note: This callback may result in this object being torn down.
  //  base::ResetAndReturn(&done_callback_).Run();
  //}
}

void NamedIpcServer::CreateChannel(
  const mojo::edk::NamedPlatformHandle& channel_handle, 
  const base::Callback<void(bool)>& cb) {
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
    cb.Run(false);
    return;
  }
  std::string user_sid_utf8 = base::WideToUTF8(user_sid);
  options.security_descriptor = base::UTF8ToUTF16(base::StringPrintf(
      "O:%sG:%sD:(A;;GA;;;AU)", user_sid_utf8.c_str(), user_sid_utf8.c_str()));

#endif  // defined(OS_WIN)
  peer_connection_ = std::make_unique<mojo::edk::PeerConnection>();
  ipc_channel_ = IPC::Channel::CreateServer(
      peer_connection_
          ->Connect(mojo::edk::ConnectionParams(
              mojo::edk::TransportProtocol::kLegacy,
              mojo::edk::CreateServerHandle(channel_handle, options)))
          .release(),
      this, base::ThreadTaskRunnerHandle::Get());

  if (!ipc_channel_->Connect()) {
    ipc_channel_.reset();
    cb.Run(false);
    return;
  }
  // It is safe to use base::Unretained here as |timer_| will be stopped and
  // this task will be removed when this instance is being destroyed.  All
  // methods must execute on the same thread (due to |thread_Checker_| so
  // the posted task and D'Tor can not execute concurrently.
  //timer_.Start(FROM_HERE, initial_connect_timeout_,
  //             base::Bind(&NamedIpcServer::OnChannelError,
  //                        base::Unretained(this)));
  cb.Run(true);
}

void NamedIpcServer::CloseChannel() {
  if (ipc_channel_) {
    ipc_channel_->Close();
    connection_close_pending_ = false;
  }
  peer_connection_.reset();
}

// void NamedIpcServer::OnClientQueryRequest(const std::string& request) {
//   std::string hex = base::HexEncode(request.data(), request.size());
//   printf("received payload (size: %zu)\n%s\n", request.size(), hex.c_str());
  
//   if(request.empty()) {
//     LOG(ERROR) << "bad: empty request";
//     return;
//   }
//   //std::string hex_string = base::HexEncode(request.data(), request.size());
//   //printf("request (%zu): '%s'", request.size() ,hex_string.c_str());
//   scoped_refptr<HostController> controller = HostController::Instance();
//   controller->ProcessQueryRequest(request, base::BindOnce(&NamedIpcServer::OnQueryReply, base::Unretained(this)));
// }

void NamedIpcServer::OnClientControlRequest(const std::string& request) {
  DLOG(ERROR) << "NamedIpcServer::OnClientControlRequest: not working!";
  //scoped_refptr<HostController> controller = HostController::Instance();
  //controller->ProcessControlRequest(request, base::Bind(&NamedIpcServer::OnControlReply, base::Unretained(this))); 
}


// void NamedIpcServer::OnQueryReply(std::string buf) {
//   HostThread::PostTask(HostThread::IO, 
//     FROM_HERE, 
//     base::BindOnce(&NamedIpcServer::OnQueryReplyOnIOThread, 
//       base::Unretained(this), 
//       base::Passed(std::move(buf))));
// }

// void NamedIpcServer::OnQueryReplyOnIOThread(std::string buf) {
//   ipc_channel_->Send(new ClientHostMsg_QueryReply(buf)); 
// }

void NamedIpcServer::OnControlReply(int code) {
  HostThread::PostTask(HostThread::IO, 
    FROM_HERE, 
    base::BindOnce(&NamedIpcServer::OnControlReplyOnIOThread, 
      base::Unretained(this), 
      code));
}

void NamedIpcServer::OnControlReplyOnIOThread(int code) {
  ipc_channel_->Send(new ClientHostMsg_ControlReply(code == net::OK ? "ok" : "failed")); 
}

}