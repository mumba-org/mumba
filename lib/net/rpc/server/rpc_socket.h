// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_RPC_RPC_SOCKET_H_
#define NET_RPC_RPC_SOCKET_H_

#include <memory>

#include "base/macros.h"
#include "net/log/net_log_with_source.h"
#include "net/socket/stream_socket.h"
#include "net/rpc/server/rpc_call_state.h"

namespace net {
class RpcService;

// Wraps a TCPClientSocket but might encapsulate some gRPC logic
class NET_EXPORT RpcSocket : public net::StreamSocket {
public:
  class Delegate {
  public:
    virtual ~Delegate() {}
    virtual void OnRpcCallDestroyed(RpcSocket* socket, int call_id) = 0;
  };

  // FIXME: WeakPtr for RpcService and Delegate
  RpcSocket(Delegate* delegate, RpcService* service, int socket_id, std::unique_ptr<net::StreamSocket> socket);
  RpcSocket(Delegate* delegate, int socket_id, std::unique_ptr<net::StreamSocket> socket);
  ~RpcSocket() override;

  int socket_id() const {
    return socket_id_;
  }

  net::StreamSocket* socket() const {
    return socket_.get();
  }

  // FIXME: WeakPtr
  RpcService* service() const {
    return service_;
  }

  // Socket
  int Read(net::IOBuffer* buf,
           int buf_len,
           net::CompletionOnceCallback callback) override;
  int Write(net::IOBuffer* buf,
            int buf_len,
            net::CompletionOnceCallback callback,
            const net::NetworkTrafficAnnotationTag& traffic_annotation) override;
  int SetReceiveBufferSize(int32_t size) override;
  int SetSendBufferSize(int32_t size) override;

  // StreamSocket
  int Connect(net::CompletionOnceCallback callback) override;
  void Disconnect() override;
  bool IsConnected() const override;
  bool IsConnectedAndIdle() const override;
  int GetPeerAddress(net::IPEndPoint* address) const override;
  int GetLocalAddress(net::IPEndPoint* address) const override;
  const net::NetLogWithSource& NetLog() const override;
  void SetSubresourceSpeculation() override;
  void SetOmniboxSpeculation() override;
  bool WasEverUsed() const override;
  bool WasAlpnNegotiated() const override;
  net::NextProto GetNegotiatedProtocol() const override;
  bool GetSSLInfo(net::SSLInfo* ssl_info) override;
  void GetConnectionAttempts(net::ConnectionAttempts* out) const override;
  void ClearConnectionAttempts() override;
  void AddConnectionAttempts(const net::ConnectionAttempts& attempts) override;
  int64_t GetTotalReceivedBytes() const override;
  void ApplySocketTag(const net::SocketTag& tag) override;

  void DetachFromThread();

  void DispatchSendMessage(int call_id, std::vector<char> data, int method_type);
  void DispatchReceiveMessage(int call_id, int method_type);

  void ReceiveMessage(int call_id, int method_type);
  void SendMessage(int call_id, std::vector<char> data, int method_type);
  void SendMessageNow(int call_id, std::vector<char> data, int method_type);
  void SendRpcStatus(int call_id, int status_code);

  void OnSendMessageComplete(int call_id, RpcState type);
  void OnSendBufferedMessageComplete(int call_id, RpcState type);
  void OnReceiveInitialMetadataComplete(int call_id);
  void OnRecvMessageComplete(int call_id);

  base::WeakPtr<RpcSocket> GetWeakPtr();

  bool have_pending_writes() {
    base::AutoLock lock(pending_writes_lock_);
    return pending_writes_.size() > 0;
  }

  size_t pending_writes_count() {
    base::AutoLock lock(pending_writes_lock_);
    return pending_writes_.size();
  }
  
  void CallWillDestroy(RpcCallState* call);
  void CallDestroyed(int call_id);

private:
  bool ReadData(base::WeakPtr<RpcCallState> call, RpcState next_state);
  bool HandleUnaryCall(base::WeakPtr<RpcCallState> call, std::vector<char> data);
  bool Send(base::WeakPtr<RpcCallState> call, RpcState type, std::vector<char> data);
  bool SendNow(base::WeakPtr<RpcCallState> call, RpcState type, std::vector<char> data, bool close_stream);
  bool SendBuffered(base::WeakPtr<RpcCallState> call, RpcState type);
  void ProcessBuffered(base::WeakPtr<RpcCallState> call, RpcState type);
  void ProcessReadData(base::WeakPtr<RpcCallState> call, RpcState type);
  bool SendStatus(base::WeakPtr<RpcCallState> call, int status_code);
  bool ReceiveInitialMetadata(base::WeakPtr<RpcCallState> call);
  //bool SendRecvCloseOnServer(base::WeakPtr<RpcCallState> call);
  void ReplySendError(base::WeakPtr<RpcCallState> call, int rc);
  bool ReadHeader(const base::WeakPtr<RpcCallState>& call, const std::vector<char>& header_data);

//  void ReplySendErrorOnIOThread(IPC::Message* message);

  // FIXME: WeakPtr
  Delegate* delegate_;
  int socket_id_;
  std::unique_ptr<net::StreamSocket> socket_;
  net::NetLogWithSource net_log_;
  // FIXME: WeakPtr
  RpcService* service_;
  std::vector<std::vector<char>> pending_writes_;
  base::Lock pending_writes_lock_;

  //grpc_status_code close_status_;
  //grpc_slice close_status_details_;
  base::WeakPtrFactory<RpcSocket> weak_factory_;
  
  DISALLOW_COPY_AND_ASSIGN(RpcSocket); 
};

}

#endif