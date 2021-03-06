// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SERVICES_NETWORK_PUBLIC_CPP_SERVER_HTTP_CONNECTION_H_
#define SERVICES_NETWORK_PUBLIC_CPP_SERVER_HTTP_CONNECTION_H_

#include <memory>
#include <string>

#include "base/macros.h"
#include "base/optional.h"
#include "mojo/public/cpp/system/data_pipe.h"
#include "mojo/public/cpp/system/simple_watcher.h"
#include "services/network/public/mojom/tcp_socket.mojom.h"

namespace network {

namespace server {

class WebSocket;

// A container which has all information of an http connection. It includes
// id, underlying socket, and pending read/write data.
class HttpConnection {
 public:
  HttpConnection(int id,
                 mojom::TCPConnectedSocketPtr socket,
                 mojo::ScopedDataPipeConsumerHandle socket_receive_handle,
                 mojo::ScopedDataPipeProducerHandle socket_send_handle,
                 const net::IPEndPoint& peer_addr);
  ~HttpConnection();

  int id() const { return id_; }
  mojom::TCPConnectedSocket* socket() const { return socket_.get(); }
  mojo::DataPipeConsumerHandle receive_handle() const {
    return socket_receive_handle_.get();
  }
  mojo::SimpleWatcher& read_watcher() { return receive_pipe_watcher_; }
  mojo::DataPipeProducerHandle send_handle() const {
    return socket_send_handle_.get();
  }
  mojo::SimpleWatcher& write_watcher() { return send_pipe_watcher_; }
  const net::IPEndPoint& GetPeerAddress() { return peer_addr_; }
  std::string& read_buf() { return read_buf_; }
  std::string& write_buf() { return write_buf_; }

  WebSocket* web_socket() const { return web_socket_.get(); }
  void SetWebSocket(std::unique_ptr<WebSocket> web_socket);

  const size_t kMaxBufferSize = 1 * 1024 * 1024;  // 1 Mbyte

 private:
  const int id_;
  const mojom::TCPConnectedSocketPtr socket_;
  const mojo::ScopedDataPipeConsumerHandle socket_receive_handle_;
  mojo::SimpleWatcher receive_pipe_watcher_;
  const mojo::ScopedDataPipeProducerHandle socket_send_handle_;
  mojo::SimpleWatcher send_pipe_watcher_;
  const net::IPEndPoint peer_addr_;
  // Stores data that has been read from the server but not yet parsed into an
  // HTTP request.
  std::string read_buf_;
  // Stores data that has been marked for sending but has not yet been sent to
  // the network.
  std::string write_buf_;

  std::unique_ptr<WebSocket> web_socket_;

  DISALLOW_COPY_AND_ASSIGN(HttpConnection);
};

}  // namespace server

}  // namespace network

#endif  // SERVICES_NETWORK_PUBLIC_CPP_SERVER_HTTP_CONNECTION_H_
