// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "services/network/socket_data_pump.h"

#include <utility>

#include "base/logging.h"
#include "base/memory/ptr_util.h"
#include "base/memory/scoped_refptr.h"
#include "base/numerics/safe_conversions.h"
#include "base/optional.h"
#include "net/base/io_buffer.h"
#include "net/base/net_errors.h"
#include "net/log/net_log.h"
#include "net/socket/client_socket_factory.h"
#include "net/socket/client_socket_handle.h"

namespace network {

SocketDataPump::SocketDataPump(
    mojom::TCPConnectedSocketObserverPtr observer,
    net::StreamSocket* socket,
    mojo::ScopedDataPipeProducerHandle receive_pipe_handle,
    mojo::ScopedDataPipeConsumerHandle send_pipe_handle,
    const net::NetworkTrafficAnnotationTag& traffic_annotation)
    : observer_(std::move(observer)),
      socket_(socket),
      receive_stream_(std::move(receive_pipe_handle)),
      receive_stream_watcher_(FROM_HERE,
                              mojo::SimpleWatcher::ArmingPolicy::MANUAL),
      send_stream_(std::move(send_pipe_handle)),
      send_stream_watcher_(FROM_HERE,
                           mojo::SimpleWatcher::ArmingPolicy::MANUAL),
      traffic_annotation_(traffic_annotation),
      weak_factory_(this) {
  send_stream_watcher_.Watch(
      send_stream_.get(),
      MOJO_HANDLE_SIGNAL_READABLE | MOJO_HANDLE_SIGNAL_PEER_CLOSED,
      base::BindRepeating(&SocketDataPump::OnSendStreamReadable,
                          base::Unretained(this)));
  receive_stream_watcher_.Watch(
      receive_stream_.get(),
      MOJO_HANDLE_SIGNAL_WRITABLE | MOJO_HANDLE_SIGNAL_PEER_CLOSED,
      base::BindRepeating(&SocketDataPump::OnReceiveStreamWritable,
                          base::Unretained(this)));
  ReceiveMore();
  SendMore();
}

SocketDataPump::~SocketDataPump() {}

void SocketDataPump::ReceiveMore() {
  DCHECK(receive_stream_.is_valid());
  DCHECK(!pending_receive_buffer_);

  uint32_t num_bytes = 0;
  MojoResult result = NetToMojoPendingBuffer::BeginWrite(
      &receive_stream_, &pending_receive_buffer_, &num_bytes);
  if (result == MOJO_RESULT_SHOULD_WAIT) {
    receive_stream_watcher_.ArmOrNotify();
    return;
  }
  if (result != MOJO_RESULT_OK) {
    ShutdownReceive();
    return;
  }
  DCHECK(pending_receive_buffer_);
  scoped_refptr<net::IOBuffer> buf =
      base::MakeRefCounted<NetToMojoIOBuffer>(pending_receive_buffer_.get());
  // Use WeakPtr here because |this| doesn't outlive |socket_|.
  int read_result =
      socket_->Read(buf.get(), base::saturated_cast<int>(num_bytes),
                    base::BindRepeating(&SocketDataPump::OnNetworkReadCompleted,
                                        weak_factory_.GetWeakPtr()));
  if (read_result == net::ERR_IO_PENDING)
    return;
  OnNetworkReadCompleted(read_result);
}

void SocketDataPump::OnReceiveStreamWritable(MojoResult result) {
  DCHECK(receive_stream_.is_valid());
  DCHECK(!pending_receive_buffer_);

  if (result != MOJO_RESULT_OK) {
    ShutdownReceive();
    return;
  }
  ReceiveMore();
}

void SocketDataPump::OnNetworkReadCompleted(int result) {
  DCHECK(!receive_stream_.is_valid());
  DCHECK(pending_receive_buffer_);

  if (result < 0 && observer_)
    observer_->OnReadError(result);

  receive_stream_ = pending_receive_buffer_->Complete(result >= 0 ? result : 0);
  pending_receive_buffer_ = nullptr;

  if (result <= 0) {
    ShutdownReceive();
    return;
  }
  ReceiveMore();
}

void SocketDataPump::ShutdownReceive() {
  DCHECK(receive_stream_.is_valid());
  DCHECK(!pending_receive_buffer_);

  receive_stream_watcher_.Cancel();
  pending_receive_buffer_ = nullptr;
  receive_stream_.reset();
}

void SocketDataPump::SendMore() {
  DCHECK(send_stream_.is_valid());
  DCHECK(!pending_send_buffer_);

  uint32_t num_bytes = 0;
  MojoResult result = MojoToNetPendingBuffer::BeginRead(
      &send_stream_, &pending_send_buffer_, &num_bytes);
  if (result == MOJO_RESULT_SHOULD_WAIT) {
    send_stream_watcher_.ArmOrNotify();
    return;
  }
  if (result != MOJO_RESULT_OK) {
    ShutdownSend();
    return;
  }
  DCHECK_EQ(MOJO_RESULT_OK, result);
  DCHECK(pending_send_buffer_);
  scoped_refptr<net::IOBuffer> buf = base::MakeRefCounted<net::WrappedIOBuffer>(
      pending_send_buffer_->buffer());
  // Use WeakPtr here because |this| doesn't outlive |socket_|.
  int write_result = socket_->Write(
      buf.get(), static_cast<int>(num_bytes),
      base::BindRepeating(&SocketDataPump::OnNetworkWriteCompleted,
                          weak_factory_.GetWeakPtr()),
      traffic_annotation_);
  if (write_result == net::ERR_IO_PENDING)
    return;
  OnNetworkWriteCompleted(write_result);
}

void SocketDataPump::OnSendStreamReadable(MojoResult result) {
  DCHECK(!pending_send_buffer_);
  DCHECK(send_stream_.is_valid());

  if (result != MOJO_RESULT_OK) {
    ShutdownSend();
    return;
  }
  SendMore();
}

void SocketDataPump::OnNetworkWriteCompleted(int result) {
  DCHECK(pending_send_buffer_);
  DCHECK(!send_stream_.is_valid());

  if (result < 0 && observer_)
    observer_->OnWriteError(result);

  // Partial write is possible.
  pending_send_buffer_->CompleteRead(result >= 0 ? result : 0);
  send_stream_ = pending_send_buffer_->ReleaseHandle();
  pending_send_buffer_ = nullptr;

  if (result <= 0) {
    ShutdownSend();
    return;
  }
  SendMore();
}

void SocketDataPump::ShutdownSend() {
  DCHECK(send_stream_.is_valid());
  DCHECK(!pending_send_buffer_);

  send_stream_watcher_.Cancel();
  pending_send_buffer_ = nullptr;
  send_stream_.reset();
}

}  // namespace network
