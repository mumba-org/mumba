// Copyright (c) 2017 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/rpc/client/rpc_ipc_stream_factory.h"

#include "net/rpc/client/rpc_stream.h"
#include "net/rpc/client/rpc_unidirectional_stream.h"
#include "net/rpc/client/rpc_bidirectional_stream.h"
#include "net/rpc/client/rpc_channel.h"
//#include "net/rpc/rpc_inproc_connection.h"

namespace net {

RpcIpcStreamFactory::RpcIpcStreamFactory() {
  
}

RpcIpcStreamFactory::~RpcIpcStreamFactory() {

}

RpcTransportType RpcIpcStreamFactory::type() const { 
  return RpcTransportType::kIPC; 
}

void RpcIpcStreamFactory::CreateUnidirectionalStream(
  const std::string& host, 
  const std::string& port, 
  const std::string& name, 
  const std::string& params, 
  const scoped_refptr<base::SequencedTaskRunner>& task_runner,
  Callback callback) {

  std::unique_ptr<RpcChannel> channel = std::make_unique<RpcChannel>(type());

  if (!channel->Open(host, port)) {
    std::move(callback).Run(ERR_FAILED, std::unique_ptr<RpcStream>());
    return;
  }
  
  std::move(callback).Run(
    OK, RpcUnidirectionalStream::Create(std::move(channel), host, port, name, params, task_runner));
}

void RpcIpcStreamFactory::CreateBidirectionalStream(
  const std::string& host, 
  const std::string& port, 
  const std::string& name, 
  const std::string& params, 
  const scoped_refptr<base::SequencedTaskRunner>& task_runner,
  RpcMethodType method_type,
  Callback callback) {
  
  std::unique_ptr<RpcChannel> channel = std::make_unique<RpcChannel>(type());
  if (!channel->Open(host, port)) {
    std::move(callback).Run(ERR_FAILED, std::unique_ptr<RpcStream>());
    return;
  }
  
  std::move(callback).Run(
    OK, RpcBidirectionalStream::Create(std::move(channel), host, port, name, params, task_runner, method_type));
}

// void RpcIpcStreamFactory::Connect() {
//   //std::string grpc_addr = "unix:" + url_.host();
//   //channel_ = grpc_insecure_channel_create(grpc_addr.c_str(), &args_, nullptr);
// }

// void RpcIpcStreamFactory::Close() {
//   //grpc_channel_destroy(channel_);
// }

// std::unique_ptr<RpcConnection> RpcIpcStreamFactory::CreateConnection(const URL& url) {
//   return std::unique_ptr<RpcConnection>(new RpcInprocConnection(url));
// }

// std::unique_ptr<RpcCall> RpcIpcStreamFactory::Call(scoped_refptr<base::SequencedWorkerPool> worker_pool) {
//   std::string grpc_addr = "unix:" + url_.host();
//   grpc_channel_args args;
//   memset(&args, 0, sizeof(args));
//   grpc_channel* channel = grpc_insecure_channel_create(grpc_addr.c_str(), &args, nullptr);

//   return std::unique_ptr<RpcCall>(new RpcCall(channel));
// }

}