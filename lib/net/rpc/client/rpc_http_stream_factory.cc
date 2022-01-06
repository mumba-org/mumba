// Copyright (c) 2017 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/rpc/client/rpc_http_stream_factory.h"

#include "base/location.h"
#include "base/bind.h"
#include "base/callback.h"
#include "net/rpc/client/rpc_channel.h"
#include "net/rpc/client/rpc_stream.h"
#include "net/rpc/client/rpc_unidirectional_stream.h"
#include "net/rpc/client/rpc_bidirectional_stream.h"
//#include "net/rpc/rpc_http_connection.h"

namespace net {

RpcHttpStreamFactory::RpcHttpStreamFactory(): 
  weak_factory_(this) {
   
}

RpcHttpStreamFactory::~RpcHttpStreamFactory() {

}

RpcTransportType RpcHttpStreamFactory::type() const { 
  return RpcTransportType::kHTTP; 
}

void RpcHttpStreamFactory::CreateUnidirectionalStream(
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
    OK,
    RpcUnidirectionalStream::Create(std::move(channel), host, port, name, params, task_runner));
}

void RpcHttpStreamFactory::CreateBidirectionalStream(
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

}