// Copyright (c) 2017 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/rpc/client/rpc_client.h"

#include "base/task_scheduler/post_task.h"
#include "base/sequenced_task_runner.h"
#include "base/threading/thread_task_runner_handle.h"
#include "net/rpc/client/rpc_host.h"
#include "net/rpc/client/rpc_http_transport.h"
#include "net/rpc/client/rpc_inproc_transport.h"

namespace net {

namespace {

std::string FormatMethod(const std::string& full_name) {
  std::string method_name;
  auto pos = full_name.find_last_of(".");
  if (pos != std::string::npos) {
    method_name = "/" + full_name.substr(0, pos) + "/" + full_name.substr(pos+1);
    return method_name;
  }
  return full_name;
} 

}

RpcClient::RpcClient(
    RpcHost* host): host_(host) {
  // host_(host),
  // io_task_runner_(
  //   base::CreateSingleThreadTaskRunnerWithTraits(
  //      {base::MayBlock(), base::WithBaseSyncPrimitives(),
  //      base::TaskShutdownBehavior::CONTINUE_ON_SHUTDOWN},
  //      base::SingleThreadTaskRunnerThreadMode::DEDICATED)) {
  
}

RpcClient::~RpcClient() {
  //worker_pool_ = nullptr;
  host_ = nullptr;
}

std::unique_ptr<RpcStream> RpcClient::NewStream(const std::string& host, const std::string& port, const std::string& name, const std::string& params) {
  RpcStreamFactory* transport = nullptr;

  RpcHttpStreamFactory http_transport;
  RpcIpcStreamFactory inproc_transport;

  RpcDescriptor* node = host_->GetNode(name);

  if (!node) {
    LOG(ERROR) << "rpc node for " << name << " not found";
    return std::unique_ptr<RpcStream>();
  }
  
  if (node->transport_type == RpcTransportType::kHTTP) {
    transport = &http_transport;
  } else if (node->transport_type == RpcTransportType::kIPC) {
    transport = &inproc_transport;
  } 
    
  if (!transport) {
    LOG(ERROR) << "unsupported rpc connection type";
    return std::unique_ptr<RpcStream>();
  }
  std::string method_name = FormatMethod(node->full_name);
  if (node->method_type == RpcMethodType::kNORMAL) {
    return transport->CreateSingle(host, port, method_name, params, 
      // FIXME: now that we are on net:: see which task_runner we should use
      base::CreateSingleThreadTaskRunnerWithTraits(
       {base::MayBlock(), base::TaskShutdownBehavior::CONTINUE_ON_SHUTDOWN},
       base::SingleThreadTaskRunnerThreadMode::SHARED));
  } else if (node->method_type == RpcMethodType::kSERVER_STREAM) {
    return transport->CreateContinuous(host, port, method_name, params, 
      // FIXME: now that we are on net:: see which task_runner we should use
      base::CreateSingleThreadTaskRunnerWithTraits(
       {base::MayBlock(), base::WithBaseSyncPrimitives(),
       base::TaskShutdownBehavior::CONTINUE_ON_SHUTDOWN},
       base::SingleThreadTaskRunnerThreadMode::DEDICATED));
  }

  return std::unique_ptr<RpcStream>();
}

// bool RpcClient::IsConnected() const {
//   return connection_ != nullptr;
// }

// bool RpcClient::Connect() {
//   std::unique_ptr<RpcConnection> conn = RpcConnection::Open(descriptor_->url);
//   if (!conn) {
//     return false;
//   }
//   connection_ = conn.Pass();
//   return true;
// }

// void RpcClient::Disconnect() {
//   connection_->Close();
//   connection_.reset();
// }

// std::unique_ptr<RpcCall> RpcClient::Call() {
//   return connection_->Call(worker_pool_).Pass();
// }

}