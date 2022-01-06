// Copyright (c) 2017 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/rpc/client/rpc_client.h"

#include "base/task_scheduler/post_task.h"
#include "base/sequenced_task_runner.h"
#include "base/threading/thread_task_runner_handle.h"
#include "core/host/rpc/client/rpc_host.h"

namespace host {

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

void RpcClient::NewStream(const std::string& host, const std::string& port, const std::string& name, const std::string& params,
  net::RpcStreamFactory::Callback callback) {
  net::RpcStreamFactory* transport = nullptr;

  net::RpcDescriptor* node = host_->GetNode(name);

  if (!node) {
    LOG(ERROR) << "rpc node for " << name << " not found";
    std::move(callback).Run(net::ERR_FAILED, std::unique_ptr<net::RpcStream>());
    return;
  }
  
  if (node->transport_type == net::RpcTransportType::kHTTP) {
    transport = &http_transport_;
  } else if (node->transport_type == net::RpcTransportType::kIPC) {
    transport = &inproc_transport_;
  } 
    
  if (!transport) {
    LOG(ERROR) << "unsupported rpc connection type";
    std::move(callback).Run(net::ERR_FAILED, std::unique_ptr<net::RpcStream>());
    return;
  }
  std::string method_name = FormatMethod(node->full_name);
  if (node->method_type == net::RpcMethodType::kNORMAL) {
    transport->CreateUnidirectionalStream(host, port, method_name, params, 
      // FIXME: now that we are on net:: see which task_runner we should use
      base::CreateSingleThreadTaskRunnerWithTraits(
       {base::MayBlock(), base::TaskShutdownBehavior::CONTINUE_ON_SHUTDOWN},
       base::SingleThreadTaskRunnerThreadMode::DEDICATED),
       std::move(callback));
  } else if (node->method_type == net::RpcMethodType::kSERVER_STREAM) {
    transport->CreateBidirectionalStream(host, port, method_name, params, 
      // FIXME: now that we are on net:: see which task_runner we should use
      base::CreateSingleThreadTaskRunnerWithTraits(
       {base::MayBlock(), base::WithBaseSyncPrimitives(),
       base::TaskShutdownBehavior::CONTINUE_ON_SHUTDOWN},
       base::SingleThreadTaskRunnerThreadMode::DEDICATED),
       node->method_type,
       std::move(callback));
  }
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