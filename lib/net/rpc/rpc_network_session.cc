// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/rpc/rpc_network_session.h"

#include "base/task_scheduler/post_task.h"
#include "base/sequenced_task_runner.h"
#include "base/threading/thread_task_runner_handle.h"
#include "net/rpc/client/rpc_stream.h"

namespace net {


RpcNetworkSession::RpcNetworkSession() {

}

RpcNetworkSession::~RpcNetworkSession() {

}

void RpcNetworkSession::CreateHttpUnidirectionalStream(
  const std::string& host, 
  const std::string& port, 
  const std::string& name, 
  const std::string& params, 
  const scoped_refptr<base::SequencedTaskRunner>& task_runner,
  RpcStreamFactory::Callback callback) {
  http_stream_factory_.CreateUnidirectionalStream(
    host, 
    port, 
    name, 
    params, 
    task_runner, 
    std::move(callback));
}

void RpcNetworkSession::CreateHttpBidirectionalStream(
  const std::string& host, 
  const std::string& port, 
  const std::string& name, 
  const std::string& params, 
  const scoped_refptr<base::SequencedTaskRunner>& task_runner,
  RpcMethodType method_type,
  RpcStreamFactory::Callback callback) {
  http_stream_factory_.CreateBidirectionalStream(
    host, 
    port, 
    name, 
    params, 
    task_runner, 
    method_type,
    std::move(callback));
}

void RpcNetworkSession::CreateIpcUnidirectionalStream(
  const std::string& host, 
  const std::string& port, 
  const std::string& name, 
  const std::string& params, 
  const scoped_refptr<base::SequencedTaskRunner>& task_runner,
  RpcStreamFactory::Callback callback) {

  ipc_stream_factory_.CreateUnidirectionalStream(
    host, 
    port, 
    name, 
    params, 
     task_runner, 
    std::move(callback));
}

void RpcNetworkSession::CreateIpcBidirectionalStream(
  const std::string& host, 
  const std::string& port, 
  const std::string& name, 
  const std::string& params, 
  const scoped_refptr<base::SequencedTaskRunner>& task_runner,
  RpcMethodType method_type,
  RpcStreamFactory::Callback callback) {
  
  ipc_stream_factory_.CreateBidirectionalStream(
    host, 
    port, 
    name, 
    params, 
    task_runner, 
    method_type,
    std::move(callback));
}

void RpcNetworkSession::RpcStreamFinished(RpcStream* caller) {
  // for (auto it = callers_.begin(); it != callers_.end(); ++it) {
  //   if (caller == it->get()) {
  //     callers_.erase(it);
  //     return;
  //   }
  // }
}

bool RpcNetworkSession::HaveEncoder(const std::string& service, const std::string& method) const {
  for (auto it = encoders_.begin(); it != encoders_.end(); ++it) {
    if ((*it)->CanEncode(service, method)) {
      return true;
    }
  }
  return false;
}

RpcMessageEncoder* RpcNetworkSession::GetEncoder(const std::string& service, const std::string& method) const {
  for (auto it = encoders_.begin(); it != encoders_.end(); ++it) {
    if ((*it)->CanEncode(service, method)) {
      return *it;
    }
  }
  return nullptr;
}

void RpcNetworkSession::AddEncoder(RpcMessageEncoder* encoder) {
  encoders_.push_back(encoder);
}

void RpcNetworkSession::RemoveEncoder(RpcMessageEncoder* encoder) {
  for (auto it = encoders_.begin(); it != encoders_.end(); ++it) {
    if (*it == encoder) {
      encoders_.erase(it);
      return;
    }
  }
}

}