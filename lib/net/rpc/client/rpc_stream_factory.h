// Copyright (c) 2017 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_RPC_CLIENT_RPC_STREAM_FACTORY_H_
#define NET_RPC_CLIENT_RPC_STREAM_FACTORY_H_

#include <memory>

#include "base/macros.h"
#include "base/single_thread_task_runner.h"
#include "net/rpc/rpc.h"
#include "net/base/net_errors.h"

namespace net {
class RpcStream;

class NET_EXPORT RpcStreamFactory {
public:
  using Callback = base::Callback<void(Error, std::unique_ptr<RpcStream>)>;

  virtual ~RpcStreamFactory(){}
  virtual RpcTransportType type() const = 0;
  
  virtual void CreateUnidirectionalStream(
  	const std::string& host, 
  	const std::string& port, 
  	const std::string& name, 
  	const std::string& params,
  	const scoped_refptr<base::SequencedTaskRunner>& task_runner,
  	Callback callback) = 0;
  
  virtual void CreateBidirectionalStream(
  	const std::string& host, 
  	const std::string& port, 
  	const std::string& name, 
  	const std::string& params,
  	const scoped_refptr<base::SequencedTaskRunner>& task_runner,
		RpcMethodType type,
  	Callback callback) = 0;
};

}

#endif