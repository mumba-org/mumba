// Copyright (c) 2017 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_RPC_CLIENT_RPC_IPC_STREAM_FACTORY_H_
#define NET_RPC_CLIENT_RPC_IPC_STREAM_FACTORY_H_

#include "base/macros.h"
//#include "base/threading/sequenced_worker_pool.h"
#include "core/shared/common/url.h"
#include "net/rpc/client/rpc_stream_factory.h"
#include "rpc/grpc.h"

namespace net {

class NET_EXPORT RpcIpcStreamFactory : public RpcStreamFactory {
public:
  RpcIpcStreamFactory();
  ~RpcIpcStreamFactory() override;

  RpcTransportType type() const override;
  
  void CreateUnidirectionalStream(
  	const std::string& host, 
  	const std::string& port, 
  	const std::string& name, 
  	const std::string& params, 
  	const scoped_refptr<base::SequencedTaskRunner>& task_runner,
  	Callback callback) override;
  
  void CreateBidirectionalStream(
  	const std::string& host, 
  	const std::string& port, 
  	const std::string& name, 
  	const std::string& params,
  	const scoped_refptr<base::SequencedTaskRunner>& task_runner,
		RpcMethodType type,
  	Callback callback) override;
  
private:

  //grpc_channel_args args_;
  //grpc_channel* channel_;

  DISALLOW_COPY_AND_ASSIGN(RpcIpcStreamFactory);
};

}

#endif