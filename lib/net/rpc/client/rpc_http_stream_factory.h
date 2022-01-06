// Copyright (c) 2017 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_RPC_CLIENT_RPC_HTTP_STREAM_FACTORY_H_
#define NET_RPC_CLIENT_RPC_HTTP_STREAM_FACTORY_H_

#include <memory>

#include "base/macros.h"
#include "base/synchronization/lock.h"
#include "base/memory/weak_ptr.h"
#include "core/shared/common/url.h"
#include "net/rpc/client/rpc_stream_factory.h"
#include "rpc/grpc.h"

namespace net {

// TODO: Anexar channel ao transport -> e reusar channel para calls
// com o mesmo endereço

class NET_EXPORT RpcHttpStreamFactory : public RpcStreamFactory {
public:
  RpcHttpStreamFactory();
  ~RpcHttpStreamFactory() override;

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

  base::WeakPtrFactory<RpcHttpStreamFactory> weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(RpcHttpStreamFactory);
};

}

#endif