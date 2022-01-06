// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_RPC_RPC_NETWORK_SESSION_H_
#define NET_RPC_RPC_NETWORK_SESSION_H_

#include <stddef.h>
#include <stdint.h>

#include <map>
#include <memory>
#include <set>
#include <string>
#include <unordered_set>
#include <vector>

#include "base/bind.h"
#include "base/containers/flat_set.h"
#include "base/memory/ref_counted.h"
#include "base/memory/weak_ptr.h"
#include "base/threading/thread_checker.h"
#include "net/base/host_mapping_rules.h"
#include "net/base/host_port_pair.h"
#include "net/base/net_export.h"
#include "net/dns/host_resolver.h"
#include "net/rpc/rpc_message_encoder.h"
#include "net/rpc/client/rpc_http_stream_factory.h"
#include "net/rpc/client/rpc_ipc_stream_factory.h"

namespace net {
class RpcStream;

// This class holds session objects used by RpcTransaction objects.
class NET_EXPORT RpcNetworkSession {
 public:
  RpcNetworkSession();
  ~RpcNetworkSession();
  
  RpcHttpStreamFactory* http_stream_factory() {
    return &http_stream_factory_;
  }

  RpcIpcStreamFactory* ipc_stream_factory() {
    return &ipc_stream_factory_;
  }

  void CreateHttpUnidirectionalStream(
    const std::string& host, 
  	const std::string& port, 
  	const std::string& name, 
  	const std::string& params, 
  	const scoped_refptr<base::SequencedTaskRunner>& task_runner,
  	RpcStreamFactory::Callback callback);

  void CreateHttpBidirectionalStream(
    const std::string& host, 
  	const std::string& port, 
  	const std::string& name, 
  	const std::string& params, 
  	const scoped_refptr<base::SequencedTaskRunner>& task_runner,
    RpcMethodType method_type,
  	RpcStreamFactory::Callback callback);

    void CreateIpcUnidirectionalStream(
    const std::string& host, 
  	const std::string& port, 
  	const std::string& name, 
  	const std::string& params, 
  	const scoped_refptr<base::SequencedTaskRunner>& task_runner,
  	RpcStreamFactory::Callback callback);

  void CreateIpcBidirectionalStream(
    const std::string& host, 
  	const std::string& port, 
  	const std::string& name, 
  	const std::string& params, 
    const scoped_refptr<base::SequencedTaskRunner>& task_runner,
    RpcMethodType method_type,
  	RpcStreamFactory::Callback callback);
  
  void RpcStreamFinished(RpcStream* caller);

  bool HaveEncoder(const std::string& service, const std::string& method) const;
  RpcMessageEncoder* GetEncoder(const std::string& service, const std::string& method) const;
  void AddEncoder(RpcMessageEncoder* encoder);
  void RemoveEncoder(RpcMessageEncoder* encoder);
 
 private:
  
  RpcHttpStreamFactory http_stream_factory_;
  RpcIpcStreamFactory ipc_stream_factory_;

  std::vector<RpcMessageEncoder*> encoders_;

  //std::vector<std::unique_ptr<RpcStream>> callers_;

  DISALLOW_COPY_AND_ASSIGN(RpcNetworkSession);
};

}

#endif