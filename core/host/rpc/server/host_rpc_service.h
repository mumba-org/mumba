// Copyright (c) 2017 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_RPC_HOST_RPC_SERVICE_H_
#define MUMBA_HOST_RPC_HOST_RPC_SERVICE_H_

#include <unordered_map>
#include <memory>

#include "base/macros.h"
#include "base/callback.h"
#include "base/memory/weak_ptr.h"
#include "base/threading/thread.h"
#include "base/synchronization/lock.h"
#include "base/strings/string_number_conversions.h"
#include "base/atomic_sequence_num.h"
#include "base/memory/ref_counted.h"
#include "base/synchronization/waitable_event.h"
#include "net/rpc/rpc.h"
#include "core/host/schema/schema.h"
#include "net/rpc/server/rpc_handler.h"
#include "net/rpc/server/rpc_service.h"
#include "net/rpc/rpc_message_encoder.h"

namespace host {

class HostRpcService : public net::RpcService {
public:
  static char kClassName[];
  HostRpcService(
    const std::string& container,
    const std::string& name,
    const std::string& host,
    int port,
    net::RpcTransportType type,
    const scoped_refptr<base::SingleThreadTaskRunner>& delegate_thread,
    const scoped_refptr<base::SingleThreadTaskRunner>& context_thread,
    const scoped_refptr<base::SingleThreadTaskRunner>& io_thread,
    Schema* schema,
    std::unique_ptr<net::RpcHandler> rpc_handler);

  ~HostRpcService() override;

  const google::protobuf::ServiceDescriptor* plugin_service_descriptor() const {
    return plugin_service_descriptor_;
  }

  // return schema associated with this service
  Schema* schema() const {
    return schema_;
  }

  std::unique_ptr<net::RpcMessageEncoder> BuildEncoder();

private:
  
  void Init();
  
  Schema* schema_;
  const google::protobuf::ServiceDescriptor* plugin_service_descriptor_;

  DISALLOW_COPY_AND_ASSIGN(HostRpcService);
};

}

#endif