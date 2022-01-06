// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_WORKSPACE_SERVICE_H_
#define MUMBA_HOST_WORKSPACE_SERVICE_H_

#include "base/macros.h"
#include "net/rpc/rpc.h"
#include "net/rpc/rpc_service_method.h"
#include "core/host/schema/schema.h"

namespace host {
class ServiceHandler;
class HostRpcService;

class ServiceHandler : public net::RpcServiceHandler {
public:
  ServiceHandler(HostRpcService* rpc_service, Schema* schema);
  ~ServiceHandler() override;

  const std::vector<net::RpcServiceMethod *>& methods() const {
    return methods_;
  }

  HostRpcService* rpc_service() const { 
    return rpc_service_; 
  }
  
  Schema* schema() const { 
    return schema_;
  }

  const google::protobuf::ServiceDescriptor* service_descriptor() const {
    return service_descriptor_;
  }

  const std::string& name() const { 
    return name_;
  }

  const std::string& container() const {
    return container_;
  }

  const std::string& fullname() const;

  net::RpcServiceMethod* GetMethod(const std::string& method_name) const override;

  net::RpcServiceMethod* AddMethod(const google::protobuf::MethodDescriptor* descriptor, net::RpcMethodType method_type);
  void AddMethod(net::RpcServiceMethod* method);
  void RemoveMethod(net::RpcServiceMethod* method);

private:

  HostRpcService* rpc_service_;
  
  Schema* schema_;

  std::vector<net::RpcServiceMethod *> methods_;

  const google::protobuf::ServiceDescriptor* service_descriptor_;
  const google::protobuf::ServiceDescriptor* plugin_service_descriptor_;

  std::string container_;

  std::string name_; 

  DISALLOW_COPY_AND_ASSIGN(ServiceHandler);
};

}

#endif