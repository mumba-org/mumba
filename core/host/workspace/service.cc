// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/workspace/service.h"

#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "base/strings/string_split.h"
#include "core/host/rpc/server/host_rpc_service.h"

namespace host {

namespace {

net::RpcMethodType GetMethodType(const google::protobuf::MethodDescriptor* method) {
  if (method->client_streaming() && method->server_streaming()) {
    return net::RpcMethodType::kBIDI_STREAM;
  } else if (method->client_streaming() && !method->server_streaming()) {
    return net::RpcMethodType::kCLIENT_STREAM;
  } else if (!method->client_streaming() && method->server_streaming()) {
    return net::RpcMethodType::kSERVER_STREAM;
  }

  return net::RpcMethodType::kNORMAL;
}

// std::string GetMethodTypeName(net::RpcMethodType type) {
//   switch (type) {
//     case net::RpcMethodType::kNORMAL:
//      return "normal";
//     case net::RpcMethodType::kBIDI_STREAM:
//      return "bi-directional stream";
//     case net::RpcMethodType::kCLIENT_STREAM:
//      return "client stream";
//     case net::RpcMethodType::kSERVER_STREAM:
//      return "server stream"; 
//   }
// }

}


ServiceHandler::ServiceHandler(HostRpcService* rpc_service, Schema* schema):
  rpc_service_(rpc_service),
  schema_(schema) {

  schema_->AddServiceHandler(this);

  service_descriptor_ = rpc_service_->service_descriptor();
  plugin_service_descriptor_ = rpc_service_->plugin_service_descriptor();
  name_ = rpc_service_->name();
  container_ = rpc_service_->container();
  
  for (int x = 0; x < service_descriptor_->method_count(); x++) {
    const google::protobuf::MethodDescriptor* method_descriptor = service_descriptor_->method(x);
    net::RpcMethodType type = GetMethodType(method_descriptor);
    AddMethod(method_descriptor, type);
  }

  if (plugin_service_descriptor_) {
    for (int x = 0; x < plugin_service_descriptor_->method_count(); x++) {
      const google::protobuf::MethodDescriptor* method_descriptor = plugin_service_descriptor_->method(x);
      net::RpcMethodType type = GetMethodType(method_descriptor);
      AddMethod(method_descriptor, type);
    }
  }

  rpc_service_->BindHandler(this);
}

ServiceHandler::~ServiceHandler() {
  for (auto it = methods_.begin(); it != methods_.end(); ++it) {
    delete *it;
  }
  methods_.clear();
  // if (schema_) {
  //   schema_->RemoveServiceHandler(this);
  // }
}

const std::string& ServiceHandler::fullname() const {
  return service_descriptor_->full_name();
}

net::RpcServiceMethod* ServiceHandler::GetMethod(const std::string& method_name) const {
  //DLOG(INFO) << "ServiceHandler::GetMethod"; 
  for (auto it = methods_.begin(); it != methods_.end(); it++) {
    //DLOG(INFO) << " comparing '" << (*it)->full_method() << "' and '" << method_name << "'";
    if ((*it)->full_method() == method_name) {
      return *it;
    }
  }
  return nullptr;
}

void ServiceHandler::AddMethod(net::RpcServiceMethod* method) {
  methods_.push_back(method);
}

net::RpcServiceMethod* ServiceHandler::AddMethod(const google::protobuf::MethodDescriptor* descriptor, net::RpcMethodType method_type) {
  net::RpcServiceMethod* method = new net::RpcServiceMethod(descriptor, method_type);
  //DLOG(INFO) << " adding method " << method->full_method();
  AddMethod(method);
  return method;
}

void ServiceHandler::RemoveMethod(net::RpcServiceMethod* method) {
  for (auto it = methods_.begin(); it != methods_.end(); ++it) {
    if (*it == method) {
      delete *it;
      methods_.erase(it);
      return;
    }
  }
}

}