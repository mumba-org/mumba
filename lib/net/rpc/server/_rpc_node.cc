// Copyright (c) 2017 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/rpc/server/rpc_node.h"

#include "base/stl_util.h"

namespace net {

namespace {

URL FormatAddress(RpcTransportType type, const std::string& addr) {
  bool has_scheme = (addr.find("://") != std::string::npos);
  
  if (has_scheme)
    return URL(addr);

  std::string scheme = (type == RpcTransportType::kIPC ? "unix://" : "http://");
  return URL(scheme + addr);
}

}

RpcMethod::RpcMethod(RpcTransportType transport_type, common::RpcMethodType method_type, const std::string& host, const std::string& name, int port):
    transport_type(transport_type), 
    method_type(method_type), 
    host(host),
    port(port),
    name(name),  
    tag(nullptr) {}

RpcMethod::~RpcMethod() {}

RpcNode::RpcNode(const base::UUID& uuid, const std::string& host, int port, const std::string& ns, RpcTransportType transport_type): 
  uuid_(uuid),
  host_(host),
  port_(port),
  ns_(ns),
  transport_type_(transport_type) {

}

RpcNode::~RpcNode() {
  //STLDeleteAppHostPointers(methods_.begin(), methods_.end());
  for (auto it = methods_.begin(); it != methods_.end(); it++) {
    delete *it;
  }
  methods_.clear();
}

RpcMethod* RpcNode::GetMethod(const std::string& addr) const {
  URL full_address = FormatAddress(transport_type_, addr);

  for (auto it = methods_.begin(); it != methods_.end(); it++) {
    if ((*it)->url() == full_address) {
      return *it;
    }
  }
  return nullptr;
}

RpcMethod* RpcNode::AddMethod(const std::string& name, common::RpcMethodType method_type) {
  RpcMethod* m = new RpcMethod(transport_type_, method_type, host_, name, port_);
  methods_.push_back(m);
  return m;
}

bool RpcNode::FillDescriptor(const std::string& method_addr, RpcDescriptor* descr) const {
  RpcMethod* method = GetMethod(method_addr);
  
  if (!method) {
    return false;
  }

  descr->uuid = uuid();
  descr->ns = ns();
  descr->method_type = method->method_type;
  descr->transport_type = transport_type();
  descr->url = method->url();

  return true;
}

bool RpcNode::FillDescriptor(RpcMethod* method, RpcDescriptor* descr) const {
  descr->uuid = uuid();
  descr->ns = ns();
  descr->method_type = method->method_type;
  descr->transport_type = transport_type();
  descr->url = method->url();

  return true;
}

void RpcNode::AddObserver(RpcNode::Observer* obs) {
  
}

void RpcNode::RemoveObserver(RpcNode::Observer* obs) {

}

}