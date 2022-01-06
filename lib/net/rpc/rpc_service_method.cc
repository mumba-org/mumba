// Copyright (c) 2017 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/rpc/rpc_service_method.h"

#include "base/strings/string_split.h"

namespace net {

RpcServiceMethod::RpcServiceMethod(
  const google::protobuf::MethodDescriptor* descriptor,
  net::RpcMethodType method_type):
    method_type_(method_type), 
    descriptor_(descriptor) { 
  Init();
}

RpcServiceMethod::~RpcServiceMethod() {}

const std::string& RpcServiceMethod::full_name() const {
  return descriptor_->full_name();
}

void RpcServiceMethod::Init() {
  // parse from full_name 'container.Service.Method' to method_name '/container.Service/Method'
  std::vector<base::StringPiece> tokens = base::SplitStringPieceUsingSubstr(
    full_name(),
    ".",
    base::TRIM_WHITESPACE,
    base::SPLIT_WANT_NONEMPTY);
 
  if (tokens.size() != 3) {
    LOG(ERROR) << "malformed rpc method name '" << full_name() << "' expecting 'container.service.method'. parse failed.";
    return;
  }
  
  container_ = tokens[0];
  service_ = tokens[1];
  method_ = tokens[2];
  
  full_method_.append("/").
              append(container_.data(), container_.size()).
              append(".").
              append(service_.data(), service_.size()).
              append("/").
              append(method_.data(), method_.size());

}

}