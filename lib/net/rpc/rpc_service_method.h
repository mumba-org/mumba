// Copyright (c) 2017 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_RPC_RPC_SERVICE_METHODH_
#define NET_RPC_RPC_SERVICE_METHODH_

#include <string>

#include "base/uuid.h"
#include "base/strings/string_piece.h"
#include "net/base/net_export.h"
#include "net/rpc/rpc.h"
#include "third_party/protobuf/src/google/protobuf/descriptor.h"
#include "third_party/protobuf/src/google/protobuf/descriptor.pb.h"

namespace net {

class NET_EXPORT RpcServiceMethod {  
public:  
  RpcServiceMethod(
    const google::protobuf::MethodDescriptor* descriptor,
    net::RpcMethodType method_type);
  
  ~RpcServiceMethod();

  
  net::RpcMethodType method_type() const { 
    return method_type_;
  }
   
  base::StringPiece service() const {
    return service_;
  }
  
  base::StringPiece container() const {
    return container_;
  }
  
  base::StringPiece method() const {
    return method_;
  }

  const std::string& full_name() const;

  const std::string& full_method() const {
    return full_method_;
  }

  const google::protobuf::MethodDescriptor* descriptor() const {
    return descriptor_;
  }

  void Init();

private: 
  net::RpcMethodType method_type_;
  base::StringPiece service_;
  base::StringPiece container_;
  base::StringPiece method_;
  std::string full_method_;
  const google::protobuf::MethodDescriptor* descriptor_;
};

class NET_EXPORT RpcServiceHandler {
public:
  virtual ~RpcServiceHandler() {}
  virtual RpcServiceMethod* GetMethod(const std::string& method_name) const = 0;
};

}

#endif