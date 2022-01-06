// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_RPC_RPC_MESSAGE_ENCODER_H_
#define NET_RPC_RPC_MESSAGE_ENCODER_H_

#include <map>
#include <string>

#include "net/base/net_export.h"

namespace google {
namespace protobuf {
class Descriptor;  
}  
}

namespace net {

class NET_EXPORT RpcMessageEncoder {
public:
  virtual ~RpcMessageEncoder() {}
  virtual bool CanEncode(const std::string& service_name, const std::string& method) = 0;
  virtual bool EncodeArguments(const std::string& service_name, const std::string& method, const std::map<std::string, std::string>& kvmap, std::string* out) = 0;
  virtual const google::protobuf::Descriptor* GetMethodInputType(const std::string& service_name, const std::string& method) = 0;
  virtual const google::protobuf::Descriptor* GetMethodOutputType(const std::string& service_name, const std::string& method) = 0;
};

}

#endif