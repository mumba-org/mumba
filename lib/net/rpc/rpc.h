// Copyright (c) 2017 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_RPC_RPC_H_
#define NET_RPC_RPC_H_

#include <string>

#include "base/uuid.h"
#include "base/strings/string_piece.h"
#include "net/base/net_export.h"

namespace net {

enum class NET_EXPORT RpcMethodType : int {
  kNORMAL = 0,
  kCLIENT_STREAM = 1,
  kSERVER_STREAM = 2,
  kBIDI_STREAM = 3
};  

enum class NET_EXPORT RpcTransportType : int {
  kIPC = 0,
  kHTTP = 1
};

struct NET_EXPORT RpcDescriptor {
  base::UUID uuid;
  std::string full_name;
  std::string name;
  RpcMethodType method_type;
  RpcTransportType transport_type;
};

}

#endif