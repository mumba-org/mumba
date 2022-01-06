// Copyright (c) 2017 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_RPC_RPC_STATE_H_
#define NET_RPC_RPC_STATE_H_

#include "net/base/net_export.h"

namespace net {

enum NET_EXPORT RpcState {
  kCALL_NOOP = -1,
  kCALL_BEGIN = 0,
  kCALL_UNARY_READ = 1,
  kCALL_STREAM_READ = 2,
  kCALL_STREAM_SEND_INIT_METADATA = 3,
  kCALL_STREAM_WRITE = 4,
  kCALL_END = 5
};

}

#endif