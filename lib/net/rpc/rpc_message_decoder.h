// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_RPC_RPC_MESSAGE_DECODER_H_
#define NET_RPC_RPC_MESSAGE_DECODER_H_

#include "net/base/net_export.h"

namespace net {

class NET_EXPORT RpcMessageDecoder {
public:
  virtual ~RpcMessageDecoder() {}
};

}

#endif