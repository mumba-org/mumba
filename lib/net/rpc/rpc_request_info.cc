// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/rpc/rpc_request_info.h"

namespace net {

RpcRequestInfo::RpcRequestInfo()
    : load_flags(0) {
}

RpcRequestInfo::RpcRequestInfo(const RpcRequestInfo& other) = default;

RpcRequestInfo::~RpcRequestInfo() = default;

}  // namespace net
