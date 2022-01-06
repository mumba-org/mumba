// Copyright (c) 2011 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_RPC_RPC_REQUEST_INFO_H__
#define NET_RPC_RPC_REQUEST_INFO_H__

#include <string>
#include <map>

#include "net/base/net_export.h"
#include "net/base/privacy_mode.h"
#include "net/http/http_request_headers.h"
#include "net/socket/socket_tag.h"
#include "net/traffic_annotation/network_traffic_annotation.h"
#include "url/gurl.h"
#include "net/rpc/rpc.h"

namespace net {

struct NET_EXPORT RpcRequestInfo {
  RpcRequestInfo();
  RpcRequestInfo(const RpcRequestInfo& other);
  ~RpcRequestInfo();

  // The requested URL.
  GURL url;

  std::string fullname;

  std::string service;

  std::string method;

  std::string encoded_input_params;

  std::map<std::string, std::string> input_params;

  RpcMethodType method_type = RpcMethodType::kNORMAL;

  // Any extra request headers (including User-Agent).
  HttpRequestHeaders extra_headers;

  // Any load flags (see load_flags.h).
  int load_flags;

  // Tag applied to all sockets used to service request.
  SocketTag socket_tag;

  // Network traffic annotation received from URL request.
  net::MutableNetworkTrafficAnnotationTag traffic_annotation;
};

}  // namespace net

#endif  // NET_RPC_RPC_REQUEST_INFO_H__
