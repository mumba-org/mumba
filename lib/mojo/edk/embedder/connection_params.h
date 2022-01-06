// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MOJO_EDK_EMBEDDER_CONNECTION_PARAMS_H_
#define MOJO_EDK_EMBEDDER_CONNECTION_PARAMS_H_

#include "base/macros.h"
#include "build/build_config.h"
#include "mojo/public/cpp/platform/scoped_platform_handle.h"
#include "mojo/edk/embedder/transport_protocol.h"
#include "mojo/edk/system/system_impl_export.h"
#include "mojo/public/cpp/platform/platform_channel_endpoint.h"
#include "mojo/public/cpp/platform/platform_channel_server_endpoint.h"

namespace mojo {
namespace edk {

// A set of parameters used when establishing a connection to another process.
class MOJO_SYSTEM_IMPL_EXPORT ConnectionParams {
 public:
  enum Type {
   kOLD,
   kNEW,
  };

  ConnectionParams();
  explicit ConnectionParams(PlatformChannelEndpoint endpoint);
  explicit ConnectionParams(PlatformChannelServerEndpoint server_endpoint);
  
  // Configures an OS pipe-based connection of type |type| to the remote process
  // using the given transport |protocol|.
  ConnectionParams(TransportProtocol protocol, ScopedPlatformHandle channel);

  ConnectionParams(ConnectionParams&& params);
  ConnectionParams& operator=(ConnectionParams&& params);

  TransportProtocol protocol() const { return protocol_; }

  ScopedPlatformHandle TakeChannelHandle();

  const PlatformChannelEndpoint& endpoint() const { return endpoint_; }
  const PlatformChannelServerEndpoint& server_endpoint() const {
    return server_endpoint_;
  }

  PlatformChannelEndpoint TakeEndpoint() { 
    DCHECK(type_ == kNEW);
    return std::move(endpoint_); 
  }

  PlatformChannelServerEndpoint TakeServerEndpoint() {
    DCHECK(type_ == kNEW);
    return std::move(server_endpoint_);
  }

  Type type() const { return type_; }

 private:
  TransportProtocol protocol_;
  ScopedPlatformHandle channel_;

  PlatformChannelEndpoint endpoint_;
  PlatformChannelServerEndpoint server_endpoint_;

  Type type_;

  DISALLOW_COPY_AND_ASSIGN(ConnectionParams);
};

}  // namespace edk
}  // namespace mojo

#endif  // MOJO_EDK_EMBEDDER_CONNECTION_PARAMS_H_
