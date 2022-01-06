// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_NET_ICE_CONFIG_REQUEST_H_
#define MUMBA_HOST_NET_ICE_CONFIG_REQUEST_H_

#include "base/callback_forward.h"

namespace host {

struct IceConfig;

// Abstract interface used to fetch STUN and TURN configuration.
class IceConfigRequest {
 public:
  // Callback to receive results of the request. |ice_config| is null if the
  // request has failed.
  typedef base::Callback<void(const IceConfig& ice_config)> OnIceConfigCallback;

  virtual ~IceConfigRequest() {}

  // Sends the request and calls the |callback| with the results.
  virtual void Send(const OnIceConfigCallback& callback) = 0;
};

}

#endif  // REMOTING_PROTOCOL_ICE_CONFIG_REQUEST_H_
