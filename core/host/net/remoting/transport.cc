// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/net/transport.h"

#include "base/logging.h"

namespace host {

// static
std::string TransportRoute::GetTypeString(RouteType type) {
  switch (type) {
    case DIRECT:
      return "direct";
    case STUN:
      return "stun";
    case RELAY:
      return "relay";
  }
  NOTREACHED();
  return std::string();
}

TransportRoute::TransportRoute() : type(DIRECT) {}
TransportRoute::~TransportRoute() = default;

}
