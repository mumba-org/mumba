// Copyright 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.


#include "core/shared/common/p2p_socket_type.h"

namespace common {

P2PSocketOptions::P2PSocketOptions() {}

P2PSocketOptions::P2PSocketOptions(const net::IPEndPoint& local_address,
                  const common::P2PPortRange& port_range,
                  const common::P2PHostAndIPEndPoint& remote_address):
                    local_address(local_address),
                    port_range(port_range),
                    remote_address(remote_address) {

}

P2PSocketOptions::P2PSocketOptions(const net::IPEndPoint& local_address,
                  const common::P2PPortRange& port_range,
                  const common::P2PHostAndIPEndPoint& remote_address,
                  const std::string& package,
                  const std::string& name):
                    local_address(local_address),
                    port_range(port_range),
                    remote_address(remote_address),
                    package(package),
                    name(name) {}

P2PSocketOptions::~P2PSocketOptions() {

}

}