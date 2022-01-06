// Copyright 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_SHARE_SHARE_PEER_H_
#define MUMBA_HOST_SHARE_SHARE_PEER_H_

#include <string>

#include "base/macros.h"
#include "base/uuid.h"
#include "core/common/proto/objects.pb.h"
#include "core/host/serializable.h"

namespace host {
class ShareService;


class SharePeer : public Serializable {
public:
  static char kClassName[];
  static std::unique_ptr<SharePeer> Deserialize(net::IOBuffer* buffer, int size);

  SharePeer();
  SharePeer(protocol::SharePeer peer_proto);
  ~SharePeer() override;

  const base::UUID& id() const {
    return id_;
  }

  const std::string& ip_address() const {
    return ip_address_;
  }
  
  void set_ip_address(const std::string& ip_address);
  
  int port() const {
    return peer_proto_.port();
  }
  
  void set_port(int port) {
    peer_proto_.set_port(port);
  }

  protocol::ShareRemoteStatus status() const {
    return peer_proto_.status();
  }

  void set_status(protocol::ShareRemoteStatus status) {
    peer_proto_.set_status(status);
  }

  const std::vector<std::unique_ptr<ShareService>>& services() const {
    return services_;
  }

  std::vector<std::unique_ptr<ShareService>>& services() {
    return services_;
  }

  bool is_managed() const {
    return managed_;
  }

  void set_managed(bool managed) {
    managed_ = managed;
  }

  scoped_refptr<net::IOBufferWithSize> Serialize() const override;

private:
  
  base::UUID id_;

  protocol::SharePeer peer_proto_;

  std::vector<std::unique_ptr<ShareService>> services_;

  std::string ip_address_;

  bool managed_;
  
  DISALLOW_COPY_AND_ASSIGN(SharePeer);
};

}

#endif
