// Copyright 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_SHARE_SHARE_TRANSPORT_H_
#define MUMBA_HOST_SHARE_SHARE_TRANSPORT_H_

#include <string>

#include "base/macros.h"
#include "base/uuid.h"
#include "core/common/proto/objects.pb.h"
#include "core/host/serializable.h"
#include "core/common/protocol/message_serialization.h"

namespace host {


struct ShareTransport : public Serializable {
    
  static std::unique_ptr<ShareTransport> Deserialize(net::IOBuffer* buffer, int size);

  ShareTransport() {}
  ShareTransport(protocol::ShareTransport proto): transport_proto(std::move(proto)) {}
  
  protocol::ShareTransportType type() const {
    return transport_proto.type();
  }

  void set_type(protocol::ShareTransportType type) {
    transport_proto.set_type(type);
  }

  const std::string& name() const {
    return transport_proto.name();
  }

  void set_name(const std::string& name) {
    transport_proto.set_name(name);
  }

  const std::string& vendor() const {
    return transport_proto.vendor();
  }

  void set_vendor(const std::string& vendor) {
    transport_proto.set_vendor(vendor); 
  }
  const std::string& version() const {
    return transport_proto.version();
  }

  void set_version(const std::string& version) {
    transport_proto.set_version(version);
  }

  const std::string& options() const {
    return transport_proto.options();
  }

  void set_options(const std::string& options) {
    transport_proto.set_options(options);
  }
  
  scoped_refptr<net::IOBufferWithSize> Serialize() const override {
    return protocol::SerializeMessage(transport_proto);
  }


  protocol::ShareTransport transport_proto;
};

}

#endif
