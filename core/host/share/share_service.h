// Copyright 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_SHARE_SHARE_SERVICE_H_
#define MUMBA_HOST_SHARE_SHARE_SERVICE_H_

#include <string>

#include "base/macros.h"
#include "base/uuid.h"
#include "core/common/proto/objects.pb.h"
#include "core/host/serializable.h"

namespace host {

class ShareService : public Serializable {
public:
  static char kClassName[];
  static std::unique_ptr<ShareService> Deserialize(net::IOBuffer* buffer, int size);

  ShareService();
  ShareService(protocol::ShareService service_proto);
  ~ShareService();

  const base::UUID& id() const {
    return id_;
  }

  const std::string& name() const {
    return service_proto_.name();    
  }

  void set_name(const std::string& name) {
    service_proto_.set_name(name); 
  }

  const std::string& full_name() const {
    return service_proto_.full_name();
  }

  void set_full_name(const std::string& full_name) {
    service_proto_.set_full_name(full_name); 
  }

  const std::string& vendor() const {
    return service_proto_.vendor();
  }

  void set_vendor(const std::string& vendor) {
    service_proto_.set_vendor(vendor);  
  }
  
  const std::string& description() const {
    return service_proto_.description();
  }

  void set_description(const std::string& description) {
    service_proto_.set_description(description); 
  }
  
  const std::string& mime_type() const {
    return service_proto_.mime_type();
  }

  void set_mime_type(const std::string& mime_type) {
    service_proto_.set_mime_type(mime_type); 
  }
  
  const std::string& version() const {
    return service_proto_.version();
  }

  void set_version(const std::string& version) {
    service_proto_.set_version(version); 
  }
  
  protocol::ShareTransport transport() {
    return service_proto_.transport();
  }

  void set_transport(protocol::ShareTransport transport);

  const base::UUID& peer_uuid() const {
    return peer_uuid_;
  }

  void set_peer_uuid(const base::UUID& peer_uuid) {
    peer_uuid_ = peer_uuid; 
  }

  const std::string& ip_address() const {
    return ip_address_;
  }

  void set_ip_address(const std::string& ip_address);
  
  int port() const {
    return service_proto_.port();
  }

  void set_port(int port) {
    service_proto_.set_port(port); 
  }

  const std::string& options() const {
    return service_proto_.options();
  }

  void set_options(const std::string& options) {
    service_proto_.set_options(options); 
  }

  protocol::ShareRemoteStatus status() const {
    return service_proto_.status();
  }

  void set_status(protocol::ShareRemoteStatus status) {
    service_proto_.set_status(status);
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

  protocol::ShareService service_proto_;

  base::UUID peer_uuid_;

  std::string ip_address_;

  bool managed_;
  
  DISALLOW_COPY_AND_ASSIGN(ShareService);
};

}

#endif
