// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_DEVICE_DEVICE_H_
#define MUMBA_HOST_DEVICE_DEVICE_H_

#include <memory>

#include "base/macros.h"
#include "base/uuid.h"
#include "core/host/serializable.h"
#include "core/host/data/resource.h"
#include "core/common/proto/objects.pb.h"

namespace host {

class Device : public Resource {
public:
  static char kClassName[];
  static std::unique_ptr<Device> Deserialize(net::IOBuffer* buffer, int size);

  ~Device() override;

  scoped_refptr<net::IOBufferWithSize> Serialize() const override;

  const base::UUID& id() const override {
    return id_;
  }

  const std::string& type() const;
  const std::string& name() const override;

  bool is_managed() const override {
    return managed_;
  }

  void set_managed(bool managed) {
    managed_ = managed;
  }
  
private:
  Device(protocol::Device device_proto);

  protocol::Device device_proto_;
  base::UUID id_;
  bool managed_;
  
  DISALLOW_COPY_AND_ASSIGN(Device);
};

}

#endif