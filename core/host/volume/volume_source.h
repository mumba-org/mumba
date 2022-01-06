// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_CONTAINER_SOURCE_H_
#define MUMBA_HOST_CONTAINER_SOURCE_H_

#include "base/macros.h"
#include "base/uuid.h"
#include "core/host/serializable.h"
#include "core/common/proto/objects.pb.h"

namespace host {

class VolumeSource : public Serializable {
public:

  static std::unique_ptr<VolumeSource> Deserialize(net::IOBuffer* buffer, int size);

  VolumeSource(protocol::VolumeSource volume_proto);
  VolumeSource();
  ~VolumeSource() override;

  const base::UUID& id() const {
    return id_;
  }

  const std::string& name() const {
    return name_;
  }

  // managed = persisted on DB
  bool is_managed() const {
    return managed_;
  }

  void set_managed(bool managed) {
    managed_ = managed;
  }

  scoped_refptr<net::IOBufferWithSize> Serialize() const override;
 
private:

  base::UUID id_;

  std::string name_;

  protocol::VolumeSource proto_;

  bool managed_;
  
  DISALLOW_COPY_AND_ASSIGN(VolumeSource);
};

}

#endif