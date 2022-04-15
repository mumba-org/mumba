// Copyright (c) 2022 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_DATA_RESOURCE_H_
#define MUMBA_HOST_DATA_RESOURCE_H_

#include <string>

#include "base/macros.h"
#include "base/uuid.h"
#include "core/host/serializable.h"
#include "third_party/protobuf/src/google/protobuf/descriptor.h"
#include "third_party/protobuf/src/google/protobuf/descriptor.pb.h"

namespace host {

class Resource : public Serializable {
public:
  virtual ~Resource() = default;
  // every resource have a unique identifier
  virtual const base::UUID& id() const = 0;
  // should also have some name
  virtual const std::string& name() const = 0;
  // if its managed/persisted by a database or there's just a on-heap representation
  virtual bool is_managed() const = 0;
  
};

/*
 * Should be implemented by managers or models of items/resources that should be used
 * over the system table virtual tables mechanism
 *
 * This is the adapter interface that the system table and cursor will use to have access to the resources
 */
class ResourceManager {
public:
  virtual ~ResourceManager() = default;
  virtual bool HaveResource(const base::UUID& id) = 0;
  virtual bool HaveResource(const std::string& name) = 0;
  virtual Resource* GetResource(const base::UUID& id) = 0;
  virtual Resource* GetResource(const std::string& name) = 0;
  // Message descriptor of the resource being managed by this manager
  virtual const google::protobuf::Descriptor* resource_descriptor() = 0;
  virtual std::string resource_classname() const = 0;
};

}

#endif