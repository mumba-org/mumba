// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/bundle/bundle.h"

#include "core/common/protocol/message_serialization.h"
#include "base/strings/string_util.h"

namespace host {

char Bundle::kClassName[] = "bundle";    

// static 
std::unique_ptr<Bundle> Bundle::Deserialize(net::IOBuffer* buffer, int size) {
  protocol::Bundle bundle_proto;
  protocol::CompoundBuffer cbuffer;
  cbuffer.Append(buffer, size);
  cbuffer.Lock();
  protocol::CompoundBufferInputStream stream(&cbuffer);
  
  if (!bundle_proto.ParseFromZeroCopyStream(&stream)) {
    return {};
  }
  return std::unique_ptr<Bundle>(new Bundle(std::move(bundle_proto)));
}

Bundle::Bundle(): managed_(false) {
  id_ = base::UUID::generate();
}

Bundle::Bundle(const std::string& name, const std::string& path, const std::string& executable_path, const std::string& resources_path):
  resource_package_(nullptr),
  application_package_(nullptr),
  managed_(false) {
  
  id_ = base::UUID::generate();
  bundle_proto_.set_uuid(id_.data, 16);
  bundle_proto_.set_name(name);
  bundle_proto_.set_path(path);
}

Bundle::Bundle(protocol::Bundle bundle_proto):
  resource_package_(nullptr),
  application_package_(nullptr),
  id_(reinterpret_cast<const uint8_t *>(bundle_proto.uuid().data())),
  bundle_proto_(std::move(bundle_proto)),
  managed_(false)  {
  
  for (int i = 0; i < bundle_proto_.packages_size(); i++) {
    protocol::BundlePackage proto = bundle_proto_.packages(i);
    std::unique_ptr<BundlePackage> package = std::make_unique<BundlePackage>(std::move(proto));
    if (package->type() == BundlePackageType::APPLICATION) {
      application_package_ = package.get();
    } else if (package->type() == BundlePackageType::RESOURCE) {
      resource_package_ = package.get();
    }
    packages_.push_back(std::move(package));
  }
}

Bundle::~Bundle() {
  
}

const std::string& Bundle::name() const {
  return bundle_proto_.name();
}

void Bundle::set_name(const std::string& name) {
  bundle_proto_.set_name(name);
}

const std::string& Bundle::application_path() {
  if (application_package_ == nullptr) {
    ResolveApplicationPackage();
  }
  return application_package_->path();
}

const std::string& Bundle::resources_path() {
  if (resource_package_ == nullptr) {
    ResolveResourcePackage();
  }
  return resource_package_->path();
}

const std::string& Bundle::path() const {
  return bundle_proto_.path();
}

void Bundle::set_path(const std::string& path) {
  bundle_proto_.set_path(path);
}

const std::string& Bundle::src_path() const {
  return bundle_proto_.src_path();
}

void Bundle::set_src_path(const std::string& path) {
  bundle_proto_.set_src_path(path);
}

void Bundle::AddPackage(std::unique_ptr<BundlePackage> package) {
  if (package->type() == BundlePackageType::APPLICATION) {
    application_package_ = package.get();
  } else if (package->type() == BundlePackageType::RESOURCE) {
    resource_package_ = package.get();
  }
  protocol::BundlePackage* cloned = bundle_proto_.mutable_packages()->Add();
  cloned->CopyFrom(package->package_proto_);
  packages_.push_back(std::move(package));
}

void Bundle::ResolvePackages() {
  for (auto it = packages_.begin(); it != packages_.end(); it++) {
    BundlePackage* package = it->get();
    if (package->type() == BundlePackageType::RESOURCE) {
      resource_package_ = package;
    } else if (package->type() == BundlePackageType::APPLICATION) {
      application_package_ = package;
    }
  }
}

void Bundle::ResolveResourcePackage() {
  for (auto it = packages_.begin(); it != packages_.end(); it++) {
    BundlePackage* package = it->get();
    if (package->type() == BundlePackageType::RESOURCE) {
      resource_package_ = package;
    }
  }
}

void Bundle::ResolveApplicationPackage() {
  for (auto it = packages_.begin(); it != packages_.end(); it++) {
    BundlePackage* package = it->get();
    if (package->type() == BundlePackageType::APPLICATION) {
      application_package_ = package;
    }
  }
}

scoped_refptr<net::IOBufferWithSize> Bundle::Serialize() const {
  return protocol::SerializeMessage(bundle_proto_);
}

}
