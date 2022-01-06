// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/bundle/bundle_package.h"

namespace host {

char BundlePackage::kClassName[] = "bundle-package";

// static 
std::unique_ptr<BundlePackage> BundlePackage::Deserialize(net::IOBuffer* buffer, int size) {
  protocol::BundlePackage bundle_proto;
  protocol::CompoundBuffer cbuffer;
  cbuffer.Append(buffer, size);
  cbuffer.Lock();
  protocol::CompoundBufferInputStream stream(&cbuffer);
  
  if (!bundle_proto.ParseFromZeroCopyStream(&stream)) {
    return {};
  }
  return std::unique_ptr<BundlePackage>(new BundlePackage(std::move(bundle_proto)));
}

BundlePackage::BundlePackage() {
  
}

BundlePackage::~BundlePackage() {
  
}

const std::string& BundlePackage::name() const {
  return package_proto_.name();
}

void BundlePackage::set_name(const std::string& name) {
  package_proto_.set_name(name);
}

const std::string& BundlePackage::path() const {
  return package_proto_.path();
}

void BundlePackage::set_path(const std::string& path) {
  package_proto_.set_path(path);
}

BundlePlatform BundlePackage::platform() const {
  return static_cast<protocol::BundlePlatform>(package_proto_.platform());
}

void BundlePackage::set_platform(BundlePlatform platform) {
  package_proto_.set_platform(platform);
}

BundleArchitecture BundlePackage::arch() const {
  return static_cast<protocol::BundlePlatform>(package_proto_.arch());
}

void BundlePackage::set_arch(BundleArchitecture arch) {
  package_proto_.set_arch(arch);
}

BundlePackageType BundlePackage::type() const {
  return static_cast<protocol::BundlePlatform>(package_proto_.type());
}

void BundlePackage::set_type(BundlePackageType type) {
  package_proto_.set_type(type);
}

scoped_refptr<net::IOBufferWithSize> BundlePackage::Serialize() const {
  return protocol::SerializeMessage(package_proto_);
}

}