// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/bundle/bundle_package.h"

#include "core/common/protocol/message_serialization.h"
#include "base/strings/string_util.h"

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

BundlePackage::BundlePackage(const std::string& name, 
                             const std::string& path, 
                             BundlePlatform platform,
                             BundleArchitecture arch,
                             BundlePackageType type,
                             uint64_t size):
                            size_(size),
                            managed_(false) {
  id_ = base::UUID::generate();
  package_proto_.set_uuid(id_.data, 16);
  package_proto_.set_name(name);
  package_proto_.set_path(path);
  package_proto_.set_platform(static_cast<protocol::BundlePlatform>(platform));
  package_proto_.set_arch(static_cast<protocol::BundleArchitecture>(arch));
  package_proto_.set_type(static_cast<protocol::BundlePackageType>(type));
}

BundlePackage::BundlePackage(protocol::BundlePackage package_proto): 
  id_(reinterpret_cast<const uint8_t *>(package_proto.uuid().data())),
  package_proto_(std::move(package_proto)),
  size_(0),
  managed_(false) {

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
  return static_cast<BundlePlatform>(package_proto_.platform());
}

void BundlePackage::set_platform(BundlePlatform platform) {
  package_proto_.set_platform(static_cast<protocol::BundlePlatform>(platform));
}

BundleArchitecture BundlePackage::arch() const {
  return static_cast<BundleArchitecture>(package_proto_.arch());
}

void BundlePackage::set_arch(BundleArchitecture arch) {
  package_proto_.set_arch(static_cast<protocol::BundleArchitecture>(arch));
}

BundlePackageType BundlePackage::type() const {
  return static_cast<BundlePackageType>(package_proto_.type());
}

void BundlePackage::set_type(BundlePackageType type) {
  package_proto_.set_type(static_cast<protocol::BundlePackageType>(type));
}

uint64_t BundlePackage::size() const {
  return size_;
}

void BundlePackage::set_size(uint64_t size) {
  size_ = size;
}

scoped_refptr<net::IOBufferWithSize> BundlePackage::Serialize() const {
  return protocol::SerializeMessage(package_proto_);
}

}