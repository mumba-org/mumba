// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_BUNDLE_BUNDLE_PACKAGE_H_
#define MUMBA_HOST_BUNDLE_BUNDLE_PACKAGE_H_

#include <memory>

#include "base/macros.h"
#include "base/uuid.h"
#include "base/strings/string_piece.h"
#include "core/host/serializable.h"
#include "core/common/proto/objects.pb.h"
#include "core/host/bundle/bundle_info.h"

namespace host {
class Bundle;

class BundlePackage : public Serializable {
public:
  static char kClassName[];
  static std::unique_ptr<BundlePackage> Deserialize(net::IOBuffer* buffer, int size);

  BundlePackage(const std::string& name, 
                const std::string& path, 
                const std::string& src_path,
                BundlePlatform platform,
                BundleArchitecture arch,
                BundlePackageType type,
                uint64_t size);

  BundlePackage(protocol::BundlePackage package_proto);

  ~BundlePackage();

  const base::UUID& id() const {
    return id_;
  }

  const std::string& name() const;
  void set_name(const std::string& name);

  const std::string& path() const;
  void set_path(const std::string& path);

  const std::string& src_path() const;
  void set_src_path(const std::string& path);

  BundlePlatform platform() const;
  void set_platform(BundlePlatform platform);

  BundleArchitecture arch() const;
  void set_arch(BundleArchitecture arch);

  BundlePackageType type() const;
  void set_type(BundlePackageType type);

  uint64_t size() const;
  void set_size(uint64_t size);

  bool is_managed() const {
    return managed_;
  }

  void set_managed(bool managed) {
    managed_ = managed;
  }

  scoped_refptr<net::IOBufferWithSize> Serialize() const override;
  
private:
  friend class Bundle;

  base::UUID id_;
  protocol::BundlePackage package_proto_;
  
  bool managed_;

  DISALLOW_COPY_AND_ASSIGN(BundlePackage);
};

}

#endif