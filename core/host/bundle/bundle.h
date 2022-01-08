// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_BUNDLE_BUNDLE_H_
#define MUMBA_HOST_BUNDLE_BUNDLE_H_

#include <memory>

#include "base/macros.h"
#include "base/uuid.h"
#include "base/strings/string_piece.h"
#include "base/synchronization/lock.h"
#include "core/host/serializable.h"
#include "core/common/proto/objects.pb.h"
#include "core/host/bundle/bundle_info.h"
#include "core/host/bundle/bundle_package.h"
#include "core/shared/common/mojom/bundle.mojom.h"

namespace host {

/*
 *
 * Get the whole bundle manifest info from msix
 * and populate this with information
 *
 * For instance: how many package this bundle have
 * and how they look like? what their own manifest?
 *
 * we need a BundlePackage type where a bundle will
 * have one or more of them
 *
 * we need them ALL serialized in the database after they are installed
 */

class Bundle : public Serializable {
public:
  static char kClassName[];
  static std::unique_ptr<Bundle> Deserialize(net::IOBuffer* buffer, int size);

  // FIXME: We need to have BundlePackage objects, each one with their own directory
  //        and add them to the bundle.  
  Bundle(const std::string& name, const std::string& path, const std::string& executable_path, const std::string& resources_path);
  Bundle();
  Bundle(protocol::Bundle bundle_proto);
  ~Bundle() override;

  const base::UUID& id() const {
    return id_;
  }

  const std::string& name() const;
  void set_name(const std::string& name);

  const std::string& path() const;
  void set_path(const std::string& path);

  const std::string& src_path() const;
  void set_src_path(const std::string& path);

  const std::string& application_path();
  const std::string& resources_path();

  bool is_managed() const {
    return managed_;
  }

  void set_managed(bool managed) {
    managed_ = managed;
  }

  const std::vector<std::unique_ptr<BundlePackage>>& packages() const {
    return packages_;
  }

  void AddPackage(std::unique_ptr<BundlePackage> package);

  scoped_refptr<net::IOBufferWithSize> Serialize() const override;

private:

  void ResolvePackages();
  void ResolveResourcePackage();
  void ResolveApplicationPackage();

  BundlePackage* resource_package_;
  BundlePackage* application_package_;
  base::UUID id_;
  protocol::Bundle bundle_proto_;
  // fixme: should be added to the proto
  std::vector<std::unique_ptr<BundlePackage>> packages_;
  
  bool managed_;

  DISALLOW_COPY_AND_ASSIGN(Bundle);
};

}

#endif