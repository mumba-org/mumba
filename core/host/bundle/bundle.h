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
  Bundle(const std::string& name, const base::FilePath& path, const std::string& executable_path, const std::string& resources_path);
  Bundle(protocol::Bundle bundle_proto);
  ~Bundle() override;

  const base::UUID& id() const {
    return id_;
  }

  const std::string& name() const;
  
  void set_name(const std::string& name);

  const base::FilePath& path() const {
    return path_;
  }

  void set_path(const base::FilePath& path);

  const std::string& executable_path() const;

  void set_executable_path(const std::string& executable_path);

  const std::string& resources_path() const;

  void set_resources_path(const std::string& resources_path);

  bool is_managed() const {
    return managed_;
  }

  void set_managed(bool managed) {
    managed_ = managed;
  }

  scoped_refptr<net::IOBufferWithSize> Serialize() const override;

private:

  base::UUID id_;
  protocol::Bundle bundle_proto_;
  base::FilePath path_;
  //base::FilePath executable_path_;
  
  bool managed_;

  DISALLOW_COPY_AND_ASSIGN(Bundle);
};

}

#endif