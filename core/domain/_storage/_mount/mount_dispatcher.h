// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_MOUNT_DISPATCHER_H_
#define MUMBA_DOMAIN_MOUNT_DISPATCHER_H_

#include "base/macros.h"
#include "core/shared/common/mojom/mount.mojom.h"
#include "mojo/public/cpp/bindings/binding.h"
#include "mojo/public/cpp/bindings/associated_binding.h"

namespace domain {

class MountDispatcher : public common::mojom::MountManager {
public:
  MountDispatcher();
  ~MountDispatcher() override;

  void Bind(common::mojom::MountManagerAssociatedRequest request);

  void Mount(const std::string& namespace_name, const std::string& target_path, MountCallback callback) override;
  void Umount(const std::string& target_path, UmountCallback callback) override;
  void GetMountDescription(GetMountDescriptionCallback callback) override;

private:
  
  mojo::AssociatedBinding<common::mojom::MountManager> binding_;

  DISALLOW_COPY_AND_ASSIGN(MountDispatcher);
};

}


#endif