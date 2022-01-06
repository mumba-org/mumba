// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/domain/storage/mount/mount_dispatcher.h"

#include "base/single_thread_task_runner.h"

namespace domain {

MountDispatcher::MountDispatcher(): binding_(this) {

}

MountDispatcher::~MountDispatcher() {

}

void MountDispatcher::Bind(common::mojom::MountManagerAssociatedRequest request) {
  binding_.Bind(std::move(request));
}

void MountDispatcher::Mount(const std::string& namespace_name, const std::string& target_path, MountCallback callback) {
  common::mojom::DomainStatus status = common::mojom::DomainStatus::kOk;
  
  std::move(callback).Run(std::move(status));
}

void MountDispatcher::Umount(const std::string& target_path, UmountCallback callback) {

}

void MountDispatcher::GetMountDescription(GetMountDescriptionCallback callback) {

}

}