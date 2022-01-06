// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/background_sync/background_sync_controller_factory.h"

#include "core/host/background_sync/background_sync_controller_impl.h"
#include "core/host/application/domain.h"

namespace host {

// static
BackgroundSyncControllerImpl* BackgroundSyncControllerFactory::GetForDomain(
    Domain* domain) {
  return GetInstance()->GetBackgroundSyncController(domain);
}

// static
BackgroundSyncControllerFactory*
BackgroundSyncControllerFactory::GetInstance() {
  return base::Singleton<BackgroundSyncControllerFactory>::get();
}

BackgroundSyncControllerFactory::BackgroundSyncControllerFactory() {}
BackgroundSyncControllerFactory::~BackgroundSyncControllerFactory() {}

BackgroundSyncControllerImpl* BackgroundSyncControllerFactory::GetBackgroundSyncController(Domain* domain) {
  if (!controller_) {
    controller_ = std::make_unique<BackgroundSyncControllerImpl>(domain);
  }
  return controller_.get();
}

}