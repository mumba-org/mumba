// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/net/pairing_registry_delegate.h"

#include "base/task_runner.h"

namespace host {

std::unique_ptr<PairingRegistry::Delegate> CreatePairingRegistryDelegate() {
  return nullptr;
}

}  // namespace remoting
