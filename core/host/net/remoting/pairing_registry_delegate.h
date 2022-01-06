// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_NET_PAIRING_REGISTRY_DELEGATE_H_
#define MUMBA_HOST_NET_PAIRING_REGISTRY_DELEGATE_H_

#include <memory>

#include "base/memory/ref_counted.h"
#include "core/host/net/pairing_registry.h"

namespace base {
class SingleThreadTaskRunner;
}  // namespace base

namespace host {
// Returns a platform-specific pairing registry delegate that will save to
// permanent storage. Returns nullptr on platforms that don't support pairing.
std::unique_ptr<PairingRegistry::Delegate> CreatePairingRegistryDelegate();

// Convenience function which returns a new PairingRegistry, using the delegate
// returned by CreatePairingRegistryDelegate(). The passed |task_runner| is used
// to run the delegate's methods asynchronously.
scoped_refptr<PairingRegistry> CreatePairingRegistry(
    scoped_refptr<base::SingleThreadTaskRunner> task_runner);

}  // namespace remoting

#endif  // REMOTING_HOST_PAIRING_REGISTRY_DELEGATE_H_
