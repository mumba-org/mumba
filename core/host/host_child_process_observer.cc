// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/host_child_process_observer.h"

#include "core/host/host_child_process_host_impl.h"

namespace host {

// static
void HostChildProcessObserver::Add(HostChildProcessObserver* observer) {
  HostChildProcessHostImpl::AddObserver(observer);
}

// static
void HostChildProcessObserver::Remove(
    HostChildProcessObserver* observer) {
  HostChildProcessHostImpl::RemoveObserver(observer);
}

}  // namespace host
