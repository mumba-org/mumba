// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_NET_SSL_CONFIG_SERVICE_MANAGER_H_
#define MUMBA_HOST_NET_SSL_CONFIG_SERVICE_MANAGER_H_

#include "base/memory/ref_counted.h"

namespace base {
class SingleThreadTaskRunner;
}

namespace net {
class SSLConfigService;
}  // namespace net

namespace host {

// An interface for creating SSLConfigService objects.
class SSLConfigServiceManager {
 public:
  // Create an instance of the SSLConfigServiceManager. The lifetime of the
  // PrefService objects must be longer than that of the manager. Get SSL
  // preferences from local_state object.
  static SSLConfigServiceManager* CreateDefaultManager(
    const scoped_refptr<base::SingleThreadTaskRunner>& io_task_runner);

  virtual ~SSLConfigServiceManager() {}

  // Get an SSLConfigService instance.  It may be a new instance or the manager
  // may return the same instance multiple times.
  // The caller should hold a reference as long as it needs the instance (eg,
  // using scoped_refptr.)
  virtual net::SSLConfigService* Get() = 0;
};

}

#endif