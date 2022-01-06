// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_MOUNT_MOUNT_CONTEXT_H_
#define MUMBA_DOMAIN_MOUNT_MOUNT_CONTEXT_H_

#include "base/macros.h"
#include "url/gurl.h"

namespace domain {

// manager -> 
//    context  - mounted at "/" or "/hello"
//       namespace->graph
//         node 0
//         node 1
//         ...
class MountContext {
public:
  MountContext();
  ~MountContext();

  const GURL& url() const {
    return url_;
  }

  // NOTE: mount contexts have namespaces
  // so when can mount rpc:// or http://
  // or blob:// or device:// when it make sense
  // well-known ns' s:
  // device, rpc, web, blob, app, etc..
  // note that namespaces will make sense of it
  // so a ApplicationNamespace is mounted in a app:// ns
  std::string ns() const {
    return url_.scheme();
  }

private:
  
  GURL url_;

  DISALLOW_COPY_AND_ASSIGN(MountContext);
};

}

#endif