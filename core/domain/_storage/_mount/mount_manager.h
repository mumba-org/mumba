// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_MOUNT_MOUNT_MANAGER_H_
#define MUMBA_DOMAIN_MOUNT_MOUNT_MANAGER_H_

#include "base/macros.h"

namespace domain {
// manager -> 
//    context ->
//       (mount tree)
//         mount 0
//         mount 1
class MountManager {
public:
  MountManager();
  ~MountManager();

  void Initialize();
  void Shutdown();

private:

  DISALLOW_COPY_AND_ASSIGN(MountManager);
};

}

#endif