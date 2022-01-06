// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_MOUNT_MOUNTABLE_H_
#define MUMBA_DOMAIN_MOUNT_MOUNTABLE_H_

#include "base/macros.h"

namespace domain {

// Something that can be mounted like a namespace
class Mountable {
public:
  virtual ~Mountable() {}
};

}

#endif