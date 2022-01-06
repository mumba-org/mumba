// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_NAMESPACE_MOUNT_INFO_H_
#define MUMBA_DOMAIN_NAMESPACE_MOUNT_INFO_H_

namespace domain {

struct MountInfo {
  base::UUID ns;
  std::string mount_point;
  base::TimeTicks mounted_time;
};

}

#endif