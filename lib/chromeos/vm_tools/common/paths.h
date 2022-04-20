// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_COMMON_PATHS_H_
#define VM_TOOLS_COMMON_PATHS_H_

namespace vm_tools {

// Path to the file that garcon will check to determine the ip address of the
// host.
constexpr char kGarconHostIpFile[] = "/dev/.host_ip";

// Path to the file that garcon will check to get the container token.
constexpr char kGarconContainerTokenFile[] = "/dev/.container_token";

}  // namespace vm_tools

#endif  // VM_TOOLS_COMMON_PATHS_H_
