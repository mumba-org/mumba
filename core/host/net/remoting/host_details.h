// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_NET_HOST_DETAILS_H_
#define MUMBA_HOST_NET_HOST_DETAILS_H_

#include <string>

namespace host {

// Returns the host OS name in a standard format for any build target.
std::string GetHostOperatingSystemName();

// Returns the host OS version in a standard format for any build target.
std::string GetHostOperatingSystemVersion();

}  // namespace remoting

#endif  // REMOTING_HOST_HOST_DETAILS_H_
