// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_SHELL_NET_P2P_NETWORK_MANAGER_UMA_H_
#define MUMBA_SHELL_NET_P2P_NETWORK_MANAGER_UMA_H_

namespace base {
class TimeDelta;
}  // namespace

namespace application {

// Need to be kept the same order as in histograms.xml
enum IPPermissionStatus {
  PERMISSION_UNKNOWN,  // Requested but have never fired SignalNetworksChanged.
  PERMISSION_NOT_REQUESTED,             // Multiple routes is not requested.
  PERMISSION_DENIED,                    // Requested but denied.
  PERMISSION_GRANTED_WITH_CHECKING,     // Requested and granted after checking
                                        // mic/camera permission.
  PERMISSION_GRANTED_WITHOUT_CHECKING,  // Requested and granted without
                                        // checking mic/camera permission.
  PERMISSION_MAX,
};

void ReportIPPermissionStatus(IPPermissionStatus status);
void ReportTimeToUpdateNetworkList(const base::TimeDelta& ticks);

}  // namespace application

#endif  // MUMBA_SHELL_NET_P2P_NETWORK_MANAGER_UMA_H_
