// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_NET_PEER_SESSION_DETAILS_H_
#define MUMBA_HOST_NET_PEER_SESSION_DETAILS_H_

#include <cstdint>

namespace host {

class PeerSessionControl;

// Provides ClientSession control and state information to HostExtensions.
class PeerSessionDetails {
 public:
  virtual ~PeerSessionDetails() {}

  // Returns a ClientSessionControl interface pointer used to interact with the
  // current session.
  virtual PeerSessionControl* session_control() = 0;

  // Returns the id of the current desktop session being remoted.  If no session
  // exists, UINT32_MAX is returned.
  // Note: The return value should never be cached as it can change.
  virtual uint32_t desktop_session_id() const = 0;
};

}  // namespace remoting

#endif  // REMOTING_HOST_CLIENT_SESSION_DETAILS_H_
