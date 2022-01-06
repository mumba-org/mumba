// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_NET_P2P_WEBRTC_CALLBACKS_H_
#define MUMBA_HOST_NET_P2P_WEBRTC_CALLBACKS_H_

#include <memory>

#include "base/callback.h"

namespace host {

using WebRtcRtpPacketCallback =
      base::Callback<void(std::unique_ptr<uint8_t[]> packet_header,
                          size_t header_length,
                          size_t packet_length,
                          bool incoming)>;

using WebRtcStopRtpDumpCallback =
      base::Callback<void(bool incoming, bool outgoing)>;

}

#endif