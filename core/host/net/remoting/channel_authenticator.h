// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_NET_CHANNEL_AUTHENTICATOR_H_
#define MUMBA_HOST_NET_CHANNEL_AUTHENTICATOR_H_

#include <string>

#include "base/callback_forward.h"

namespace protocol {
class PeerStreamSocket;
}

namespace host {

// Interface for channel authentications that perform channel-level
// authentication. Depending on implementation channel authenticators
// may also establish SSL connection. Each instance of this interface
// should be used only once for one channel.
class ChannelAuthenticator {
 public:
  typedef base::Callback<void(int error, std::unique_ptr<protocol::PeerStreamSocket>)>
      DoneCallback;

  virtual ~ChannelAuthenticator() {}

  // Start authentication of the given |socket|. |done_callback| is called when
  // authentication is finished. Callback may be invoked before this method
  // returns, and may delete the calling authenticator.
  virtual void SecureAndAuthenticate(std::unique_ptr<protocol::PeerStreamSocket> socket,
                                     const DoneCallback& done_callback) = 0;
};

}

#endif  // REMOTING_PROTOCOL_CHANNEL_AUTHENTICATOR_H_
