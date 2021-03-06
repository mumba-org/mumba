// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_NET_DATAGRAM_CHANNEL_FACTORY_H_
#define MUMBA_HOST_NET_DATAGRAM_CHANNEL_FACTORY_H_

#include <memory>
#include <string>

#include "base/callback_forward.h"
#include "base/macros.h"

namespace protocol {
class PeerDatagramSocket;  
}

namespace host {

class DatagramChannelFactory {
 public:
  typedef base::Callback<void(std::unique_ptr<protocol::PeerDatagramSocket>)>
      ChannelCreatedCallback;

  DatagramChannelFactory() {}

  // Creates new channels and calls the |callback| when then new channel is
  // created and connected. The |callback| is called with nullptr if channel
  // setup failed for any reason. Callback may be called synchronously, before
  // the call returns. All channels must be destroyed, and
  // CancelChannelCreation() called for any pending channels, before the factory
  // is destroyed.
  virtual void CreateChannel(const std::string& name,
                             const ChannelCreatedCallback& callback) = 0;

  // Cancels a pending CreateChannel() operation for the named channel. If the
  // channel creation already completed then canceling it has no effect. When
  // shutting down this method must be called for each channel pending creation.
  virtual void CancelChannelCreation(const std::string& name) = 0;

 protected:
  virtual ~DatagramChannelFactory() {}

 private:
  DISALLOW_COPY_AND_ASSIGN(DatagramChannelFactory);
};

}  // namespace host

#endif  // REMOTING_PROTOCOL_DATAGRAM_CHANNEL_FACTORY_H_
