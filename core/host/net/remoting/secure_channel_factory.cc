// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/net/secure_channel_factory.h"

#include <utility>

#include "base/bind.h"
#include "core/host/net/authenticator.h"
#include "core/host/net/channel_authenticator.h"
#include "core/common/protocol/peer_stream_socket.h"

namespace host {

SecureChannelFactory::SecureChannelFactory(
    StreamChannelFactory* channel_factory,
    Authenticator* authenticator)
    : channel_factory_(channel_factory),
      authenticator_(authenticator) {
  DCHECK_EQ(authenticator_->state(), Authenticator::ACCEPTED);
}

SecureChannelFactory::~SecureChannelFactory() {
  // CancelChannelCreation() is expected to be called before destruction.
  DCHECK(channel_authenticators_.empty());
}

void SecureChannelFactory::CreateChannel(
    const std::string& name,
    const ChannelCreatedCallback& callback) {
  DCHECK(!callback.is_null());
  channel_factory_->CreateChannel(
      name,
      base::Bind(&SecureChannelFactory::OnBaseChannelCreated,
                 base::Unretained(this), name, callback));
}

void SecureChannelFactory::CancelChannelCreation(
    const std::string& name) {
  AuthenticatorMap::iterator it = channel_authenticators_.find(name);
  if (it == channel_authenticators_.end()) {
    channel_factory_->CancelChannelCreation(name);
  } else {
    delete it->second;
    channel_authenticators_.erase(it);
  }
}

void SecureChannelFactory::OnBaseChannelCreated(
    const std::string& name,
    const ChannelCreatedCallback& callback,
    std::unique_ptr<protocol::PeerStreamSocket> socket) {
  if (!socket) {
    callback.Run(nullptr);
    return;
  }

  ChannelAuthenticator* channel_authenticator =
      authenticator_->CreateChannelAuthenticator().release();
  channel_authenticators_[name] = channel_authenticator;
  channel_authenticator->SecureAndAuthenticate(
      std::move(socket),
      base::Bind(&SecureChannelFactory::OnSecureChannelCreated,
                 base::Unretained(this), name, callback));
}

void SecureChannelFactory::OnSecureChannelCreated(
    const std::string& name,
    const ChannelCreatedCallback& callback,
    int error,
    std::unique_ptr<protocol::PeerStreamSocket> socket) {
  DCHECK((socket && error == net::OK) || (!socket && error != net::OK));

  AuthenticatorMap::iterator it = channel_authenticators_.find(name);
  DCHECK(it != channel_authenticators_.end());
  delete it->second;
  channel_authenticators_.erase(it);

  callback.Run(std::move(socket));
}

}
