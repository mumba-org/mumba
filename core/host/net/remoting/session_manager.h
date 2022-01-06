// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_NET_SESSION_MANAGER_H_
#define MUMBA_HOST_NET_SESSION_MANAGER_H_

#include "base/callback.h"
#include "base/macros.h"
#include "core/host/net/session.h"

namespace host {
class Authenticator;
class AuthenticatorFactory;
class SignalingAddress;
class SignalStrategy;

// Generic interface for Chromoting session manager.
class SessionManager {
 public:
  enum IncomingSessionResponse {
    // Accept the session.
    ACCEPT,

    // Reject the session because the host is currently disabled due
    // to previous login attempts.
    OVERLOAD,

    // Reject the session because the client is not allowed to connect
    // to the host.
    DECLINE,
  };

  // Callback used to accept incoming connections. If the host decides to accept
  // the session it should set the |response| to ACCEPT. Otherwise it should set
  // it to DECLINE, or INCOMPATIBLE. INCOMPATIBLE indicates that the session has
  // incompatible configuration, and cannot be accepted. If the callback accepts
  // the |session| then it must also set configuration for the |session| using
  // Session::set_config(). The callback must take ownership of the |session| if
  // it ACCEPTs it.
  typedef base::Callback<void(Session* session,
                              IncomingSessionResponse* response)>
      IncomingSessionCallback;

  SessionManager() {}
  virtual ~SessionManager() {}

  // Starts accepting incoming connections.
  virtual void AcceptIncoming(
      const IncomingSessionCallback& incoming_session_callback) = 0;

  // Sets local protocol configuration to be used when negotiating outgoing and
  // incoming connections.
  virtual void set_protocol_config(
      std::unique_ptr<CandidateSessionConfig> config) = 0;

  // Creates a new outgoing session.
  //
  // |peer_address| - full SignalingAddress to connect to.
  // |authenticator| - client authenticator for the session.
  virtual std::unique_ptr<Session> Connect(
      const SignalingAddress& peer_address,
      std::unique_ptr<Authenticator> authenticator) = 0;

  // Set authenticator factory that should be used to authenticate
  // incoming connection. No connections will be accepted if
  // authenticator factory isn't set. Must not be called more than
  // once per SessionManager because it may not be safe to delete
  // factory before all authenticators it created are deleted.
  virtual void set_authenticator_factory(
      std::unique_ptr<AuthenticatorFactory> authenticator_factory) = 0;

 private:
  DISALLOW_COPY_AND_ASSIGN(SessionManager);
};

}

#endif