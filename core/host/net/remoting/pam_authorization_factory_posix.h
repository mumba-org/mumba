// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_NET_PAM_AUTHORIZATION_FACTORY_POSIX_H_
#define MUMBA_HOST_NET_PAM_AUTHORIZATION_FACTORY_POSIX_H_

#include <memory>

#include "core/host/net/authenticator.h"


// PamAuthorizationFactory abuses the AuthenticatorFactory interface to apply
// PAM-based authorization on top of some underlying authentication scheme.

namespace host {

class PamAuthorizationFactory : public AuthenticatorFactory {
 public:
  PamAuthorizationFactory(
      std::unique_ptr<AuthenticatorFactory> underlying);
  ~PamAuthorizationFactory() override;

  std::unique_ptr<Authenticator> CreateAuthenticator(
      const std::string& local_jid,
      const std::string& remote_jid) override;

 private:
  std::unique_ptr<AuthenticatorFactory> underlying_;
};

}  // namespace remoting

#endif
