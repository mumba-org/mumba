// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_NET_REJECTING_AUTHENTICATOR_FACTORY_H_
#define MUMBA_HOST_NET_REJECTING_AUTHENTICATOR_FACTORY_H_

#include <string>

#include "base/macros.h"
#include "core/host/net/authenticator.h"

namespace host {

// Authenticator that accepts one message and rejects connection after that.
class RejectingAuthenticator : public Authenticator {
 public:
  RejectingAuthenticator(RejectionReason rejection_reason);
  ~RejectingAuthenticator() override;

  // Authenticator interface
  State state() const override;
  bool started() const override;
  RejectionReason rejection_reason() const override;
  void ProcessMessage(const buzz::XmlElement* message,
                      const base::Closure& resume_callback) override;
  std::unique_ptr<buzz::XmlElement> GetNextMessage() override;
  const std::string& GetAuthKey() const override;
  std::unique_ptr<ChannelAuthenticator> CreateChannelAuthenticator()
      const override;

 private:
  RejectionReason rejection_reason_;
  State state_ = WAITING_MESSAGE;
  std::string auth_key_;

  DISALLOW_COPY_AND_ASSIGN(RejectingAuthenticator);
};

}

#endif  // REMOTING_PROTOCOL_REJECTING_AUTHENTICATOR_FACTORY_H_
