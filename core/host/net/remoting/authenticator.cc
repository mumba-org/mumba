// Copyright (c) 2011 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/net/authenticator.h"

#include "core/host/net/constants.h"
#include "third_party/libjingle_xmpp/xmllite/xmlelement.h"

namespace host {

namespace {
const buzz::StaticQName kAuthenticationQName = { kChromotingXmlNamespace,
                                                 "authentication" };
}  // namespace

// static
bool Authenticator::IsAuthenticatorMessage(const buzz::XmlElement* message) {
  return message->Name() == kAuthenticationQName;
}

// static
std::unique_ptr<buzz::XmlElement>
Authenticator::CreateEmptyAuthenticatorMessage() {
  return std::make_unique<buzz::XmlElement>(kAuthenticationQName);
}

// static
const buzz::XmlElement* Authenticator::FindAuthenticatorMessage(
    const buzz::XmlElement* message) {
  return message->FirstNamed(kAuthenticationQName);
}

}