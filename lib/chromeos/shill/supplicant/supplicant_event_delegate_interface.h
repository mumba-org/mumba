// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_SUPPLICANT_SUPPLICANT_EVENT_DELEGATE_INTERFACE_H_
#define SHILL_SUPPLICANT_SUPPLICANT_EVENT_DELEGATE_INTERFACE_H_

#include <string>

namespace shill {

// SupplicantEventDelegateInterface declares the set of methods that
// a SupplicantInterfaceProxy calls on an interested party when
// wpa_supplicant events occur on the network interface interface.
class SupplicantEventDelegateInterface {
 public:
  virtual ~SupplicantEventDelegateInterface() = default;

  // Supplicant has added a BSS to its table of visible endpoints.
  virtual void BSSAdded(const RpcIdentifier& BSS,
                        const KeyValueStore& properties) = 0;

  // Supplicant has removed a BSS from its table of visible endpoints.
  virtual void BSSRemoved(const RpcIdentifier& BSS) = 0;

  // Supplicant has received a certficate from the remote server during
  // the process of authentication.
  virtual void Certification(const KeyValueStore& properties) = 0;

  // Supplicant state machine has output an EAP event notification.
  virtual void EAPEvent(const std::string& status,
                        const std::string& parameter) = 0;

  // The interface element in the supplicant has changed one or more
  // properties.
  virtual void PropertiesChanged(const KeyValueStore& properties) = 0;

  // A scan has completed on this interface.
  virtual void ScanDone(const bool& success) = 0;

  // Report a match between an endpoint |BSS| and a set of Passpoint credentials
  // referred by |cred|. A set of complementary information gathered by
  // supplicant (such as match types) are provided in |properties|.
  virtual void InterworkingAPAdded(const RpcIdentifier& BSS,
                                   const RpcIdentifier& cred,
                                   const KeyValueStore& properties) = 0;

  // Interworking match between endpoint and Passpoint credentials is over.
  virtual void InterworkingSelectDone() = 0;
};

}  // namespace shill

#endif  // SHILL_SUPPLICANT_SUPPLICANT_EVENT_DELEGATE_INTERFACE_H_
