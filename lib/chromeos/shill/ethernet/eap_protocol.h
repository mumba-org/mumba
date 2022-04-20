// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_ETHERNET_EAP_PROTOCOL_H_
#define SHILL_ETHERNET_EAP_PROTOCOL_H_

#include <base/compiler_specific.h>

namespace shill {

namespace eap_protocol {

struct ALIGNAS(1) Ieee8021xHdr {
  uint8_t version;
  uint8_t type;
  uint16_t length;
};

enum IeeeEapolVersion {
  kIeee8021xEapolVersion1 = 1,
  kIeee8021xEapolVersion2 = 2
};

enum IeeeEapolType {
  kIIeee8021xTypeEapPacket = 0,
  kIIeee8021xTypeEapolStart = 1,
  kIIeee8021xTypeEapolLogoff = 2,
  kIIeee8021xTypeEapolKey = 3,
  kIIeee8021xTypeEapolEncapsulatedAsfAlert = 4
};

struct ALIGNAS(1) EapHeader {
  uint8_t code;
  uint8_t identifier;
  uint16_t length;  // including code and identifier; network byte order
};

enum EapCode {
  kEapCodeRequest = 1,
  kEapCodeRespnose = 2,
  kEapCodeSuccess = 3,
  kEapCodeFailure = 4
};

}  // namespace eap_protocol

}  // namespace shill

#endif  // SHILL_ETHERNET_EAP_PROTOCOL_H_
