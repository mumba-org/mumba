// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_TETHERING_H_
#define SHILL_TETHERING_H_

#include <stdint.h>

#include <set>
#include <vector>

namespace shill {

class Tethering {
 public:
  // Modern Android phones in tethering mode provide DHCP option 43 even
  // without a DHCP client requesting it.  The constant below is the value
  // that it provides for this propery.
  static const char kAndroidVendorEncapsulatedOptions[];

  // This 802.11 BSS prefix is provided by many Android-based devices.
  static const uint8_t kAndroidBSSIDPrefix[];

  // This OUI is provided in 802.11 vendor IEs by many IOS devices in
  // tethering mode.
  static const uint32_t kIosOui;

  // This bit, if set in the first octet of a MAC address, indicates that
  // this address is not assigned by the IEEE, but was generated locally.
  static const uint8_t kLocallyAdministratedMacBit;

  // Returns whether an 802.11 BSSID is likely to be owned by an Android device.
  static bool IsAndroidBSSID(const std::vector<uint8_t>& bssid);

  // Returns whether an 802.11 BSSID is a locally-administered address, as
  // opposed to a unique IEEE-issued address.
  static bool IsLocallyAdministeredBSSID(const std::vector<uint8_t>& bssid);

  // Returns whether any of the organizationally unique identifiers in
  // |oui_set| is commonly associated with IOS devices.
  static bool HasIosOui(const std::set<uint32_t>& oui_set);
};

}  // namespace shill

#endif  // SHILL_TETHERING_H_
