// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_NET_NETLINK_MESSAGE_MATCHERS_H_
#define SHILL_NET_NETLINK_MESSAGE_MATCHERS_H_

#include <base/logging.h>
#include <gmock/gmock.h>

#include "shill/net/netlink_message.h"
#include "shill/net/nl80211_message.h"

namespace shill {

// Given a netlink message, verifies that it is an Nl80211Message and verifies,
// further that it is the specified command.
MATCHER_P2(IsNl80211Command, nl80211_message_type, command, "") {
  if (!arg) {
    return false;
  }
  if (arg->message_type() != nl80211_message_type) {
    return false;
  }
  const Nl80211Message* msg = static_cast<const Nl80211Message*>(arg);
  if (msg->command() != command) {
    return false;
  }
  return true;
}

// Given a netlink message, verifies that it is configured to disable
// wake on WiFi functionality of the NIC.
MATCHER(IsDisableWakeOnWiFiMsg, "") {
  if (!arg) {
    return false;
  }
  const Nl80211Message* msg = static_cast<const Nl80211Message*>(arg);
  if (msg->command() != NL80211_CMD_SET_WOWLAN) {
    return false;
  }
  uint32_t wiphy;
  if (!msg->const_attributes()->GetU32AttributeValue(NL80211_ATTR_WIPHY,
                                                     &wiphy)) {
    return false;
  }
  AttributeListConstRefPtr triggers;
  if (msg->const_attributes()->ConstGetNestedAttributeList(
          NL80211_ATTR_WOWLAN_TRIGGERS, &triggers)) {
    return false;
  }
  return true;
}

// Verifies that a NetlinkMessage is an NL80211_CMD_TRIGGER_SCAN message that
// contains exactly one SSID along with the requisite empty one.
MATCHER_P(HasHiddenSSID, nl80211_message_type, "") {
  if (!arg) {
    return false;
  }
  if (arg->message_type() != nl80211_message_type) {
    return false;
  }
  const Nl80211Message* msg = reinterpret_cast<const Nl80211Message*>(arg);
  if (msg->command() != NL80211_CMD_TRIGGER_SCAN) {
    return false;
  }
  AttributeListConstRefPtr ssids;
  if (!msg->const_attributes()->ConstGetNestedAttributeList(
          NL80211_ATTR_SCAN_SSIDS, &ssids)) {
    return false;
  }
  ByteString ssid;
  AttributeIdIterator ssid_iter(*ssids);
  if (!ssids->GetRawAttributeValue(ssid_iter.GetId(), &ssid)) {
    return false;
  }

  // A valid Scan containing a single hidden SSID should contain
  // two SSID entries: one containing the SSID we are looking for,
  // and an empty entry, signifying that we also want to do a
  // broadcast probe request for all non-hidden APs as well.
  ByteString empty_ssid;
  if (ssid_iter.AtEnd()) {
    return false;
  }
  ssid_iter.Advance();
  if (!ssids->GetRawAttributeValue(ssid_iter.GetId(), &empty_ssid) ||
      !empty_ssid.IsEmpty()) {
    return false;
  }

  return true;
}

// Verifies that a NetlinkMessage is an NL80211_CMD_TRIGGER_SCAN message that
// contains no SSIDs.
MATCHER_P(HasNoHiddenSSID, nl80211_message_type, "") {
  if (!arg) {
    return false;
  }
  if (arg->message_type() != nl80211_message_type) {
    return false;
  }
  const Nl80211Message* msg = reinterpret_cast<const Nl80211Message*>(arg);
  if (msg->command() != NL80211_CMD_TRIGGER_SCAN) {
    return false;
  }
  AttributeListConstRefPtr ssids;
  if (!msg->const_attributes()->ConstGetNestedAttributeList(
          NL80211_ATTR_SCAN_SSIDS, &ssids)) {
    return true;
  }
  AttributeIdIterator ssid_iter(*ssids);
  if (ssid_iter.AtEnd()) {
    return true;
  }

  return false;
}

}  // namespace shill

#endif  // SHILL_NET_NETLINK_MESSAGE_MATCHERS_H_
