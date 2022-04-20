// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/routing_policy_entry.h"

#include <linux/rtnetlink.h>

#include <utility>

bool operator==(const fib_rule_uid_range& a, const fib_rule_uid_range& b) {
  return (a.start == b.start) && (a.end == b.end);
}

namespace shill {

RoutingPolicyEntry::RoutingPolicyEntry()
    : family(IPAddress::kFamilyUnknown),
      priority(1),
      table(RT_TABLE_MAIN),
      invert_rule(false) {}

// static
RoutingPolicyEntry RoutingPolicyEntry::Create(IPAddress::Family family_in) {
  RoutingPolicyEntry entry;
  entry.family = family_in;
  return entry;
}

// static
RoutingPolicyEntry RoutingPolicyEntry::CreateFromSrc(IPAddress src_in) {
  RoutingPolicyEntry entry;
  entry.family = src_in.family();
  entry.src = std::move(src_in);
  return entry;
}

// static
RoutingPolicyEntry RoutingPolicyEntry::CreateFromDst(IPAddress dst_in) {
  RoutingPolicyEntry entry;
  entry.family = dst_in.family();
  entry.dst = std::move(dst_in);
  return entry;
}

RoutingPolicyEntry& RoutingPolicyEntry::SetPriority(uint32_t priority_in) {
  priority = priority_in;
  return *this;
}

RoutingPolicyEntry& RoutingPolicyEntry::SetTable(uint32_t table_in) {
  table = table_in;
  return *this;
}

RoutingPolicyEntry& RoutingPolicyEntry::SetFwMark(FwMark fw_mark_in) {
  fw_mark = fw_mark_in;
  return *this;
}

RoutingPolicyEntry& RoutingPolicyEntry::SetUid(uint32_t uid) {
  uid_range = fib_rule_uid_range{uid, uid};
  return *this;
}

RoutingPolicyEntry& RoutingPolicyEntry::SetUidRange(
    fib_rule_uid_range uid_range_in) {
  uid_range = uid_range_in;
  return *this;
}

RoutingPolicyEntry& RoutingPolicyEntry::SetIif(std::string iif_name_in) {
  iif_name = std::move(iif_name_in);
  return *this;
}

RoutingPolicyEntry& RoutingPolicyEntry::SetOif(std::string oif_name_in) {
  oif_name = std::move(oif_name_in);
  return *this;
}

RoutingPolicyEntry& RoutingPolicyEntry::FlipFamily() {
  family = (family == IPAddress::kFamilyIPv4) ? IPAddress::kFamilyIPv6
                                              : IPAddress::kFamilyIPv4;
  // We should not have src/dst whose family does not match |family|.
  if (src.family() != IPAddress::kFamilyUnknown) {
    src = IPAddress(family);
  }
  if (dst.family() != IPAddress::kFamilyUnknown) {
    dst = IPAddress(family);
  }

  return *this;
}

// clang-format off
bool RoutingPolicyEntry::operator==(const RoutingPolicyEntry& b) const {
    return (family == b.family &&
            priority == b.priority &&
            table == b.table &&
            dst == b.dst &&
            src == b.src &&
            fw_mark == b.fw_mark &&
            uid_range == b.uid_range &&
            iif_name == b.iif_name &&
            oif_name == b.oif_name &&
            invert_rule == b.invert_rule);
}
// clang-format on

}  // namespace shill
