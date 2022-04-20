// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_ROUTING_TABLE_ENTRY_H_
#define SHILL_ROUTING_TABLE_ENTRY_H_

#include <iostream>

#include "shill/net/ip_address.h"

namespace shill {

// Represents a single entry in a routing table.
struct RoutingTableEntry {
  static const int kDefaultTag;

  RoutingTableEntry();

  static RoutingTableEntry Create(IPAddress::Family family);
  static RoutingTableEntry Create(const IPAddress& dst_in,
                                  const IPAddress& src_in,
                                  const IPAddress& gateway_in);

  RoutingTableEntry& SetMetric(uint32_t metric_in);
  RoutingTableEntry& SetScope(unsigned char scope_in);
  RoutingTableEntry& SetTable(uint32_t table_in);
  RoutingTableEntry& SetType(unsigned char type_in);
  RoutingTableEntry& SetTag(uint8_t tag_in);

  bool operator==(const RoutingTableEntry& b) const;

  IPAddress dst;
  IPAddress src;
  IPAddress gateway;
  uint32_t metric;
  unsigned char scope;
  uint32_t table;
  unsigned char type;
  unsigned char protocol;
  int tag;
};

// Print out an entry in a format similar to that of ip route.
std::ostream& operator<<(std::ostream& os, const RoutingTableEntry& entry);

}  // namespace shill

#endif  // SHILL_ROUTING_TABLE_ENTRY_H_
