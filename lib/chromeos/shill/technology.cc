// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/technology.h"

#include <set>
#include <string>
#include <vector>

//#include <base/check.h>
#include <base/containers/contains.h>
#include <base/strings/string_split.h>
#include <chromeos/dbus/service_constants.h>

#include "shill/error.h"
#include "shill/logging.h"

namespace shill {

// static
bool GetTechnologyVectorFromString(const std::string& technologies_string,
                                   std::vector<Technology>* technologies_vector,
                                   Error* error) {
  CHECK(technologies_vector);
  CHECK(error);

  technologies_vector->clear();

  // Check if |technologies_string| is empty as some versions of
  // base::SplitString return a vector with one empty string when given an
  // empty string.
  if (technologies_string.empty()) {
    return true;
  }

  std::set<Technology> seen;
  const auto technology_parts = base::SplitString(
      technologies_string, ",", base::TRIM_WHITESPACE, base::SPLIT_WANT_ALL);
  for (const auto& name : technology_parts) {
    Technology technology = Technology::CreateFromName(name);

    if (technology == Technology::kUnknown) {
      Error::PopulateAndLog(FROM_HERE, error, Error::kInvalidArguments,
                            name + " is an unknown technology name");
      return false;
    }

    if (base::Contains(seen, technology)) {
      Error::PopulateAndLog(FROM_HERE, error, Error::kInvalidArguments,
                            name + " is duplicated in the list");
      return false;
    }
    seen.insert(technology);
    technologies_vector->push_back(technology);
  }

  return true;
}

// static
Technology Technology::CreateFromName(const std::string& name) {
  if (name == kTypeEthernet) {
    return kEthernet;
  } else if (name == kTypeEthernetEap) {
    return kEthernetEap;
  } else if (name == kTypeWifi) {
    return kWiFi;
  } else if (name == kTypeCellular) {
    return kCellular;
  } else if (name == kTypeVPN) {
    return kVPN;
  } else if (name == kTypeTunnel) {
    return kTunnel;
  } else if (name == kTypeLoopback) {
    return kLoopback;
  } else if (name == kTypePPP) {
    return kPPP;
  } else if (name == kTypeGuestInterface) {
    return kGuestInterface;
  } else {
    return kUnknown;
  }
}

// static
Technology Technology::CreateFromStorageGroup(const std::string& group) {
  const auto group_parts = base::SplitString(group, "_", base::TRIM_WHITESPACE,
                                             base::SPLIT_WANT_ALL);
  if (group_parts.empty()) {
    return kUnknown;
  }
  return CreateFromName(group_parts[0]);
}

std::string Technology::GetName() const {
  if (type_ == kEthernet) {
    return kTypeEthernet;
  } else if (type_ == kEthernetEap) {
    return kTypeEthernetEap;
  } else if (type_ == kWiFi) {
    return kTypeWifi;
  } else if (type_ == kCellular) {
    return kTypeCellular;
  } else if (type_ == kVPN) {
    return kTypeVPN;
  } else if (type_ == kTunnel) {
    return kTypeTunnel;
  } else if (type_ == kLoopback) {
    return kTypeLoopback;
  } else if (type_ == kPPP) {
    return kTypePPP;
  } else if (type_ == kGuestInterface) {
    return kTypeGuestInterface;
  } else {
    return kTypeUnknown;
  }
}

bool Technology::IsPrimaryConnectivityTechnology() const {
  return (type_ == kCellular || type_ == kEthernet || type_ == kWiFi);
}

std::ostream& operator<<(std::ostream& os, const Technology& technology) {
  os << technology.GetName();
  return os;
}

}  // namespace shill
