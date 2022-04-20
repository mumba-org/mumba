// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_TECHNOLOGY_H_
#define SHILL_TECHNOLOGY_H_

#include <iostream>
#include <string>
#include <vector>

namespace shill {

class Error;
class Technology;

// Convert a comma-separated list of technology names (with no whitespace
// around commas) into a vector of Technology instances output in
// |technologies_vector|. Returns true if the |technologies_string| contains a
// valid set of technologies with no duplicate elements, false otherwise.
bool GetTechnologyVectorFromString(const std::string& technologies_string,
                                   std::vector<Technology>* technologies_vector,
                                   Error* error);

// A class representing a particular network technology type.
class Technology {
 public:
  enum Type {
    kEthernet,
    kEthernetEap,
    kWiFi,
    kWiFiMonitor,
    kCellular,
    kVPN,
    kTunnel,
    kBlocked,
    kLoopback,
    kCDCEthernet,      // Only for internal use in DeviceInfo.
    kVirtioEthernet,   // Only for internal use in DeviceInfo.
    kNoDeviceSymlink,  // Only for internal use in DeviceInfo.
    kPPP,
    kArcBridge,
    // Virtual tap devices used by guest OS and clients getting Internet via
    // Chrome OS host kernel.
    kGuestInterface,
    kUnknown,
  };

  // Return a Technology instance given the technology name, or
  // Technology::kUnknown if the technology name is unknown.
  static Technology CreateFromName(const std::string& name);

  // Return a Technology instance for a storage group identifier in |group|
  // |group|, which should have the format of <technology name>_<suffix>, or
  // Technology::kUnknown if |group| is not prefixed with a known technology
  // name.
  static Technology CreateFromStorageGroup(const std::string& group);

  Technology() : Technology(kUnknown) {}
  // Not explicit so that Types can be passed to methods taking Technologies.
  Technology(Type type) : type_(type) {}  // NOLINT(runtime/explicit)

  // Allow for Technology to be used as a Type (useful for
  // comparisons/switch-cases involving Types).
  operator Type() const { return type_; }

  std::string GetName() const;

  // Return true if |technology| is a primary connectivity technology, i.e.
  // Ethernet, Cellular, WiFi.
  bool IsPrimaryConnectivityTechnology() const;

 private:
  Type type_;
};

// Add the Technology name to the ostream.
std::ostream& operator<<(std::ostream& os, const Technology& technology);

}  // namespace shill

#endif  // SHILL_TECHNOLOGY_H_
