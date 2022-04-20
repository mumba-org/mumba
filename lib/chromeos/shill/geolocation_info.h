// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_GEOLOCATION_INFO_H_
#define SHILL_GEOLOCATION_INFO_H_

#include <map>
#include <string>

#include <base/time/time.h>

namespace shill {

// Geolocation property field names are defined by those kGeo* constants in
// <chromiumos>/src/platform/system_api/dbus/shill/dbus-constants.h.
using GeolocationInfo = std::map<std::string, std::string>;

// Helper functions to serialize and transform the last-seen time for a
// geolocation object, so up-to-date age values can be returned over D-Bus.
void AddLastSeenTime(GeolocationInfo* info, const base::TimeTicks& time);
GeolocationInfo PrepareGeolocationInfoForExport(const GeolocationInfo& info);

}  // namespace shill

#endif  // SHILL_GEOLOCATION_INFO_H_
