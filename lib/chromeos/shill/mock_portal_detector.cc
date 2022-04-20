// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/mock_portal_detector.h"

namespace shill {

MockPortalDetector::MockPortalDetector()
    : PortalDetector(nullptr,
                     nullptr,
                     base::Callback<void(const PortalDetector::Result&)>()) {}

MockPortalDetector::~MockPortalDetector() = default;

}  // namespace shill
