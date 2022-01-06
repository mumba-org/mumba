// Copyright 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "services/network/public/cpp/request_mode.h"

namespace network {

const char* RequestModeToString(network::mojom::FetchRequestMode mode) {
  switch (mode) {
    case network::mojom::FetchRequestMode::kSameOrigin:
      return "same-origin";
    case network::mojom::FetchRequestMode::kNoCors:
      return "no-cors";
    case network::mojom::FetchRequestMode::kCors:
    case network::mojom::FetchRequestMode::kCorsWithForcedPreflight:
      return "cors";
    case network::mojom::FetchRequestMode::kNavigate:
      return "navigate";
  }
  NOTREACHED();
  return "";
}

}  // namespace network
