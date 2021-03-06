// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CORE_DOMAIN_LOADER_NAVIGATION_RESPONSE_OVERRIDE_PARAMETERS_H_
#define CORE_DOMAIN_LOADER_NAVIGATION_RESPONSE_OVERRIDE_PARAMETERS_H_

#include <vector>

#include "core/shared/common/content_export.h"
#include "net/url_request/redirect_info.h"
#include "services/network/public/cpp/resource_response.h"
#include "services/network/public/mojom/url_loader.mojom.h"
#include "url/gurl.h"

namespace domain {

// Used to override parameters of the navigation request.
struct CONTENT_EXPORT NavigationResponseOverrideParameters {
 public:
  NavigationResponseOverrideParameters();
  ~NavigationResponseOverrideParameters();

  network::mojom::URLLoaderClientEndpointsPtr url_loader_client_endpoints;
  network::ResourceResponseHead response;
  std::vector<GURL> redirects;
  std::vector<network::ResourceResponseHead> redirect_responses;
  std::vector<net::RedirectInfo> redirect_infos;
};

}  // namespace domain

#endif  // CORE_DOMAIN_LOADER_NAVIGATION_RESPONSE_OVERRIDE_PARAMETERS_H_
