// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CORE_DOMAIN_URL_LOADER_THROTTLE_PROVIDER_H_
#define CORE_DOMAIN_URL_LOADER_THROTTLE_PROVIDER_H_

#include <memory>
#include <vector>

#include "core/shared/common/content_export.h"
#include "core/shared/common/resource_type.h"
#include "core/shared/common/url_loader_throttle.h"
#include "third_party/blink/public/platform/web_url_request.h"

namespace domain {

enum class URLLoaderThrottleProviderType {
  // Used for requests from frames. Please note that the requests could be
  // frame or subresource requests.
  kFrame,
  // Used for requests from workers, including dedicated, shared and service
  // workers.
  kWorker
};

class CONTENT_EXPORT URLLoaderThrottleProvider {
 public:
  virtual ~URLLoaderThrottleProvider() {}

  // Used to copy a URLLoaderThrottleProvider between worker threads.
  virtual std::unique_ptr<URLLoaderThrottleProvider> Clone() = 0;

  // For requests from frames and dedicated workers, |render_frame_id| should be
  // set to the corresponding frame. For requests from shared or
  // service workers, |render_frame_id| should be set to MSG_ROUTING_NONE.
  virtual std::vector<std::unique_ptr<common::URLLoaderThrottle>> CreateThrottles(
      int render_frame_id,
      const blink::WebURLRequest& request,
      common::ResourceType resource_type) = 0;
};

}  // namespace content

#endif  // CORE_DOMAIN_URL_LOADER_THROTTLE_PROVIDER_H_
