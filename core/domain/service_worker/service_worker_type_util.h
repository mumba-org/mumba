// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CORE_DOMAIN_SERVICE_WORKER_SERVICE_WORKER_TYPE_UTIL_H_
#define CORE_DOMAIN_SERVICE_WORKER_SERVICE_WORKER_TYPE_UTIL_H_

#include "core/shared/common/service_worker/service_worker_types.h"

namespace blink {
class WebServiceWorkerRequest;
class WebServiceWorkerResponse;
}

namespace domain {

void GetServiceWorkerHeaderMapFromWebRequest(
    const blink::WebServiceWorkerRequest& web_request,
    common::ServiceWorkerHeaderMap* headers);

common::ServiceWorkerResponse GetServiceWorkerResponseFromWebResponse(
    const blink::WebServiceWorkerResponse& web_response);

}  // namespace domain

#endif  // CORE_DOMAIN_SERVICE_WORKER_SERVICE_WORKER_TYPE_UTIL_H_
