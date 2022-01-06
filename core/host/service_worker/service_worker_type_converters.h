// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_BROWSER_SERVICE_WORKER_SERVICE_WORKER_STATE_CONVERTERS_H_
#define CONTENT_BROWSER_SERVICE_WORKER_SERVICE_WORKER_STATE_CONVERTERS_H_

#include "core/host/service_worker/service_worker_version.h"
#include "core/shared/common/service_worker/service_worker_status_code.h"
#include "third_party/blink/public/mojom/service_worker/service_worker_event_status.mojom.h"
#include "third_party/blink/public/mojom/service_worker/service_worker_state.mojom.h"

namespace mojo {

template <>
struct CONTENT_EXPORT TypeConverter<blink::mojom::ServiceWorkerState,
                                    host::ServiceWorkerVersion::Status> {
  static blink::mojom::ServiceWorkerState Convert(
      host::ServiceWorkerVersion::Status status);
};

template <>
struct CONTENT_EXPORT TypeConverter<common::ServiceWorkerStatusCode,
                                    blink::mojom::ServiceWorkerEventStatus> {
  static common::ServiceWorkerStatusCode Convert(
      blink::mojom::ServiceWorkerEventStatus status);
};

}  // namespace mojo

#endif  // CONTENT_RENDERER_SERVICE_WORKER_SERVICE_WORKER_STATE_CONVERTERS_H_
