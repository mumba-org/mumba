// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/service_worker/service_worker_registration_status.h"

#include <string>

#include "base/logging.h"
#include "base/strings/utf_string_conversions.h"
#include "third_party/blink/public/mojom/service_worker/service_worker_error_type.mojom.h"

namespace host {

using blink::WebServiceWorkerError;

void GetServiceWorkerErrorTypeForRegistration(
    common::ServiceWorkerStatusCode status,
    const std::string& status_message,
    blink::mojom::ServiceWorkerErrorType* out_error,
    std::string* out_message) {
  *out_error = blink::mojom::ServiceWorkerErrorType::kUnknown;
  if (!status_message.empty())
    *out_message = status_message;
  else
    *out_message = ServiceWorkerStatusToString(status);
  switch (status) {
    case common::SERVICE_WORKER_OK:
      NOTREACHED() << "Calling this when status == OK is not allowed";
      return;

    case common::SERVICE_WORKER_ERROR_START_WORKER_FAILED:
    case common::SERVICE_WORKER_ERROR_INSTALL_WORKER_FAILED:
    case common::SERVICE_WORKER_ERROR_PROCESS_NOT_FOUND:
    case common::SERVICE_WORKER_ERROR_REDUNDANT:
    case common::SERVICE_WORKER_ERROR_DISALLOWED:
      *out_error = blink::mojom::ServiceWorkerErrorType::kInstall;
      return;

    case common::SERVICE_WORKER_ERROR_NOT_FOUND:
      *out_error = blink::mojom::ServiceWorkerErrorType::kNotFound;
      return;

    case common::SERVICE_WORKER_ERROR_NETWORK:
      *out_error = blink::mojom::ServiceWorkerErrorType::kNetwork;
      return;

    case common::SERVICE_WORKER_ERROR_SCRIPT_EVALUATE_FAILED:
      *out_error = blink::mojom::ServiceWorkerErrorType::kScriptEvaluateFailed;
      return;

    case common::SERVICE_WORKER_ERROR_SECURITY:
      *out_error = blink::mojom::ServiceWorkerErrorType::kSecurity;
      return;

    case common::SERVICE_WORKER_ERROR_TIMEOUT:
      *out_error = blink::mojom::ServiceWorkerErrorType::kTimeout;
      return;

    case common::SERVICE_WORKER_ERROR_ABORT:
      *out_error = blink::mojom::ServiceWorkerErrorType::kAbort;
      return;

    case common::SERVICE_WORKER_ERROR_ACTIVATE_WORKER_FAILED:
    case common::SERVICE_WORKER_ERROR_IPC_FAILED:
    case common::SERVICE_WORKER_ERROR_FAILED:
    case common::SERVICE_WORKER_ERROR_EXISTS:
    case common::SERVICE_WORKER_ERROR_EVENT_WAITUNTIL_REJECTED:
    case common::SERVICE_WORKER_ERROR_STATE:
    case common::SERVICE_WORKER_ERROR_DISK_CACHE:
    case common::SERVICE_WORKER_ERROR_MAX_VALUE:
      // Unexpected, or should have bailed out before calling this, or we don't
      // have a corresponding blink error code yet.
      break;  // Fall through to NOTREACHED().
  }
  NOTREACHED() << "Got unexpected error code: " << status << " "
               << ServiceWorkerStatusToString(status);
}

}  // namespace host
