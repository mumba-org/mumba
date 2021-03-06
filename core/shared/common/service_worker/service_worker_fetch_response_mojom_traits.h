// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#ifndef CONTENT_COMMON_SERVICE_WORKER_SERVICE_WORKER_FETCH_RESPONSE_MOJOM_TRAITS_H_
#define CONTENT_COMMON_SERVICE_WORKER_SERVICE_WORKER_FETCH_RESPONSE_MOJOM_TRAITS_H_

#include <map>
#include <string>
#include <vector>

#include "base/numerics/safe_conversions.h"
#include "core/shared/common/service_worker/service_worker_types.h"
#include "storage/common/blob_storage/blob_handle.h"
#include "third_party/blink/public/mojom/blob/blob.mojom.h"
#include "third_party/blink/public/platform/modules/fetch/fetch_api_response.mojom.h"

namespace mojo {

template <>
struct StructTraits<blink::mojom::FetchAPIResponseDataView,
                    common::ServiceWorkerResponse> {
  static const std::vector<GURL>& url_list(
      const common::ServiceWorkerResponse& response) {
    return response.url_list;
  }
  static int status_code(const common::ServiceWorkerResponse& response) {
    return response.status_code;
  }
  static bool is_in_cache_storage(
      const common::ServiceWorkerResponse& response) {
    return response.is_in_cache_storage;
  }
  static blink::mojom::BlobPtr blob(
      const common::ServiceWorkerResponse& response) {
    if (response.blob) {
      return response.blob->Clone();
    }
    return nullptr;
  }
  static const std::string& status_text(
      const common::ServiceWorkerResponse& response) {
    return response.status_text;
  }
  static network::mojom::FetchResponseType response_type(
      const common::ServiceWorkerResponse& response) {
    return response.response_type;
  }
  static std::map<std::string,
                  std::string,
                  common::ServiceWorkerCaseInsensitiveCompare>
  headers(const common::ServiceWorkerResponse& response) {
    return response.headers;
  }
  static std::string blob_uuid(const common::ServiceWorkerResponse& response) {
    return response.blob_uuid;
  }
  static uint64_t blob_size(const common::ServiceWorkerResponse& response) {
    return response.blob_size;
  }
  static blink::mojom::ServiceWorkerResponseError error(
      const common::ServiceWorkerResponse& response) {
    return response.error;
  }
  static const base::Time& response_time(
      const common::ServiceWorkerResponse& response) {
    return response.response_time;
  }
  static const std::string& cache_storage_cache_name(
      const common::ServiceWorkerResponse& response) {
    return response.cache_storage_cache_name;
  }
  static const std::vector<std::string>& cors_exposed_header_names(
      const common::ServiceWorkerResponse& response) {
    return response.cors_exposed_header_names;
  }
  static bool Read(blink::mojom::FetchAPIResponseDataView,
                   common::ServiceWorkerResponse* output);
};

}  // namespace mojo

#endif  // CONTENT_COMMON_SERVICE_WORKER_SERVICE_WORKER_FETCH_RESPONSE_MOJOM_TRAITS_H_
