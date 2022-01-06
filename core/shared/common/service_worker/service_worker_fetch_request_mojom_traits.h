// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_COMMON_SERVICE_WORKER_SERVICE_WORKER_FETCH_REQUEST_MOJOM_TRAITS_H_
#define CONTENT_COMMON_SERVICE_WORKER_SERVICE_WORKER_FETCH_REQUEST_MOJOM_TRAITS_H_

#include "base/numerics/safe_conversions.h"
#include "core/shared/common/referrer.h"
#include "services/network/public/mojom/request_context_frame_type.mojom.h"
#include "storage/common/blob_storage/blob_handle.h"
#include "third_party/blink/public/platform/modules/fetch/fetch_api_request.mojom.h"

namespace mojo {

template <>
struct EnumTraits<blink::mojom::RequestContextType,
                  common::RequestContextType> {
  static blink::mojom::RequestContextType ToMojom(
      common::RequestContextType input);

  static bool FromMojom(blink::mojom::RequestContextType input,
                        common::RequestContextType* out);
};

template <>
struct StructTraits<blink::mojom::FetchAPIRequestDataView,
                    common::ServiceWorkerFetchRequest> {
  static network::mojom::FetchRequestMode mode(
      const common::ServiceWorkerFetchRequest& request) {
    return request.mode;
  }

  static bool is_main_resource_load(
      const common::ServiceWorkerFetchRequest& request) {
    return request.is_main_resource_load;
  }

  static common::RequestContextType request_context_type(
      const common::ServiceWorkerFetchRequest& request) {
    return request.request_context_type;
  }

  static network::mojom::RequestContextFrameType frame_type(
      const common::ServiceWorkerFetchRequest& request) {
    return request.frame_type;
  }

  static const GURL& url(const common::ServiceWorkerFetchRequest& request) {
    return request.url;
  }

  static const std::string& method(
      const common::ServiceWorkerFetchRequest& request) {
    return request.method;
  }

  static std::map<std::string,
                  std::string,
                  common::ServiceWorkerCaseInsensitiveCompare>
  headers(const common::ServiceWorkerFetchRequest& request) {
    return request.headers;
  }

  // common::ServiceWorkerFetchRequest does not support the request body.
  static const std::string& blob_uuid(
      const common::ServiceWorkerFetchRequest& request) {
    return base::EmptyString();
  }

  // common::ServiceWorkerFetchRequest does not support the request body.
  static uint64_t blob_size(const common::ServiceWorkerFetchRequest& request) {
    return 0;
  }

  // common::ServiceWorkerFetchRequest does not support the request body.
  static blink::mojom::BlobPtr blob(
      const common::ServiceWorkerFetchRequest& request) {
    return nullptr;
  }

  static const common::Referrer& referrer(
      const common::ServiceWorkerFetchRequest& request) {
    return request.referrer;
  }

  static network::mojom::FetchCredentialsMode credentials_mode(
      const common::ServiceWorkerFetchRequest& request) {
    return request.credentials_mode;
  }

  static blink::mojom::FetchCacheMode cache_mode(
      const common::ServiceWorkerFetchRequest& request) {
    return request.cache_mode;
  }

  static network::mojom::FetchRedirectMode redirect_mode(
      const common::ServiceWorkerFetchRequest& request) {
    return request.redirect_mode;
  }

  static const std::string& integrity(
      const common::ServiceWorkerFetchRequest& request) {
    return request.integrity;
  }

  static bool keepalive(const common::ServiceWorkerFetchRequest& request) {
    return request.keepalive;
  }

  static const std::string& client_id(
      const common::ServiceWorkerFetchRequest& request) {
    return request.client_id;
  }

  static bool is_reload(const common::ServiceWorkerFetchRequest& request) {
    return request.is_reload;
  }

  static bool Read(blink::mojom::FetchAPIRequestDataView data,
                   common::ServiceWorkerFetchRequest* out);
};

}  // namespace mojo

#endif  // CONTENT_COMMON_SERVICE_WORKER_SERVICE_WORKER_FETCH_REQUEST_MOJOM_TRAITS_H_
