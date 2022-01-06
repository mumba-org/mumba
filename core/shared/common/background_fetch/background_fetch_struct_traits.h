// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_BROWSER_BACKGROUND_FETCH_BACKGROUND_FETCH_STRUCT_TRAITS_H_
#define CONTENT_BROWSER_BACKGROUND_FETCH_BACKGROUND_FETCH_STRUCT_TRAITS_H_

#include <string>
#include <vector>

#include "core/shared/common/background_fetch/background_fetch_types.h"
#include "core/shared/common/content_export.h"
#include "mojo/public/cpp/bindings/struct_traits.h"
#include "third_party/blink/public/platform/modules/background_fetch/background_fetch.mojom.h"

namespace common {
namespace mojom {
class BackgroundFetchSettledFetchDataView;
}
}

namespace mojo {

template <>
struct CONTENT_EXPORT StructTraits<blink::mojom::BackgroundFetchOptionsDataView,
                                   common::BackgroundFetchOptions> {
  static const std::vector<common::IconDefinition>& icons(
      const common::BackgroundFetchOptions& options) {
    return options.icons;
  }
  static const std::string& title(
      const common::BackgroundFetchOptions& options) {
    return options.title;
  }
  static uint64_t download_total(
      const common::BackgroundFetchOptions& options) {
    return options.download_total;
  }

  static bool Read(blink::mojom::BackgroundFetchOptionsDataView data,
                   common::BackgroundFetchOptions* options);
};

template <>
struct CONTENT_EXPORT
    StructTraits<blink::mojom::BackgroundFetchRegistrationDataView,
                 common::BackgroundFetchRegistration> {
  static const std::string& developer_id(
      const common::BackgroundFetchRegistration& registration) {
    return registration.developer_id;
  }
  static const std::string& unique_id(
      const common::BackgroundFetchRegistration& registration) {
    return registration.unique_id;
  }
  static uint64_t upload_total(
      const common::BackgroundFetchRegistration& registration) {
    return registration.upload_total;
  }
  static uint64_t uploaded(
      const common::BackgroundFetchRegistration& registration) {
    return registration.uploaded;
  }
  static uint64_t download_total(
      const common::BackgroundFetchRegistration& registration) {
    return registration.download_total;
  }
  static uint64_t downloaded(
      const common::BackgroundFetchRegistration& registration) {
    return registration.downloaded;
  }

  static bool Read(blink::mojom::BackgroundFetchRegistrationDataView data,
                   common::BackgroundFetchRegistration* registration);
};

template <>
struct CONTENT_EXPORT
    StructTraits<common::mojom::BackgroundFetchSettledFetchDataView,
                 common::BackgroundFetchSettledFetch> {
  static const common::ServiceWorkerFetchRequest& request(
      const common::BackgroundFetchSettledFetch& fetch) {
    return fetch.request;
  }
  static const common::ServiceWorkerResponse& response(
      const common::BackgroundFetchSettledFetch& fetch) {
    return fetch.response;
  }

  static bool Read(common::mojom::BackgroundFetchSettledFetchDataView data,
                   common::BackgroundFetchSettledFetch* definition);
};

template <>
struct CONTENT_EXPORT StructTraits<blink::mojom::IconDefinitionDataView,
                                   common::IconDefinition> {
  static const std::string& src(const common::IconDefinition& definition) {
    return definition.src;
  }
  static const std::string& sizes(const common::IconDefinition& definition) {
    return definition.sizes;
  }
  static const std::string& type(const common::IconDefinition& definition) {
    return definition.type;
  }

  static bool Read(blink::mojom::IconDefinitionDataView data,
                   common::IconDefinition* definition);
};

}  // namespace mojo

#endif  // CONTENT_BROWSER_BACKGROUND_FETCH_BACKGROUND_FETCH_STRUCT_TRAITS_H_
