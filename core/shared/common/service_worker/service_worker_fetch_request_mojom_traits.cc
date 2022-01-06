// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/common/service_worker/service_worker_fetch_request_mojom_traits.h"

#include "base/logging.h"
#include "core/shared/common/referrer_struct_traits.h"
#include "url/mojom/url_gurl_mojom_traits.h"

namespace mojo {

using blink::mojom::RequestContextType;
using network::mojom::FetchRequestMode;

RequestContextType
EnumTraits<RequestContextType, common::RequestContextType>::ToMojom(
    common::RequestContextType input) {
  switch (input) {
    case common::REQUEST_CONTEXT_TYPE_UNSPECIFIED:
      return RequestContextType::UNSPECIFIED;
    case common::REQUEST_CONTEXT_TYPE_AUDIO:
      return RequestContextType::AUDIO;
    case common::REQUEST_CONTEXT_TYPE_BEACON:
      return RequestContextType::BEACON;
    case common::REQUEST_CONTEXT_TYPE_CSP_REPORT:
      return RequestContextType::CSP_REPORT;
    case common::REQUEST_CONTEXT_TYPE_DOWNLOAD:
      return RequestContextType::DOWNLOAD;
    case common::REQUEST_CONTEXT_TYPE_EMBED:
      return RequestContextType::EMBED;
    case common::REQUEST_CONTEXT_TYPE_EVENT_SOURCE:
      return RequestContextType::EVENT_SOURCE;
    case common::REQUEST_CONTEXT_TYPE_FAVICON:
      return RequestContextType::FAVICON;
    case common::REQUEST_CONTEXT_TYPE_FETCH:
      return RequestContextType::FETCH;
    case common::REQUEST_CONTEXT_TYPE_FONT:
      return RequestContextType::FONT;
    case common::REQUEST_CONTEXT_TYPE_FORM:
      return RequestContextType::FORM;
    case common::REQUEST_CONTEXT_TYPE_FRAME:
      return RequestContextType::FRAME;
    case common::REQUEST_CONTEXT_TYPE_HYPERLINK:
      return RequestContextType::HYPERLINK;
    case common::REQUEST_CONTEXT_TYPE_IFRAME:
      return RequestContextType::IFRAME;
    case common::REQUEST_CONTEXT_TYPE_IMAGE:
      return RequestContextType::IMAGE;
    case common::REQUEST_CONTEXT_TYPE_IMAGE_SET:
      return RequestContextType::IMAGE_SET;
    case common::REQUEST_CONTEXT_TYPE_IMPORT:
      return RequestContextType::IMPORT;
    case common::REQUEST_CONTEXT_TYPE_INTERNAL:
      return RequestContextType::INTERNAL;
    case common::REQUEST_CONTEXT_TYPE_LOCATION:
      return RequestContextType::LOCATION;
    case common::REQUEST_CONTEXT_TYPE_MANIFEST:
      return RequestContextType::MANIFEST;
    case common::REQUEST_CONTEXT_TYPE_OBJECT:
      return RequestContextType::OBJECT;
    case common::REQUEST_CONTEXT_TYPE_PING:
      return RequestContextType::PING;
    case common::REQUEST_CONTEXT_TYPE_PLUGIN:
      return RequestContextType::PLUGIN;
    case common::REQUEST_CONTEXT_TYPE_PREFETCH:
      return RequestContextType::PREFETCH;
    case common::REQUEST_CONTEXT_TYPE_SCRIPT:
      return RequestContextType::SCRIPT;
    case common::REQUEST_CONTEXT_TYPE_SERVICE_WORKER:
      return RequestContextType::SERVICE_WORKER;
    case common::REQUEST_CONTEXT_TYPE_SHARED_WORKER:
      return RequestContextType::SHARED_WORKER;
    case common::REQUEST_CONTEXT_TYPE_SUBRESOURCE:
      return RequestContextType::SUBRESOURCE;
    case common::REQUEST_CONTEXT_TYPE_STYLE:
      return RequestContextType::STYLE;
    case common::REQUEST_CONTEXT_TYPE_TRACK:
      return RequestContextType::TRACK;
    case common::REQUEST_CONTEXT_TYPE_VIDEO:
      return RequestContextType::VIDEO;
    case common::REQUEST_CONTEXT_TYPE_WORKER:
      return RequestContextType::WORKER;
    case common::REQUEST_CONTEXT_TYPE_XML_HTTP_REQUEST:
      return RequestContextType::XML_HTTP_REQUEST;
    case common::REQUEST_CONTEXT_TYPE_XSLT:
      return RequestContextType::XSLT;
  }

  NOTREACHED();
  return RequestContextType::UNSPECIFIED;
}

bool EnumTraits<RequestContextType, common::RequestContextType>::FromMojom(
    RequestContextType input,
    common::RequestContextType* out) {
  switch (input) {
    case RequestContextType::UNSPECIFIED:
      *out = common::REQUEST_CONTEXT_TYPE_UNSPECIFIED;
      return true;
    case RequestContextType::AUDIO:
      *out = common::REQUEST_CONTEXT_TYPE_AUDIO;
      return true;
    case RequestContextType::BEACON:
      *out = common::REQUEST_CONTEXT_TYPE_BEACON;
      return true;
    case RequestContextType::CSP_REPORT:
      *out = common::REQUEST_CONTEXT_TYPE_CSP_REPORT;
      return true;
    case RequestContextType::DOWNLOAD:
      *out = common::REQUEST_CONTEXT_TYPE_DOWNLOAD;
      return true;
    case RequestContextType::EMBED:
      *out = common::REQUEST_CONTEXT_TYPE_EMBED;
      return true;
    case RequestContextType::EVENT_SOURCE:
      *out = common::REQUEST_CONTEXT_TYPE_EVENT_SOURCE;
      return true;
    case RequestContextType::FAVICON:
      *out = common::REQUEST_CONTEXT_TYPE_FAVICON;
      return true;
    case RequestContextType::FETCH:
      *out = common::REQUEST_CONTEXT_TYPE_FETCH;
      return true;
    case RequestContextType::FONT:
      *out = common::REQUEST_CONTEXT_TYPE_FONT;
      return true;
    case RequestContextType::FORM:
      *out = common::REQUEST_CONTEXT_TYPE_FORM;
      return true;
    case RequestContextType::FRAME:
      *out = common::REQUEST_CONTEXT_TYPE_FRAME;
      return true;
    case RequestContextType::HYPERLINK:
      *out = common::REQUEST_CONTEXT_TYPE_HYPERLINK;
      return true;
    case RequestContextType::IFRAME:
      *out = common::REQUEST_CONTEXT_TYPE_IFRAME;
      return true;
    case RequestContextType::IMAGE:
      *out = common::REQUEST_CONTEXT_TYPE_IMAGE;
      return true;
    case RequestContextType::IMAGE_SET:
      *out = common::REQUEST_CONTEXT_TYPE_IMAGE_SET;
      return true;
    case RequestContextType::IMPORT:
      *out = common::REQUEST_CONTEXT_TYPE_IMPORT;
      return true;
    case RequestContextType::INTERNAL:
      *out = common::REQUEST_CONTEXT_TYPE_INTERNAL;
      return true;
    case RequestContextType::LOCATION:
      *out = common::REQUEST_CONTEXT_TYPE_LOCATION;
      return true;
    case RequestContextType::MANIFEST:
      *out = common::REQUEST_CONTEXT_TYPE_MANIFEST;
      return true;
    case RequestContextType::OBJECT:
      *out = common::REQUEST_CONTEXT_TYPE_OBJECT;
      return true;
    case RequestContextType::PING:
      *out = common::REQUEST_CONTEXT_TYPE_PING;
      return true;
    case RequestContextType::PLUGIN:
      *out = common::REQUEST_CONTEXT_TYPE_PLUGIN;
      return true;
    case RequestContextType::PREFETCH:
      *out = common::REQUEST_CONTEXT_TYPE_PREFETCH;
      return true;
    case RequestContextType::SCRIPT:
      *out = common::REQUEST_CONTEXT_TYPE_SCRIPT;
      return true;
    case RequestContextType::SERVICE_WORKER:
      *out = common::REQUEST_CONTEXT_TYPE_SERVICE_WORKER;
      return true;
    case RequestContextType::SHARED_WORKER:
      *out = common::REQUEST_CONTEXT_TYPE_SHARED_WORKER;
      return true;
    case RequestContextType::SUBRESOURCE:
      *out = common::REQUEST_CONTEXT_TYPE_SUBRESOURCE;
      return true;
    case RequestContextType::STYLE:
      *out = common::REQUEST_CONTEXT_TYPE_STYLE;
      return true;
    case RequestContextType::TRACK:
      *out = common::REQUEST_CONTEXT_TYPE_TRACK;
      return true;
    case RequestContextType::VIDEO:
      *out = common::REQUEST_CONTEXT_TYPE_VIDEO;
      return true;
    case RequestContextType::WORKER:
      *out = common::REQUEST_CONTEXT_TYPE_WORKER;
      return true;
    case RequestContextType::XML_HTTP_REQUEST:
      *out = common::REQUEST_CONTEXT_TYPE_XML_HTTP_REQUEST;
      return true;
    case RequestContextType::XSLT:
      *out = common::REQUEST_CONTEXT_TYPE_XSLT;
      return true;
  }

  return false;
}

bool StructTraits<blink::mojom::FetchAPIRequestDataView,
                  common::ServiceWorkerFetchRequest>::
    Read(blink::mojom::FetchAPIRequestDataView data,
         common::ServiceWorkerFetchRequest* out) {
  std::unordered_map<std::string, std::string> headers;
  if (!data.ReadMode(&out->mode) ||
      !data.ReadRequestContextType(&out->request_context_type) ||
      !data.ReadFrameType(&out->frame_type) || !data.ReadUrl(&out->url) ||
      !data.ReadMethod(&out->method) || !data.ReadHeaders(&headers) ||
      !data.ReadReferrer(&out->referrer) ||
      !data.ReadCredentialsMode(&out->credentials_mode) ||
      !data.ReadRedirectMode(&out->redirect_mode) ||
      !data.ReadIntegrity(&out->integrity) ||
      !data.ReadClientId(&out->client_id)) {
    return false;
  }

  // common::ServiceWorkerFetchRequest doesn't support request body.
  base::Optional<std::string> blob_uuid;
  if (data.ReadBlobUuid(&blob_uuid) && blob_uuid && !blob_uuid->empty())
    return false;
  blink::mojom::BlobPtr blob = data.TakeBlob<blink::mojom::BlobPtr>();
  if (blob)
    return false;

  out->is_main_resource_load = data.is_main_resource_load();
  out->headers.insert(headers.begin(), headers.end());
  out->cache_mode = data.cache_mode();
  out->keepalive = data.keepalive();
  out->is_reload = data.is_reload();
  return true;
}

}  // namespace mojo
