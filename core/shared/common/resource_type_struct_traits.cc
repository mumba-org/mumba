// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/common/resource_type_struct_traits.h"

namespace mojo {

// static
common::mojom::ResourceType
EnumTraits<common::mojom::ResourceType, common::ResourceType>::ToMojom(
    common::ResourceType input) {
  switch (input) {
    case common::RESOURCE_TYPE_MAIN_FRAME:
      return common::mojom::ResourceType::RESOURCE_TYPE_MAIN_FRAME;
    case common::RESOURCE_TYPE_SUB_FRAME:
      return common::mojom::ResourceType::RESOURCE_TYPE_SUB_FRAME;
    case common::RESOURCE_TYPE_STYLESHEET:
      return common::mojom::ResourceType::RESOURCE_TYPE_STYLESHEET;
    case common::RESOURCE_TYPE_SCRIPT:
      return common::mojom::ResourceType::RESOURCE_TYPE_SCRIPT;
    case common::RESOURCE_TYPE_IMAGE:
      return common::mojom::ResourceType::RESOURCE_TYPE_IMAGE;
    case common::RESOURCE_TYPE_FONT_RESOURCE:
      return common::mojom::ResourceType::RESOURCE_TYPE_FONT_RESOURCE;
    case common::RESOURCE_TYPE_SUB_RESOURCE:
      return common::mojom::ResourceType::RESOURCE_TYPE_SUB_RESOURCE;
    case common::RESOURCE_TYPE_OBJECT:
      return common::mojom::ResourceType::RESOURCE_TYPE_OBJECT;
    case common::RESOURCE_TYPE_MEDIA:
      return common::mojom::ResourceType::RESOURCE_TYPE_MEDIA;
    case common::RESOURCE_TYPE_WORKER:
      return common::mojom::ResourceType::RESOURCE_TYPE_WORKER;
    case common::RESOURCE_TYPE_SHARED_WORKER:
      return common::mojom::ResourceType::RESOURCE_TYPE_SHARED_WORKER;
    case common::RESOURCE_TYPE_PREFETCH:
      return common::mojom::ResourceType::RESOURCE_TYPE_PREFETCH;
    case common::RESOURCE_TYPE_FAVICON:
      return common::mojom::ResourceType::RESOURCE_TYPE_FAVICON;
    case common::RESOURCE_TYPE_XHR:
      return common::mojom::ResourceType::RESOURCE_TYPE_XHR;
    case common::RESOURCE_TYPE_PING:
      return common::mojom::ResourceType::RESOURCE_TYPE_PING;
    case common::RESOURCE_TYPE_SERVICE_WORKER:
      return common::mojom::ResourceType::RESOURCE_TYPE_SERVICE_WORKER;
    case common::RESOURCE_TYPE_CSP_REPORT:
      return common::mojom::ResourceType::RESOURCE_TYPE_CSP_REPORT;
    case common::RESOURCE_TYPE_PLUGIN_RESOURCE:
      return common::mojom::ResourceType::RESOURCE_TYPE_PLUGIN_RESOURCE;
    case common::RESOURCE_TYPE_LAST_TYPE:
      return common::mojom::ResourceType::RESOURCE_TYPE_LAST_TYPE;
  }

  NOTREACHED();
  return common::mojom::ResourceType::RESOURCE_TYPE_MAIN_FRAME;
}
// static
bool EnumTraits<common::mojom::ResourceType, common::ResourceType>::FromMojom(

    common::mojom::ResourceType input,
    common::ResourceType* output) {
  switch (input) {
    case common::mojom::ResourceType::RESOURCE_TYPE_MAIN_FRAME:
      *output = common::RESOURCE_TYPE_MAIN_FRAME;
      return true;
    case common::mojom::ResourceType::RESOURCE_TYPE_SUB_FRAME:
      *output = common::RESOURCE_TYPE_SUB_FRAME;
      return true;
    case common::mojom::ResourceType::RESOURCE_TYPE_STYLESHEET:
      *output = common::RESOURCE_TYPE_STYLESHEET;
      return true;
    case common::mojom::ResourceType::RESOURCE_TYPE_SCRIPT:
      *output = common::RESOURCE_TYPE_SCRIPT;
      return true;
    case common::mojom::ResourceType::RESOURCE_TYPE_IMAGE:
      *output = common::RESOURCE_TYPE_IMAGE;
      return true;
    case common::mojom::ResourceType::RESOURCE_TYPE_FONT_RESOURCE:
      *output = common::RESOURCE_TYPE_FONT_RESOURCE;
      return true;
    case common::mojom::ResourceType::RESOURCE_TYPE_SUB_RESOURCE:
      *output = common::RESOURCE_TYPE_SUB_RESOURCE;
      return true;
    case common::mojom::ResourceType::RESOURCE_TYPE_OBJECT:
      *output = common::RESOURCE_TYPE_OBJECT;
      return true;
    case common::mojom::ResourceType::RESOURCE_TYPE_MEDIA:
      *output = common::RESOURCE_TYPE_MEDIA;
      return true;
    case common::mojom::ResourceType::RESOURCE_TYPE_WORKER:
      *output = common::RESOURCE_TYPE_WORKER;
      return true;
    case common::mojom::ResourceType::RESOURCE_TYPE_SHARED_WORKER:
      *output = common::RESOURCE_TYPE_SHARED_WORKER;
      return true;
    case common::mojom::ResourceType::RESOURCE_TYPE_PREFETCH:
      *output = common::RESOURCE_TYPE_PREFETCH;
      return true;
    case common::mojom::ResourceType::RESOURCE_TYPE_FAVICON:
      *output = common::RESOURCE_TYPE_FAVICON;
      return true;
    case common::mojom::ResourceType::RESOURCE_TYPE_XHR:
      *output = common::RESOURCE_TYPE_XHR;
      return true;
    case common::mojom::ResourceType::RESOURCE_TYPE_PING:
      *output = common::RESOURCE_TYPE_PING;
      return true;
    case common::mojom::ResourceType::RESOURCE_TYPE_SERVICE_WORKER:
      *output = common::RESOURCE_TYPE_SERVICE_WORKER;
      return true;
    case common::mojom::ResourceType::RESOURCE_TYPE_CSP_REPORT:
      *output = common::RESOURCE_TYPE_CSP_REPORT;
      return true;
    case common::mojom::ResourceType::RESOURCE_TYPE_PLUGIN_RESOURCE:
      *output = common::RESOURCE_TYPE_PLUGIN_RESOURCE;
      return true;
    case common::mojom::ResourceType::RESOURCE_TYPE_LAST_TYPE:
      *output = common::RESOURCE_TYPE_LAST_TYPE;
      return true;
  }
  return false;
}

}  // namespace mojo
