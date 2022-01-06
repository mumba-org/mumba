// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/common/background_fetch/background_fetch_struct_traits.h"

#include "core/shared/common/service_worker/service_worker_event_dispatcher.mojom.h"
#include "core/shared/common/service_worker/service_worker_fetch_request_mojom_traits.h"
#include "core/shared/common/service_worker/service_worker_messages.h"
#include "mojo/public/cpp/bindings/array_data_view.h"

namespace mojo {

// static
bool StructTraits<blink::mojom::BackgroundFetchOptionsDataView,
                  common::BackgroundFetchOptions>::
    Read(blink::mojom::BackgroundFetchOptionsDataView data,
         common::BackgroundFetchOptions* options) {
  if (!data.ReadIcons(&options->icons) || !data.ReadTitle(&options->title))
    return false;

  options->download_total = data.download_total();
  return true;
}

// static
bool StructTraits<blink::mojom::BackgroundFetchRegistrationDataView,
                  common::BackgroundFetchRegistration>::
    Read(blink::mojom::BackgroundFetchRegistrationDataView data,
         common::BackgroundFetchRegistration* registration) {
  if (!data.ReadDeveloperId(&registration->developer_id) ||
      !data.ReadUniqueId(&registration->unique_id)) {
    return false;
  }

  registration->upload_total = data.upload_total();
  registration->uploaded = data.uploaded();
  registration->download_total = data.download_total();
  registration->downloaded = data.downloaded();
  return true;
}

// static
bool StructTraits<common::mojom::BackgroundFetchSettledFetchDataView,
                  common::BackgroundFetchSettledFetch>::
    Read(common::mojom::BackgroundFetchSettledFetchDataView data,
         common::BackgroundFetchSettledFetch* fetch) {
  return data.ReadRequest(&fetch->request) &&
         data.ReadResponse(&fetch->response);
}

// static
bool StructTraits<
    blink::mojom::IconDefinitionDataView,
    common::IconDefinition>::Read(blink::mojom::IconDefinitionDataView data,
                                   common::IconDefinition* definition) {
  return data.ReadSrc(&definition->src) && data.ReadSizes(&definition->sizes) &&
         data.ReadType(&definition->type);
}

}  // namespace mojo
