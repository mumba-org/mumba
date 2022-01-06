// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/common/cache_storage/cache_storage_mojom_traits.h"
#include "base/logging.h"
#include "core/shared/common/referrer_struct_traits.h"

namespace mojo {

using blink::mojom::CacheStorageError;
using blink::mojom::OperationType;

OperationType
EnumTraits<OperationType, common::CacheStorageCacheOperationType>::ToMojom(
    common::CacheStorageCacheOperationType input) {
  switch (input) {
    case common::CACHE_STORAGE_CACHE_OPERATION_TYPE_UNDEFINED:
      return OperationType::kUndefined;
    case common::CACHE_STORAGE_CACHE_OPERATION_TYPE_PUT:
      return OperationType::kPut;
    case common::CACHE_STORAGE_CACHE_OPERATION_TYPE_DELETE:
      return OperationType::kDelete;
  }
  NOTREACHED();
  return OperationType::kUndefined;
}

bool EnumTraits<OperationType, common::CacheStorageCacheOperationType>::
    FromMojom(OperationType input,
              common::CacheStorageCacheOperationType* out) {
  switch (input) {
    case OperationType::kUndefined:
      *out = common::CACHE_STORAGE_CACHE_OPERATION_TYPE_UNDEFINED;
      return true;
    case OperationType::kPut:
      *out = common::CACHE_STORAGE_CACHE_OPERATION_TYPE_PUT;
      return true;
    case OperationType::kDelete:
      *out = common::CACHE_STORAGE_CACHE_OPERATION_TYPE_DELETE;
      return true;
  }
  return false;
}

bool StructTraits<blink::mojom::QueryParamsDataView,
                  common::CacheStorageCacheQueryParams>::
    Read(blink::mojom::QueryParamsDataView data,
         common::CacheStorageCacheQueryParams* out) {
  base::Optional<base::string16> cache_name;
  if (!data.ReadCacheName(&cache_name))
    return false;
  out->cache_name = base::NullableString16(std::move(cache_name));
  out->ignore_search = data.ignore_search();
  out->ignore_method = data.ignore_method();
  out->ignore_vary = data.ignore_vary();
  return true;
}

bool StructTraits<blink::mojom::BatchOperationDataView,
                  common::CacheStorageBatchOperation>::
    Read(blink::mojom::BatchOperationDataView data,
         common::CacheStorageBatchOperation* out) {
  if (!data.ReadRequest(&out->request))
    return false;
  if (!data.ReadResponse(&out->response))
    return false;
  if (!data.ReadMatchParams(&out->match_params))
    return false;
  if (!data.ReadOperationType(&out->operation_type))
    return false;
  return true;
}

}  // namespace mojo
