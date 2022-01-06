// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/common/cache_storage/cache_storage_types.h"

namespace common {

CacheStorageCacheQueryParams::CacheStorageCacheQueryParams()
    : ignore_search(false), ignore_method(false), ignore_vary(false) {
}

CacheStorageBatchOperation::CacheStorageBatchOperation() {
}

CacheStorageBatchOperation::CacheStorageBatchOperation(
    const CacheStorageBatchOperation& other) = default;

}  // namespace content
