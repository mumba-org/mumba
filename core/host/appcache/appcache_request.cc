// Copyright (c) 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/appcache/appcache_request.h"
#include "core/shared/common/appcache_interfaces.h"
#include "net/url_request/url_request.h"

namespace host {

AppCacheRequest::~AppCacheRequest() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
}

// static
bool AppCacheRequest::IsSchemeAndMethodSupportedForAppCache(
    const AppCacheRequest* request) {
  return common::IsSchemeSupportedForAppCache(request->GetURL()) &&
         common::IsMethodSupportedForAppCache(request->GetMethod());
}

net::URLRequest* AppCacheRequest::GetURLRequest() {
  return nullptr;
}

network::ResourceRequest* AppCacheRequest::GetResourceRequest() {
  return nullptr;
}

AppCacheURLRequest* AppCacheRequest::AsURLRequest() {
  return nullptr;
}

AppCacheURLLoaderRequest* AppCacheRequest::AsURLLoaderRequest() {
  return nullptr;
}

}  // namespace host
