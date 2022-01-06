// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/loader/navigation_loader_interceptor.h"

#include "core/shared/common/navigation_subresource_loader_params.h"

namespace host {

base::Optional<common::SubresourceLoaderParams>
NavigationLoaderInterceptor::MaybeCreateSubresourceLoaderParams() {
  return base::nullopt;
}

bool NavigationLoaderInterceptor::MaybeCreateLoaderForResponse(
    const network::ResourceResponseHead& response,
    network::mojom::URLLoaderPtr* loader,
    network::mojom::URLLoaderClientRequest* client_request,
    ThrottlingURLLoader* url_loader) {
  return false;
}

}  // namespace host
