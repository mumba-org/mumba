// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/common/url_loader_factory_bundle_struct_traits.h"

namespace mojo {

using Traits =
    StructTraits<common::mojom::URLLoaderFactoryBundleDataView,
                 std::unique_ptr<common::URLLoaderFactoryBundleInfo>>;

// static
network::mojom::URLLoaderFactoryPtrInfo Traits::default_factory(
    BundleInfoType& bundle) {
  return std::move(bundle->default_factory_info());
}

// static
std::map<std::string, network::mojom::URLLoaderFactoryPtrInfo>
Traits::factories(BundleInfoType& bundle) {
  return std::move(bundle->factories_info());
}

// static
bool Traits::Read(common::mojom::URLLoaderFactoryBundleDataView data,
                  BundleInfoType* out_bundle) {
  *out_bundle = std::make_unique<common::URLLoaderFactoryBundleInfo>();

  (*out_bundle)->default_factory_info() =
      data.TakeDefaultFactory<network::mojom::URLLoaderFactoryPtrInfo>();
  if (!data.ReadFactories(&(*out_bundle)->factories_info()))
    return false;

  return true;
}

}  // namespace mojo
