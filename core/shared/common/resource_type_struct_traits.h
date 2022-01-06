// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_PUBLIC_COMMON_RESOURCE_TYPE_ENUM_TRAITS_H_
#define CONTENT_PUBLIC_COMMON_RESOURCE_TYPE_ENUM_TRAITS_H_

#include "core/shared/common/resource_type.h"
#include "core/shared/common/resource_type.mojom-shared.h"
#include "mojo/public/cpp/bindings/enum_traits.h"

namespace mojo {

template <>
struct EnumTraits<common::mojom::ResourceType, common::ResourceType> {
  static common::mojom::ResourceType ToMojom(common::ResourceType input);
  static bool FromMojom(common::mojom::ResourceType input,
                        common::ResourceType* output);
};
}  // namespace mojo

#endif  // CONTENT_PUBLIC_COMMON_RESOURCE_TYPE_ENUM_TRAITS_H_
