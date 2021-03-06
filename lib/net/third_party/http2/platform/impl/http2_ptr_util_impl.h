// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_THIRD_PARTY_HTTP2_PLATFORM_IMPL_HTTP2_PTR_UTIL_IMPL_H_
#define NET_THIRD_PARTY_HTTP2_PLATFORM_IMPL_HTTP2_PTR_UTIL_IMPL_H_

#include <memory>
#include <utility>

namespace net {

template <typename T, typename... Args>
std::unique_ptr<T> Http2MakeUniqueImpl(Args&&... args) {
  return std::make_unique<T>(std::forward<Args>(args)...);
}

}  // namespace net

#endif  // NET_THIRD_PARTY_HTTP2_PLATFORM_IMPL_HTTP2_PTR_UTIL_IMPL_H_
