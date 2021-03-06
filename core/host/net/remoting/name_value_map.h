// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Helper functions that allow to map enum values to strings.

#ifndef MUMBA_HOST_NET_NAME_VALUE_MAP_H_
#define MUMBA_HOST_NET_NAME_VALUE_MAP_H_

#include <stddef.h>

#include "base/logging.h"

namespace host {

template <typename T>
struct NameMapElement {
  const T value;
  const char* const name;
};

template <typename T, size_t N>
const char* ValueToName(const NameMapElement<T> (&map)[N], T value) {
  for (size_t i = 0; i < N; ++i) {
    if (map[i].value == value)
      return map[i].name;
  }
  NOTREACHED();
  return nullptr;
}

template <typename T, size_t N>
bool NameToValue(const NameMapElement<T> (&map)[N],
                 const std::string& name,
                 T* result) {
  for (size_t i = 0; i < N; ++i) {
    if (map[i].name == name) {
      *result = map[i].value;
      return true;
    }
  }
  return false;
}

}  // namespace remoting

#endif  // REMOTING_BASE_NAME_VALUE_MAP_H_
