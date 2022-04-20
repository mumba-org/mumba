// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_CALLBACKS_H_
#define SHILL_CALLBACKS_H_

#include <map>
#include <string>
#include <vector>

#include <base/callback.h>
#include <brillo/any.h>

#include "shill/data_types.h"
#include "shill/error.h"
#include "shill/store/key_value_store.h"

namespace shill {

class Error;
// Convenient typedefs for some commonly used callbacks.
using ResultCallback = base::Callback<void(const Error&)>;
using ResultOnceCallback = base::OnceCallback<void(const Error&)>;
using ResultBoolCallback = base::Callback<void(const Error&, bool)>;
using ResultStringCallback =
    base::Callback<void(const Error&, const std::string&)>;
using ResultVariantDictionariesCallback =
    base::Callback<void(const Error&, const VariantDictionaries&)>;
using ResultVariantDictionariesOnceCallback =
    base::OnceCallback<void(const VariantDictionaries&, const Error&)>;
using EnabledStateChangedCallback = base::Callback<void(const Error&)>;
using KeyValueStoreCallback =
    base::Callback<void(const KeyValueStore&, const Error&)>;
using KeyValueStoresCallback =
    base::Callback<void(const std::vector<KeyValueStore>&, const Error&)>;
using KeyValueStoresOnceCallback =
    base::OnceCallback<void(const std::vector<KeyValueStore>&, const Error&)>;
using RpcIdentifierCallback =
    base::Callback<void(const RpcIdentifier&, const Error&)>;
using StringCallback = base::Callback<void(const std::string&, const Error&)>;
using ActivationStateSignalCallback =
    base::Callback<void(uint32_t, uint32_t, const KeyValueStore&)>;
using ResultStringmapsCallback =
    base::Callback<void(const Stringmaps&, const Error&)>;
using BrilloAnyCallback =
    base::Callback<void(const std::map<uint32_t, brillo::Any>&, const Error&)>;

}  // namespace shill

#endif  // SHILL_CALLBACKS_H_
