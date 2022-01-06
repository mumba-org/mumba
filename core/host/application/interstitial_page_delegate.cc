// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/application/interstitial_page_delegate.h"

namespace host {
InterstitialPageDelegate::TypeID InterstitialPageDelegate::GetTypeForTesting()
    const {
  return nullptr;
}

}  // namespace host
