// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef THIRD_PARTY_BLINK_RENDERER_CORE_INSPECTOR_ADD_STRING_TO_DIGESTOR_H_
#define THIRD_PARTY_BLINK_RENDERER_CORE_INSPECTOR_ADD_STRING_TO_DIGESTOR_H_

#include "third_party/blink/renderer/core/core_export.h"

namespace WTF {
class String;
}

namespace blink {
class WebCryptoDigestor;
void CORE_EXPORT AddStringToDigestor(WebCryptoDigestor*, const WTF::String&);
}  // namespace blink

#endif  // THIRD_PARTY_BLINK_RENDERER_CORE_INSPECTOR_ADD_STRING_TO_DIGESTOR_H_
