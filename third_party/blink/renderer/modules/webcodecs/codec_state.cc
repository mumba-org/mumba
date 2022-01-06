// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/webcodecs/codec_state.h"

namespace blink {

String CodecStateString(CodecState state) {
  switch (state) {
    case CodecState::kUnconfigured:
      return "unconfigured";
    case CodecState::kConfigured:
      return "configured";
    case CodecState::kClosed:
      return "closed";
  }
}

}  // namespace blink
