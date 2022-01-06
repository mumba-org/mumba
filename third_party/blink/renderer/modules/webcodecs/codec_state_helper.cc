// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/webcodecs/codec_state_helper.h"

namespace blink {

// static
bool ThrowIfCodecStateClosed(CodecState state,
                             String operation,
                             ExceptionState& exception_state) {
  if (state != CodecState::kClosed)
    return false;

  exception_state.ThrowDOMException(
      kInvalidStateError,
      "Cannot call '" + operation + "' on a closed codec.");
  return true;
}

// static
bool ThrowIfCodecStateUnconfigured(CodecState state,
                                   String operation,
                                   ExceptionState& exception_state) {
  if (state != CodecState::kUnconfigured)
    return false;

  exception_state.ThrowDOMException(
      kInvalidStateError,
      "Cannot call '" + operation + "' on an unconfigured codec.");
  return true;
}

}  // namespace blink
