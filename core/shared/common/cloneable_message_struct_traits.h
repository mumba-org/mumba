// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CORE_SHARED_COMMON_CLONEABLE_MESSAGE_STRUCT_TRAITS_H_
#define CORE_SHARED_COMMON_CLONEABLE_MESSAGE_STRUCT_TRAITS_H_

#include "mojo/public/cpp/base/big_buffer.h"
#include "core/shared/common/cloneable_message.h"
#include "core/shared/common/message.mojom.h"
#include "core/shared/common/content_export.h"

namespace mojo {

template <>
struct CONTENT_EXPORT
    StructTraits<common::mojom::CloneableMessage::DataView,
                 common::CloneableMessage> {
  static mojo_base::BigBufferView encoded_message(
      common::CloneableMessage& input);

  static std::vector<blink::mojom::SerializedBlobPtr>& blobs(
      common::CloneableMessage& input) {
    return input.blobs;
  }

  static uint64_t stack_trace_id(common::CloneableMessage& input) {
    return input.stack_trace_id;
  }

  static int64_t stack_trace_debugger_id_first(common::CloneableMessage& input) {
    return input.stack_trace_debugger_id_first;
  }

  static int64_t stack_trace_debugger_id_second(
      common::CloneableMessage& input) {
    return input.stack_trace_debugger_id_second;
  }

  static bool Read(common::mojom::CloneableMessage::DataView data,
                   common::CloneableMessage* out);
};

}  // namespace mojo

#endif  // THIRD_PARTY_BLINK_COMMON_MESSAGE_PORT_CLONEABLE_MESSAGE_STRUCT_TRAITS_H_
