// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CORE_SHARED_COMMON_CLONEABLE_MESSAGE_H_
#define CORE_SHARED_COMMON_CLONEABLE_MESSAGE_H_

#include <vector>

#include "base/containers/span.h"
#include "base/macros.h"
#include "mojo/public/cpp/bindings/struct_ptr.h"
#include "core/shared/common/content_export.h"
#include "third_party/blink/public/mojom/blob/serialized_blob.mojom.h"

namespace common {

// This struct represents messages as they are posted over a broadcast channel.
// This type can be serialized as a blink::mojom::CloneableMessage struct.
struct CONTENT_EXPORT CloneableMessage {
  CloneableMessage();
  CloneableMessage(CloneableMessage&&);
  CloneableMessage& operator=(CloneableMessage&&);
  ~CloneableMessage();

  // Returns a shallow clone of this message. |encoded_message| in the clone
  // will point to the same memory as |encoded_message| in this.
  CloneableMessage ShallowClone() const;

  // To reduce copies when serializing |encoded_message| does not have to point
  // to |owned_encoded_message|. The serialization code completely ignores the
  // |owned_encoded_message| and just serializes whatever |encoded_message|
  // points to. When deserializing |owned_encoded_message| is set to the data
  // and |encoded_message| is set to point to |owned_encoded_message|.
  base::span<const uint8_t> encoded_message;
  std::vector<uint8_t> owned_encoded_message;

  // Copies data into owned_encoded_message if it's not already there.
  void EnsureDataIsOwned();

  // Blob handles for any blobs being sent in this message.
  std::vector<blink::mojom::SerializedBlobPtr> blobs;

  // Stack trace captured by sender.
  // For more details see v8_inspector::V8StackTraceId.
  uint64_t stack_trace_id = 0;
  int64_t stack_trace_debugger_id_first = 0;
  int64_t stack_trace_debugger_id_second = 0;

 private:
  DISALLOW_COPY_AND_ASSIGN(CloneableMessage);
};

}  // namespace blink

#endif  // THIRD_PARTY_BLINK_PUBLIC_COMMON_MESSAGE_PORT_CLONEABLE_MESSAGE_H_
