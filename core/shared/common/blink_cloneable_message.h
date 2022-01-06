// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CORE_SHARED_COMMON_BLINK_CLONEABLE_MESSAGE_H_
#define CORE_SHARED_COMMON_BLINK_CLONEABLE_MESSAGE_H_

#include "base/macros.h"
#include "core/shared/common/content_export.h"
#include "third_party/blink/renderer/bindings/core/v8/serialization/serialized_script_value.h"
#include "v8/include/v8-inspector.h"

// Warning: this is a duplication of BlinkCloneableMessage that is on blink
//          so that we dont have to change the web api too much
//          and yet can reuse some of its IPC facilities

namespace common {

// This struct represents messages as they are posted over a broadcast channel.
// This type can be serialized as a blink::mojom::CloneableMessage struct.
// This is the renderer-side equivalent of blink::MessagePortMessage, where this
// struct uses blink types, while the other struct uses std:: types.
struct CONTENT_EXPORT BlinkCloneableMessage {
  BlinkCloneableMessage();
  ~BlinkCloneableMessage();

  BlinkCloneableMessage(BlinkCloneableMessage&&);
  BlinkCloneableMessage& operator=(BlinkCloneableMessage&&);

  scoped_refptr<blink::SerializedScriptValue> message;
  v8_inspector::V8StackTraceId sender_stack_trace_id;

 private:
  DISALLOW_COPY_AND_ASSIGN(BlinkCloneableMessage);
};

}  // namespace common

#endif  // CORE_SHARED_COMMON_BLINK_CLONEABLE_MESSAGE_H_
