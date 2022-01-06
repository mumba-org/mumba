// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/application/frame_blame_context.h"

#include "base/trace_event/trace_event_argument.h"
#include "core/shared/application/top_level_blame_context.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/web/web_local_frame.h"

namespace application {
namespace {

base::trace_event::BlameContext* GetParentBlameContext() {
    //RenderFrameImpl* parent_frame) {
  //if (parent_frame)
  //  return parent_frame->GetFrameBlameContext();
  return blink::Platform::Current()->GetTopLevelBlameContext();
}

}  // namespace

const char kFrameBlameContextCategory[] = "blink";
const char kFrameBlameContextName[] = "FrameBlameContext";
const char kFrameBlameContextType[] = "RenderFrame";
const char kFrameBlameContextScope[] = "RenderFrame";

FrameBlameContext::FrameBlameContext(int routing_id)
    : base::trace_event::BlameContext(kFrameBlameContextCategory,
                                      kFrameBlameContextName,
                                      kFrameBlameContextType,
                                      kFrameBlameContextScope,
                                      routing_id,
                                      GetParentBlameContext()) {}

FrameBlameContext::~FrameBlameContext() {}

}  // namespace application
