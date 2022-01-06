// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_RENDERER_FRAME_BLAME_CONTEXT_H_
#define CONTENT_RENDERER_FRAME_BLAME_CONTEXT_H_

#include "base/trace_event/blame_context.h"
#include "core/shared/common/content_export.h"

namespace application {

// A blame context which represents a single render frame.
class CONTENT_EXPORT FrameBlameContext : public base::trace_event::BlameContext {
 public:
  FrameBlameContext(int routing_id);
  ~FrameBlameContext() override;

  DISALLOW_COPY_AND_ASSIGN(FrameBlameContext);
};

}  // namespace application

#endif  // CONTENT_RENDERER_FRAME_BLAME_CONTEXT_H_
