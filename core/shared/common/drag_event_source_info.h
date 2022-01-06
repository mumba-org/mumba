// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_COMMON_DRAG_EVENT_SOURCE_INFO_H_
#define CONTENT_COMMON_DRAG_EVENT_SOURCE_INFO_H_

#include "core/shared/common/content_export.h"
#include "ui/base/dragdrop/drag_drop_types.h"
#include "ui/gfx/geometry/point.h"

namespace common {

// Information about the event that started a drag session.
struct CONTENT_EXPORT DragEventSourceInfo {
  gfx::Point event_location;
  ui::DragDropTypes::DragEventSource event_source;
};

};  // namespace content

#endif  // CONTENT_COMMON_DRAG_EVENT_SOURCE_INFO_H_
