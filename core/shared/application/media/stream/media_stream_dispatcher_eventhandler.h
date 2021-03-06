// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_RENDERER_MEDIA_STREAM_MEDIA_STREAM_DISPATCHER_EVENTHANDLER_H_
#define CONTENT_RENDERER_MEDIA_STREAM_MEDIA_STREAM_DISPATCHER_EVENTHANDLER_H_

#include <string>

#include "core/shared/common/content_export.h"
#include "core/shared/common/media_stream_request.h"

namespace application {

class CONTENT_EXPORT MediaStreamDispatcherEventHandler {
 public:
  // A device has been stopped in the browser process.
  virtual void OnDeviceStopped(const common::MediaStreamDevice& device) = 0;

 protected:
  virtual ~MediaStreamDispatcherEventHandler() {}
};

}  // namespace application

#endif  // CONTENT_RENDERER_MEDIA_STREAM_MEDIA_STREAM_DISPATCHER_EVENTHANDLER_H_
