// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_MEDIA_CAPTURE_WEB_CONTENTS_VIDEO_CAPTURE_DEVICE_H_
#define MUMBA_HOST_MEDIA_CAPTURE_WEB_CONTENTS_VIDEO_CAPTURE_DEVICE_H_

#include <memory>
#include <string>

#include "base/logging.h"
#include "base/macros.h"
#include "base/memory/weak_ptr.h"
#include "core/host/media/capture/frame_sink_video_capture_device.h"
#include "core/shared/common/content_export.h"
#include "core/host/host_thread.h"

namespace host {

// Captures the displayed contents of a ApplicationContents, producing a stream of video
// frames.
//
// Generally, Create() is called with a device ID string that contains
// information necessary for finding a ApplicationContents instance. Thereafter, this
// capture device will capture from the frame sink corresponding to the main
// frame of the RenderFrameHost tree for that ApplicationContents instance. As the
// RenderFrameHost tree mutates (e.g., due to page navigations, crashes, or
// reloads), capture will continue without interruption.
class CONTENT_EXPORT ApplicationContentsVideoCaptureDevice
    : public FrameSinkVideoCaptureDevice,
      public base::SupportsWeakPtr<ApplicationContentsVideoCaptureDevice> {
 public:
  ApplicationContentsVideoCaptureDevice(int render_process_id,
                                int main_render_frame_id);
  ~ApplicationContentsVideoCaptureDevice() override;

  // Creates a ApplicationContentsVideoCaptureDevice instance from the given
  // |device_id|. Returns null if |device_id| is invalid.
  static std::unique_ptr<ApplicationContentsVideoCaptureDevice> Create(
      const std::string& device_id);

 private:
  // Monitors the ApplicationContents instance and notifies the base class any time the
  // frame sink or main render frame's view changes.
  class FrameTracker;

  // FrameSinkVideoCaptureDevice overrides: These increment/decrement the
  // ApplicationContents's capturer count, which causes the embedder to be notified.
  void WillStart() final;
  void DidStop() final;

  // A helper that runs on the UI thread to monitor changes to the
  // RenderFrameHost tree during the lifetime of a ApplicationContents instance, and
  // posts notifications back to update the target frame sink.
  const std::unique_ptr<FrameTracker, HostThread::DeleteOnUIThread> tracker_;

  DISALLOW_COPY_AND_ASSIGN(ApplicationContentsVideoCaptureDevice);
};

}  // namespace host

#endif  // MUMBA_HOST_MEDIA_CAPTURE_WEB_CONTENTS_VIDEO_CAPTURE_DEVICE_H_
