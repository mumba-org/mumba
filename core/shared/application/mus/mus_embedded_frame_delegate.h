// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_RENDERER_MUS_MUS_EMBEDDED_FRAME_DELEGATE_H_
#define CONTENT_RENDERER_MUS_MUS_EMBEDDED_FRAME_DELEGATE_H_

namespace viz {
class FrameSinkId;
class SurfaceInfo;
}  // namespace viz

namespace application {

class MusEmbeddedFrameDelegate {
 public:
  // Called when the SurfaceInfo changes.
  virtual void OnMusEmbeddedFrameSurfaceChanged(
      const viz::SurfaceInfo& surface_info) = 0;

  // Called when mus determines the FrameSinkId.
  virtual void OnMusEmbeddedFrameSinkIdAllocated(
      const viz::FrameSinkId& frame_sink_id) = 0;

 protected:
  virtual ~MusEmbeddedFrameDelegate() {}
};

}  // namespace application

#endif  // CONTENT_RENDERER_MUS_MUS_EMBEDDED_FRAME_DELEGATE_H_
