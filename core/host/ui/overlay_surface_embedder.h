// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_BROWSER_PICTURE_IN_PICTURE_OVERLAY_SURFACE_EMBEDDER_H_
#define CONTENT_BROWSER_PICTURE_IN_PICTURE_OVERLAY_SURFACE_EMBEDDER_H_

#include <memory>

#include "core/host/ui/overlay_window.h"

namespace viz {
class SurfaceId;
}

namespace host {

// Embed a surface into the OverlayWindow to show content. Responsible for
// setting up the surface layers that contain content to show on the
// OverlayWindow.
class OverlaySurfaceEmbedder {
 public:
  explicit OverlaySurfaceEmbedder(OverlayWindow* window);
  ~OverlaySurfaceEmbedder();

  void SetPrimarySurfaceId(const viz::SurfaceId& surface_id);
  void UpdateLayerBounds();
  void AddControlsLayers();

 private:
  // The window which embeds the client. Weak pointer since the
  // PictureInPictureWindowController owns the window.
  OverlayWindow* window_;

  // Contains the client's content.
  std::unique_ptr<ui::Layer> surface_layer_;

  // Owned by the OverlayWindow implementation.
  ui::Layer* video_layer_ = nullptr;
  ui::Layer* close_controls_layer_ = nullptr;
  ui::Layer* play_pause_controls_layer_ = nullptr;

  DISALLOW_COPY_AND_ASSIGN(OverlaySurfaceEmbedder);
};

}  // namespace host

#endif  // CONTENT_BROWSER_PICTURE_IN_PICTURE_OVERLAY_SURFACE_EMBEDDER_H_
