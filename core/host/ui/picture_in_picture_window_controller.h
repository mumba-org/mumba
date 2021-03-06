// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_PUBLIC_BROWSER_PICTURE_IN_PICTURE_WINDOW_CONTROLLER_H_
#define CONTENT_PUBLIC_BROWSER_PICTURE_IN_PICTURE_WINDOW_CONTROLLER_H_

#include "core/shared/common/content_export.h"

namespace gfx {
class Size;
}  // namespace gfx

namespace viz {
class SurfaceId;
}  // namespace viz

namespace host {
class OverlayWindow;
class ApplicationContents;

// Interface for Picture in Picture window controllers. This is currently tied
// to a WebContents |initiator| and created when a Picture in Picture window is
// to be shown. This allows creation of a single window for the initiator
// WebContents.
class PictureInPictureWindowController {
 public:
  // Gets a reference to the controller associated with |initiator| and creates
  // one if it does not exist. The returned pointer is guaranteed to be
  // non-null.
  CONTENT_EXPORT static PictureInPictureWindowController*
  GetOrCreateForApplicationContents(ApplicationContents* initiator);

  virtual ~PictureInPictureWindowController() = default;

  virtual void Show() = 0;
  virtual void Close() = 0;
  virtual void EmbedSurface(const viz::SurfaceId& surface_id,
                            const gfx::Size& natural_size) = 0;
  virtual OverlayWindow* GetWindowForTesting() = 0;
  virtual void UpdateLayerBounds() = 0;

  // Commands.
  // Returns true if the player is active (i.e. currently playing) after this
  // call.
  virtual bool TogglePlayPause() = 0;

 protected:
  // Use PictureInPictureWindowController::GetOrCreateForWebContents() to
  // create an instance.
  PictureInPictureWindowController() = default;
};

}  // namespace host

#endif  // CONTENT_PUBLIC_BROWSER_PICTURE_IN_PICTURE_WINDOW_CONTROLLER_H_
