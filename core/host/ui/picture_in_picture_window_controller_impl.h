// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_BROWSER_PICTURE_IN_PICTURE_PICTURE_IN_PICTURE_WINDOW_CONTROLLER_IMPL_H_
#define CONTENT_BROWSER_PICTURE_IN_PICTURE_PICTURE_IN_PICTURE_WINDOW_CONTROLLER_IMPL_H_

#include "base/memory/weak_ptr.h"
#include "components/viz/common/surfaces/parent_local_surface_id_allocator.h"
#include "core/host/ui/picture_in_picture_window_controller.h"
#include "core/host/application/application_contents_user_data.h"

namespace host {
class OverlaySurfaceEmbedder;
class ApplicationContents;

// TODO(thakis,mlamouri): PictureInPictureWindowControllerImpl isn't
// CONTENT_EXPORT'd because it creates complicated build issues with
// WebContentsUserData being a non-exported template. As a result, the class
// uses CONTENT_EXPORT for methods that are being used from tests.
// CONTENT_EXPORT should be moved back to the class when the Windows build will
// work with it. https://crbug.com/589840.
class PictureInPictureWindowControllerImpl
    : public PictureInPictureWindowController,
      public ApplicationContentsUserData<PictureInPictureWindowControllerImpl> {
 public:
  // Gets a reference to the controller associated with |initiator| and creates
  // one if it does not exist. The returned pointer is guaranteed to be
  // non-null.
  CONTENT_EXPORT static PictureInPictureWindowControllerImpl*
  GetOrCreateForApplicationContents(ApplicationContents* initiator);

  ~PictureInPictureWindowControllerImpl() override;

  // PictureInPictureWindowController:
  CONTENT_EXPORT void Show() override;
  CONTENT_EXPORT void Close() override;
  CONTENT_EXPORT void EmbedSurface(const viz::SurfaceId& surface_id,
                                   const gfx::Size& natural_size) override;
  CONTENT_EXPORT OverlayWindow* GetWindowForTesting() override;
  CONTENT_EXPORT void UpdateLayerBounds() override;
  CONTENT_EXPORT bool TogglePlayPause() override;

 private:
  friend class ApplicationContentsUserData<PictureInPictureWindowControllerImpl>;

  // Use PictureInPictureWindowControllerImpl::GetOrCreateForWebContents() to
  // create an instance.
  CONTENT_EXPORT explicit PictureInPictureWindowControllerImpl(
      ApplicationContents* initiator);

  std::unique_ptr<OverlayWindow> window_;
  std::unique_ptr<OverlaySurfaceEmbedder> embedder_;
  ApplicationContents* const initiator_;

  viz::SurfaceId surface_id_;

  DISALLOW_COPY_AND_ASSIGN(PictureInPictureWindowControllerImpl);
};

}  // namespace host

#endif  // CONTENT_BROWSER_PICTURE_IN_PICTURE_PICTURE_IN_PICTURE_WINDOW_CONTROLLER_IMPL_H_