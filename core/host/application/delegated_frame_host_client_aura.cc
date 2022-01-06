// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/application/delegated_frame_host_client_aura.h"

#include "base/files/file_util.h"
#include "core/host/application/application_window_host.h"
#include "core/host/application/application_window_host_view_aura.h"
//#include "core/common/view_messages.h"
#include "ui/aura/window.h"
#include "ui/aura/window_event_dispatcher.h"
#include "ui/aura/window_tree_host.h"
#include "ui/compositor/layer.h"
#include "ui/gfx/image/image_util.h"
#include "ui/gfx/image/image.h"

namespace host {

namespace {

// void FirstSurfaceBitmap(const SkBitmap& screenshot_bmp) {
//   size_t byte_size = screenshot_bmp.computeByteSize();
//   DLOG(INFO) << "\n\n\n\n**** DelegatedFrameHostClientAura: first surface bitmap received. w: " << screenshot_bmp.width() << " h: " << screenshot_bmp.height() << " empty? " << screenshot_bmp.empty() << "size: " << byte_size;
//   if (screenshot_bmp.empty()) {
//     DLOG(ERROR) << "DelegatedFrameHostClientAura: the given bitmap is empty, so we are not saving to a jpeg";
//     return;
//   }
//   std::vector<unsigned char> jpeg_data;
//   gfx::Image image = gfx::Image::CreateFrom1xBitmap(screenshot_bmp);
//   if (!gfx::JPEG1xEncodedDataFromImage(image,
//                                   100,
//                                   &jpeg_data)) {
//     DLOG(ERROR) << "DelegatedFrameHostClientAura: failed to encode bitmap to jpeg";
//   }
//   base::FilePath path("/home/fabiok/Pictures/mumba_screenshot.jpg");
//   int r = base::WriteFile(path, reinterpret_cast<char *>(jpeg_data.data()), jpeg_data.size());
//   if (r == jpeg_data.size()) {
//     DLOG(INFO) << "DelegatedFrameHostClientAura: screenshot saved successfully on " << path;  
//   } else if (r == -1) {
//     DLOG(ERROR) << "DelegatedFrameHostClientAura: failed while writing " << path; 
//   } else {
//     DLOG(ERROR) << "DelegatedFrameHostClientAura: size mismatch: ask to save " << jpeg_data.size() << " but wrote " << r << " instead on " << path; 
//   }
// }

}

DelegatedFrameHostClientAura::DelegatedFrameHostClientAura(
    ApplicationWindowHostViewAura* application_window_host_view)
    : application_window_host_view_(application_window_host_view) {}

DelegatedFrameHostClientAura::~DelegatedFrameHostClientAura() {}

ui::Layer* DelegatedFrameHostClientAura::DelegatedFrameHostGetLayer() const {
  return application_window_host_view_->window_->layer();
}

bool DelegatedFrameHostClientAura::DelegatedFrameHostIsVisible() const {
  return !application_window_host_view_->host_->is_hidden();
}

SkColor DelegatedFrameHostClientAura::DelegatedFrameHostGetGutterColor() const {
  // When making an element on the page fullscreen the element's background
  // may not match the page's, so use black as the gutter color to avoid
  // flashes of brighter colors during the transition.
  if (application_window_host_view_->host_->delegate() &&
      application_window_host_view_->host_->delegate()
          ->IsFullscreen()) {
    return SK_ColorBLACK;
  }
  if (application_window_host_view_->GetBackgroundColor())
    return *application_window_host_view_->GetBackgroundColor();
  return SK_ColorWHITE;
}

bool DelegatedFrameHostClientAura::DelegatedFrameCanCreateResizeLock() const {
#if !defined(OS_CHROMEOS)
  // On Windows and Linux, holding pointer moves will not help throttling
  // resizes.
  // TODO(piman): on Windows we need to block (nested run loop?) the
  // WM_SIZE event. On Linux we need to throttle at the WM level using
  // _NET_WM_SYNC_REQUEST.
  return false;
#else
  if (!application_window_host_view_->host_->renderer_initialized() ||
      application_window_host_view_->host_->auto_resize_enabled()) {
    return false;
  }
  return true;
#endif
}

std::unique_ptr<CompositorResizeLock>
DelegatedFrameHostClientAura::DelegatedFrameHostCreateResizeLock() {
  // Pointer moves are released when the CompositorResizeLock ends.
  auto* host = application_window_host_view_->window_->GetHost();
  host->dispatcher()->HoldPointerMoves();

  gfx::Size desired_size = application_window_host_view_->window_->bounds().size();
  return std::make_unique<CompositorResizeLock>(this, desired_size);
}

void DelegatedFrameHostClientAura::OnFirstSurfaceActivation(
    const viz::SurfaceInfo& surface_info) {
  //gfx::Size renderered_size = application_window_host_view_->window_->bounds().size();
  // NOTE: this is supposed to be a temporary test. remove..
  //application_window_host_view_->CopyFromSurface(
  //  gfx::Rect(renderered_size), 
  //  renderered_size,
  //  base::BindOnce(&FirstSurfaceBitmap));
}

void DelegatedFrameHostClientAura::OnBeginFrame(base::TimeTicks frame_time) {
  application_window_host_view_->OnBeginFrame(frame_time);
}

bool DelegatedFrameHostClientAura::IsAutoResizeEnabled() const {
  return application_window_host_view_->host_->auto_resize_enabled();
}

void DelegatedFrameHostClientAura::OnFrameTokenChanged(uint32_t frame_token) {
  application_window_host_view_->OnFrameTokenChangedForView(frame_token);
}

std::unique_ptr<ui::CompositorLock>
DelegatedFrameHostClientAura::GetCompositorLock(
    ui::CompositorLockClient* client) {
  auto* window_host = application_window_host_view_->window_->GetHost();
  return window_host->compositor()->GetCompositorLock(client);
}

void DelegatedFrameHostClientAura::CompositorResizeLockEnded() {
  auto* window_host = application_window_host_view_->window_->GetHost();
  window_host->dispatcher()->ReleasePointerMoves();
  application_window_host_view_->host_->SynchronizeVisualProperties();
}

void DelegatedFrameHostClientAura::DidReceiveFirstFrameAfterNavigation() {
  application_window_host_view_->host_->DidReceiveFirstFrameAfterNavigation();
}

}  // namespace host
