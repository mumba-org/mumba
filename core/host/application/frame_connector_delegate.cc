// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/application/frame_connector_delegate.h"

#include "core/host/application/application_window_host.h"
#include "core/host/application/application_window_host_view_child_frame.h"
//#include "core/shared/common/content_switches_internal.h"
#include "core/shared/common/visual_properties.h"

namespace host {

void FrameConnectorDelegate::SetView(ApplicationWindowHostViewChildFrame* view) {
  view_ = view;
}

ApplicationWindowHostView*
FrameConnectorDelegate::GetParentApplicationWindowHostView() {
  return nullptr;
}

ApplicationWindowHostView*
FrameConnectorDelegate::GetRootApplicationWindowHostView() {
  return nullptr;
}

void FrameConnectorDelegate::SynchronizeVisualProperties(
    const viz::SurfaceId& surface_id,
    const common::VisualProperties& resize_params) {
  DLOG(INFO) << "FrameConnectorDelegate::SynchronizeVisualProperties";
  screen_info_ = resize_params.screen_info;
  local_surface_id_ = surface_id.local_surface_id();
  capture_sequence_number_ = resize_params.capture_sequence_number;

  //SetScreenSpaceRect(resize_params.screen_space_rect);
  //SetLocalFrameSize(resize_params.local_frame_size);
  // TODO: see if thwy match the expectations
  SetScreenSpaceRect(gfx::Rect(resize_params.compositor_viewport_pixel_size));
  SetLocalFrameSize(resize_params.new_size);

  if (!view_)
    return;
#if defined(USE_AURA)
  view_->SetFrameSinkId(surface_id.frame_sink_id());
#endif  // defined(USE_AURA)

  ApplicationWindowHost* application_window_host = view_->host();
  DCHECK(application_window_host);

  application_window_host->SetAutoResize(resize_params.auto_resize_enabled,
                                    resize_params.min_size_for_auto_resize,
                                    resize_params.max_size_for_auto_resize);

  application_window_host->SynchronizeVisualProperties();
}

gfx::PointF FrameConnectorDelegate::TransformPointToRootCoordSpace(
    const gfx::PointF& point,
    const viz::SurfaceId& surface_id) {
  return gfx::PointF();
}

bool FrameConnectorDelegate::TransformPointToLocalCoordSpaceLegacy(
    const gfx::PointF& point,
    const viz::SurfaceId& original_surface,
    const viz::SurfaceId& local_surface_id,
    gfx::PointF* transformed_point) {
  return false;
}

bool FrameConnectorDelegate::TransformPointToCoordSpaceForView(
    const gfx::PointF& point,
    ApplicationWindowHostView* target_view,
    const viz::SurfaceId& local_surface_id,
    gfx::PointF* transformed_point) {
  return false;
}

bool FrameConnectorDelegate::HasFocus() {
  return false;
}

bool FrameConnectorDelegate::LockMouse() {
  return false;
}

void FrameConnectorDelegate::EnableAutoResize(const gfx::Size& min_size,
                                              const gfx::Size& max_size) {}

void FrameConnectorDelegate::DisableAutoResize() {}

bool FrameConnectorDelegate::IsInert() const {
  return false;
}

cc::TouchAction FrameConnectorDelegate::InheritedEffectiveTouchAction() const {
  return cc::TouchAction::kTouchActionAuto;
}

bool FrameConnectorDelegate::IsHidden() const {
  return false;
}

bool FrameConnectorDelegate::IsThrottled() const {
  return false;
}

bool FrameConnectorDelegate::IsSubtreeThrottled() const {
  return false;
}

void FrameConnectorDelegate::SetLocalFrameSize(
    const gfx::Size& local_frame_size) {
  has_size_ = true;
  if (use_zoom_for_device_scale_factor_) {
    local_frame_size_in_pixels_ = local_frame_size;
    local_frame_size_in_dip_ = gfx::ScaleToRoundedSize(
        local_frame_size, 1.f / screen_info_.device_scale_factor);
  } else {
    local_frame_size_in_dip_ = local_frame_size;
    local_frame_size_in_pixels_ = gfx::ScaleToCeiledSize(
        local_frame_size, screen_info_.device_scale_factor);
  }
}

void FrameConnectorDelegate::SetScreenSpaceRect(
    const gfx::Rect& screen_space_rect) {
  if (use_zoom_for_device_scale_factor_) {
    screen_space_rect_in_pixels_ = screen_space_rect;
    screen_space_rect_in_dip_ = gfx::Rect(
        gfx::ScaleToFlooredPoint(screen_space_rect.origin(),
                                 1.f / screen_info_.device_scale_factor),
        gfx::ScaleToCeiledSize(screen_space_rect.size(),
                               1.f / screen_info_.device_scale_factor));
  } else {
    screen_space_rect_in_dip_ = screen_space_rect;
    screen_space_rect_in_pixels_ = gfx::ScaleToEnclosingRect(
        screen_space_rect, screen_info_.device_scale_factor);
  }
}

FrameConnectorDelegate::FrameConnectorDelegate(
    bool use_zoom_for_device_scale_factor)
    : use_zoom_for_device_scale_factor_(use_zoom_for_device_scale_factor) {}

}  // namespace host
