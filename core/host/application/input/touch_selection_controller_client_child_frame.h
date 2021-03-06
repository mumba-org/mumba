// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_APPLICATION_INPUT_TOUCH_SELECTION_CONTROLLER_CLIENT_CHILD_FRAME_H_
#define MUMBA_HOST_APPLICATION_INPUT_TOUCH_SELECTION_CONTROLLER_CLIENT_CHILD_FRAME_H_

#include "base/macros.h"
#include "components/viz/common/quads/selection.h"
#include "core/shared/common/content_export.h"
#include "ui/touch_selection/touch_selection_controller.h"
#include "ui/touch_selection/touch_selection_menu_runner.h"

namespace host {
class ApplicationWindowHostViewChildFrame;
class TouchSelectionControllerClientManager;

// An implementation of |TouchSelectionControllerClient| to be used by
// implementations of TouchSelectionControllerClientManager. This class serves
// cross-process iframes, which have different renderers than the main frame,
// and thus have their own ApplicationWindowHostViewChildFrames. Since a
// TouchSelectionControllerClient is intended to bind these views to the
// TouchSelectionController, we need a different implementation for
// cross-process subframes.
class CONTENT_EXPORT TouchSelectionControllerClientChildFrame
    : public ui::TouchSelectionControllerClient,
      public ui::TouchSelectionMenuClient {
 public:
  TouchSelectionControllerClientChildFrame(
      ApplicationWindowHostViewChildFrame* rwhv,
      TouchSelectionControllerClientManager* manager);
  ~TouchSelectionControllerClientChildFrame() override;

  void DidStopFlinging();
  void UpdateSelectionBoundsIfNeeded(
      const viz::Selection<gfx::SelectionBound>& selection,
      float device_scale_factor);

 private:
  // ui::TouchSelectionControllerClient:
  bool SupportsAnimation() const override;
  void SetNeedsAnimate() override;
  void MoveCaret(const gfx::PointF& position) override;
  void MoveRangeSelectionExtent(const gfx::PointF& extent) override;
  void SelectBetweenCoordinates(const gfx::PointF& base,
                                const gfx::PointF& extent) override;
  void OnSelectionEvent(ui::SelectionEventType event) override;
  void OnDragUpdate(const gfx::PointF& position) override;
  std::unique_ptr<ui::TouchHandleDrawable> CreateDrawable() override;
  void DidScroll() override;

  // ui::TouchSelectionMenuClient:
  bool IsCommandIdEnabled(int command_id) const override;
  void ExecuteCommand(int command_id, int event_flags) override;
  void RunContextMenu() override;

  gfx::Point ConvertFromRoot(const gfx::PointF& point) const;

  // Not owned, non-null for the lifetime of this object.
  ApplicationWindowHostViewChildFrame* rwhv_;
  TouchSelectionControllerClientManager* manager_;

  // The last selection bounds reported by the view.
  gfx::SelectionBound selection_start_;
  gfx::SelectionBound selection_end_;
  // Keep track of the view origin as of the last time selection was updated.
  gfx::PointF view_origin_at_last_update_;

  DISALLOW_COPY_AND_ASSIGN(TouchSelectionControllerClientChildFrame);
};

}  // namespace host
#endif  // MUMBA_HOST_APPLICATION_INPUT_TOUCH_SELECTION_CONTROLLER_CLIENT_CHILD_FRAME_H_
