// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/ui/top_container_view.h"

#include "core/host/ui/dock_frame.h"
#include "core/host/ui/dock_window.h"
#include "core/host/ui/tablist/tablist.h"
//#include "core/host/ui/immersive_mode_controller.h"
#include "ui/views/paint_info.h"

namespace host {

TopContainerView::TopContainerView(DockWindow* dock_window)
    : dock_window_(dock_window) {
}

TopContainerView::~TopContainerView() {
  // just to silent "unused private field" error from compiler
  dock_window_ = nullptr;
}

const char* TopContainerView::GetClassName() const {
  return "TopContainerView";
}

void TopContainerView::PaintChildren(const views::PaintInfo& paint_info) {
  // if (dock_window_->immersive_mode_controller()->IsRevealed()) {
  //   // Top-views depend on parts of the frame (themes, window title, window
  //   // controls) being painted underneath them. Clip rect has already been set
  //   // to the bounds of this view, so just paint the frame.  Use a clone without
  //   // invalidation info, as we're painting something outside of the normal
  //   // parent-child relationship, so invalidations are no longer in the correct
  //   // space to compare.
  //   ui::PaintContext context(paint_info.context(),
  //                            ui::PaintContext::CLONE_WITHOUT_INVALIDATION);

  //   // Since TopContainerView is not an ancestor of BrowserFrameView, it is not
  //   // responsible for its painting. To call paint on BrowserFrameView, we need
  //   // to generate a new PaintInfo that shares a DisplayItemList with
  //   // TopContainerView.
  //   dock_window_->frame()->GetFrameView()->Paint(
  //       views::PaintInfo::CreateRootPaintInfo(
  //           context, dock_window_->frame()->GetFrameView()->size()));
  // }
  View::PaintChildren(paint_info);
}

void TopContainerView::ChildPreferredSizeChanged(views::View* child) {
  PreferredSizeChanged();
}

}
