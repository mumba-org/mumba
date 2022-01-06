// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/ui/application_view_impl.h"

#include "core/host/themes/theme_properties.h"
//#include "core/host/ui/status_bubble_views.h"
#include "core/host/application/application_window_host.h"
#include "core/host/application/application_contents.h"
#include "core/host/ui/tablist/sad_tab_helper.h"
#include "ui/base/theme_provider.h"
#include "ui/compositor/layer_tree_owner.h"
#include "ui/views/background.h"

#if defined(USE_AURA)
#include "ui/aura/window.h"
#include "ui/wm/core/window_util.h"
#endif

namespace host {

ApplicationViewImpl::ApplicationViewImpl()//Application* application)
    : ApplicationView() {//,
      //status_bubble_(nullptr) {
}

ApplicationViewImpl::~ApplicationViewImpl() {

}

//void ApplicationView::SetStatusBubble(StatusBubbleViews* status_bubble) {
//  status_bubble_ = status_bubble;
//  DCHECK(!status_bubble_ || status_bubble_->base_view() == this);
//  if (status_bubble_)
//    status_bubble_->Reposition();
//}

bool ApplicationViewImpl::GetNeedsNotificationWhenVisibleBoundsChange() const {
  return true;
}

void ApplicationViewImpl::OnVisibleBoundsChanged() {
  //if (status_bubble_)
  //  status_bubble_->Reposition();
}

void ApplicationViewImpl::ViewHierarchyChanged(
    const ViewHierarchyChangedDetails& details) {
  ApplicationView::ViewHierarchyChanged(details);
  if (details.is_add)
    UpdateBackgroundColor();
}

void ApplicationViewImpl::OnThemeChanged() {
  UpdateBackgroundColor();
}

void ApplicationViewImpl::OnLetterboxingChanged() {
  UpdateBackgroundColor();
}

void ApplicationViewImpl::UpdateBackgroundColor() {
  const ui::ThemeProvider* const theme = GetThemeProvider();
  if (!theme)
    return;

  const SkColor ntp_background = color_utils::GetResultingPaintColor(
      theme->GetColor(ThemeProperties::COLOR_NTP_BACKGROUND), SK_ColorWHITE);
  
  if (is_letterboxing()) {
    // Set the background color to a dark tint of the new tab page's background
    // color.  This is the color filled within the WebView's bounds when its
    // child view is sized specially for fullscreen tab capture.  See WebView
    // header file comments for more details.
    const int kBackgroundBrightness = 0x33;  // 20%
    // Make sure the background is opaque.
    const SkColor dimmed_ntp_background = SkColorSetARGB(
        SkColorGetA(ntp_background),
        SkColorGetR(ntp_background) * kBackgroundBrightness / 0xFF,
        SkColorGetG(ntp_background) * kBackgroundBrightness / 0xFF,
        SkColorGetB(ntp_background) * kBackgroundBrightness / 0xFF);
    SetBackground(views::CreateSolidBackground(dimmed_ntp_background));
  } else {
    SetBackground(views::CreateSolidBackground(ntp_background));
  }
  // Changing a view's background does not necessarily schedule the view to be
  // redrawn.
  SchedulePaint();

  if (application_contents()) {
    SadTabHelper* sad_tab_helper = SadTabHelper::FromApplicationContents(application_contents());
    if (sad_tab_helper && sad_tab_helper->sad_tab()) {
      return;
    }
    ApplicationWindowHostView* awhv =
        application_contents()->GetApplicationWindowHostView();
    if (awhv)
     awhv->SetBackgroundColor(ntp_background);
  }
}

std::unique_ptr<ui::Layer> ApplicationViewImpl::RecreateLayer() {

  std::unique_ptr<ui::Layer> old_layer = View::RecreateLayer();

  if (cloned_layer_tree_ && old_layer) {
    // Our layer has been recreated and we have a clone of the WebContents
    // layer. Combined this means we're about to be destroyed and an animation
    // is in effect. The animation cloned our layer, but it won't create another
    // clone of the WebContents layer (|cloned_layer_tree_|). Another clone
    // is not created as the clone has no owner (see CloneChildren()). Because
    // we want the WebContents layer clone to be animated we move it to the
    // old_layer, which is the layer the animation happens on. This animation
    // ends up owning the layer (and all its descendants).
    old_layer->Add(cloned_layer_tree_->release());
    cloned_layer_tree_.reset();
  }

  return old_layer;
}

void ApplicationViewImpl::CloneApplicationContentsLayer() {
  if (!application_contents()) {
    return;
  }
#if defined(USE_AURA)
  // We don't need to clone the layers on non-Aura (Mac), because closing an
  // NSWindow does not animate.
  cloned_layer_tree_ = wm::RecreateLayers(application_contents()->GetNativeView());
#endif
  if (!cloned_layer_tree_ || !cloned_layer_tree_->root()) {
    cloned_layer_tree_.reset();
    return;
  }

  SetPaintToLayer();

  // The cloned layer is in a different coordinate system them our layer (which
  // is now the new parent of the cloned layer). Convert coordinates so that the
  // cloned layer appears at the right location.
  gfx::PointF origin;
  ui::Layer::ConvertPointToLayer(cloned_layer_tree_->root(), layer(), &origin);
  cloned_layer_tree_->root()->SetBounds(
      gfx::Rect(gfx::ToFlooredPoint(origin),
                cloned_layer_tree_->root()->bounds().size()));
 
  layer()->Add(cloned_layer_tree_->root());
}

void ApplicationViewImpl::DestroyClonedLayer() {
  cloned_layer_tree_.reset();
  DestroyLayer();
}

void ApplicationViewImpl::ApplicationWindowReady() {
  // Set the background color to be the theme's ntp background on startup.
  UpdateBackgroundColor();
  ApplicationView::ApplicationWindowReady();
}

}
