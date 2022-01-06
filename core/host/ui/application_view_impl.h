// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_UI_APPLICATION_VIEW_IMPL_H_
#define MUMBA_HOST_UI_APPLICATION_VIEW_IMPL_H_

#include <memory>

#include "base/compiler_specific.h"
#include "base/macros.h"
#include "core/host/ui/application_contents_close_handler_delegate.h"
#include "core/host/ui/application_view.h"

//class StatusBubbleViews;

namespace ui {
class LayerTreeOwner;
}

namespace host {
//class Application;

// ContentsWebView is used to present the WebContents of the active tab.
class ApplicationViewImpl
    : public ApplicationView,
      public ApplicationContentsCloseHandlerDelegate {
 public:
  explicit ApplicationViewImpl();//Application* application);//content::BrowserContext* browser_context);
  ~ApplicationViewImpl() override;

  // Sets the status bubble, which should be repositioned every time
  // this view changes visible bounds.
//  void SetStatusBubble(StatusBubbleViews* status_bubble);

  // WebView overrides:
  bool GetNeedsNotificationWhenVisibleBoundsChange() const override;
  void OnVisibleBoundsChanged() override;
  void ViewHierarchyChanged(
      const ViewHierarchyChangedDetails& details) override;
  void OnThemeChanged() override;
  void ApplicationWindowReady() override;
  void OnLetterboxingChanged() override;

  // ui::View overrides:
  std::unique_ptr<ui::Layer> RecreateLayer() override;

  // WebContentsCloseHandlerDelegate overrides:
  void CloneApplicationContentsLayer() override;
  void DestroyClonedLayer() override;

 private:
  void UpdateBackgroundColor();
  
  //StatusBubbleViews* status_bubble_;

  std::unique_ptr<ui::LayerTreeOwner> cloned_layer_tree_;

  DISALLOW_COPY_AND_ASSIGN(ApplicationViewImpl);
};

}

#endif  // CHROME_BROWSER_UI_VIEWS_FRAME_CONTENTS_WEB_VIEW_H_
