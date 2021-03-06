// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_UI_VIEWS_SAD_TAB_VIEW_H_
#define CHROME_BROWSER_UI_VIEWS_SAD_TAB_VIEW_H_

#include "core/host/ui/tablist/sad_tab.h"
#include "ui/views/controls/button/button.h"
#include "ui/views/controls/link_listener.h"
#include "ui/views/controls/styled_label.h"
#include "ui/views/controls/styled_label_listener.h"
#include "ui/views/view.h"

namespace views {
class Label;
class LabelButton;
}  // namespace views

namespace test {
class SadTabViewTestApi;
}

namespace host {
class ApplicationContents;
class ApplicationView;
///////////////////////////////////////////////////////////////////////////////
//
// SadTabView
//
//  A views::View subclass used to render the presentation of the crashed
//  "sad tab" in the browser window when a renderer is destroyed unnaturally.
//
///////////////////////////////////////////////////////////////////////////////
class SadTabView : public SadTab,
                   public views::View,
                   public views::LinkListener,
                   public views::ButtonListener {
 public:
  static const char kViewClassName[];

  SadTabView(ApplicationContents* app_contents, SadTabKind kind);
  ~SadTabView() override;

  // Overridden from SadTab:
  void ReinstallInApplicationView() override;

  // Overridden from views::View:
  void Layout() override;
  const char* GetClassName() const override;

  // Overridden from views::LinkListener:
  void LinkClicked(views::Link* source, int event_flags) override;

  // Overridden from views::ButtonListener:
  void ButtonPressed(views::Button* source, const ui::Event& event) override;

 protected:
  // Overridden from views::View:
  void OnPaint(gfx::Canvas* canvas) override;
  void RemovedFromWidget() override;

 private:
  friend class test::SadTabViewTestApi;

  // Set this View as the crashed overlay view for the WebView associated
  // with this object's WebContents.
  void AttachToApplicationView();

  bool painted_ = false;
  views::Label* message_;
  std::vector<views::Label*> bullet_labels_;
  views::Link* help_link_;
  views::LabelButton* action_button_;
  views::Label* title_;
  ApplicationView* owner_ = nullptr;

  DISALLOW_COPY_AND_ASSIGN(SadTabView);
};

}

#endif  // CHROME_BROWSER_UI_VIEWS_SAD_TAB_VIEW_H__
