// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_UI_APPLICATION_CONTENTS_SET_BACKGROUND_COLOR_H_
#define MUMBA_HOST_UI_APPLICATION_CONTENTS_SET_BACKGROUND_COLOR_H_

#include "core/host/application/application_contents_observer.h"
#include "core/host/application/application_contents_user_data.h"
#include "core/shared/common/content_export.h"

// Defined in SkColor.h (32-bit ARGB color).
using SkColor = unsigned int;

namespace host {

// Ensures that the background color of a given WebContents instance is always
// set to a given color value.
class ApplicationContentsSetBackgroundColor
    : public ApplicationContentsObserver,
      public ApplicationContentsUserData<ApplicationContentsSetBackgroundColor> {
 public:
  CONTENT_EXPORT static void CreateForApplicationContentsWithColor(
      ApplicationContents* app_contents,
      SkColor color);

  ~ApplicationContentsSetBackgroundColor() override;

 private:
  ApplicationContentsSetBackgroundColor(
    ApplicationContents* app_contents,
    SkColor color);

  // ApplicationContentsObserver:
  void ApplicationWindowReady() override;
  void ApplicationWindowCreated(ApplicationWindowHost* render_view_host) override;
  void ApplicationWindowChanged(ApplicationWindowHost* old_host,
                                ApplicationWindowHost* new_host) override;

  SkColor color_;

  DISALLOW_COPY_AND_ASSIGN(ApplicationContentsSetBackgroundColor);
};

}  // namespace views

#endif  // UI_VIEWS_CONTROLS_WEBVIEW_WEB_CONTENTS_SET_BACKGROUND_COLOR_H_
