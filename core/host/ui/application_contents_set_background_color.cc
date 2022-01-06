// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/ui/application_contents_set_background_color.h"

#include "base/memory/ptr_util.h"
#include "core/host/application/application_window_host.h"

DEFINE_WEB_CONTENTS_USER_DATA_KEY(host::ApplicationContentsSetBackgroundColor);

namespace host {

// static
void ApplicationContentsSetBackgroundColor::CreateForApplicationContentsWithColor(
    ApplicationContents* app_contents,
    SkColor color) {
  if (FromApplicationContents(app_contents))
    return;

  // SupportsUserData::Data takes ownership over the
  // ApplicationContentsSetBackgroundColor instance and will destroy it when the
  // WebContents instance is destroyed.
  app_contents->SetUserData(
      UserDataKey(),
      base::WrapUnique(new ApplicationContentsSetBackgroundColor(app_contents, color)));
}

ApplicationContentsSetBackgroundColor::ApplicationContentsSetBackgroundColor(
    ApplicationContents* app_contents,
    SkColor color)
    : ApplicationContentsObserver(app_contents), color_(color) {

  DLOG(INFO) << "ApplicationContentsSetBackgroundColor: " << this;
}

ApplicationContentsSetBackgroundColor::~ApplicationContentsSetBackgroundColor() {
  //DLOG(INFO) << "~ApplicationContentsSetBackgroundColor: " << this;
}

void ApplicationContentsSetBackgroundColor::ApplicationWindowReady() {
  application_contents()
      ->GetApplicationWindowHost()
      ->GetView()
      ->SetBackgroundColor(color_);
}

void ApplicationContentsSetBackgroundColor::ApplicationWindowCreated(
    ApplicationWindowHost* app_dock_window) {
  app_dock_window->GetView()->SetBackgroundColor(color_);
}

void ApplicationContentsSetBackgroundColor::ApplicationWindowChanged(
    ApplicationWindowHost* old_host,
    ApplicationWindowHost* new_host) {
  new_host->GetView()->SetBackgroundColor(color_);
}

}  // namespace views
