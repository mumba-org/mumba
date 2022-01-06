// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/ui/exclusive_access/fullscreen_within_tab_helper.h"

DEFINE_WEB_CONTENTS_USER_DATA_KEY(host::FullscreenWithinTabHelper);

namespace host {

FullscreenWithinTabHelper::FullscreenWithinTabHelper(
    ApplicationContents* ignored)
    : is_fullscreen_within_tab_(false) {}

FullscreenWithinTabHelper::~FullscreenWithinTabHelper() {}

// static
void FullscreenWithinTabHelper::RemoveForApplicationContents(
    ApplicationContents* app_contents) {
  DCHECK(app_contents);
  app_contents->RemoveUserData(UserDataKey());
}

}