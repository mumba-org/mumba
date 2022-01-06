// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/ui/tablist/core_tab_helper_delegate.h"

#include "core/host/application/application_contents.h"

namespace host {

CoreTabHelperDelegate::~CoreTabHelperDelegate() {
}

std::unique_ptr<ApplicationContents> CoreTabHelperDelegate::SwapTabContents(
    ApplicationContents* old_contents,
    std::unique_ptr<ApplicationContents> new_contents,
    bool did_start_load,
    bool did_finish_load) {
  return nullptr;
}

bool CoreTabHelperDelegate::CanReloadContents(
    ApplicationContents* app_contents) const {
  return true;
}

bool CoreTabHelperDelegate::CanSaveContents(
    ApplicationContents* app_contents) const {
  return true;
}

}