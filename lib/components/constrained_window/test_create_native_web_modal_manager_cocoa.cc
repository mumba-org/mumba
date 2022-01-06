// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "components/web_modal/application_contents_modal_dialog_manager.h"

namespace web_modal {

SingleApplicationContentsDialogManager*
ApplicationContentsModalDialogManager::CreateNativeWebModalManager(
    gfx::NativeWindow dialog,
    web_modal::SingleApplicationContentsDialogManagerDelegate* delegate) {
  return nullptr;
}

}  // namespace web_modal
