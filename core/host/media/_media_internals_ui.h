// Copyright (c) 2011 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_MEDIA_MEDIA_INTERNALS_UI_H_
#define MUMBA_HOST_MEDIA_MEDIA_INTERNALS_UI_H_

#include "base/macros.h"
#include "core/host/web_ui_controller.h"

namespace host {

// The implementation for the chrome://media-internals page.
class MediaInternalsUI : public WebUIController {
 public:
  explicit MediaInternalsUI(WebUI* web_ui);

 private:
  DISALLOW_COPY_AND_ASSIGN(MediaInternalsUI);
};

}  // namespace host

#endif  // MUMBA_HOST_MEDIA_MEDIA_INTERNALS_UI_H_
