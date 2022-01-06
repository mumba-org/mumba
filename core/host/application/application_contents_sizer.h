// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_UI_WEB_CONTENTS_SIZER_H_
#define CHROME_BROWSER_UI_WEB_CONTENTS_SIZER_H_


namespace gfx {
class Rect;
}

namespace host {
class ApplicationContents;

// A platform-agnostic function to resize a ApplicationContents.
void ResizeApplicationContents(ApplicationContents* app_contents,
                               const gfx::Rect& bounds);

}

#endif  // CHROME_BROWSER_UI_WEB_CONTENTS_SIZER_H_
