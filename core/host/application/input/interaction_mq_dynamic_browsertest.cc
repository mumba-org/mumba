// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/macros.h"
#include "base/strings/utf_string_conversions.h"
#include "build/build_config.h"
#include "core/host/application/application_window_host.h"
#include "core/host/web_contents.h"
#include "content/public/test/browser_test_utils.h"
#include "content/public/test/content_browser_test.h"
#include "content/public/test/content_browser_test_utils.h"
#include "content/public/test/test_utils.h"
#include "content/domain/browser/shell.h"
#include "ui/base/touch/touch_device.h"

namespace host {

namespace {

class InteractionMediaQueriesDynamicTest : public ContentBrowserTest {
 public:
  InteractionMediaQueriesDynamicTest() = default;
  ~InteractionMediaQueriesDynamicTest() override = default;
};

}  //  namespace

// Disable test on Android ASAN bot: crbug.com/807420
#if defined(OS_WIN) || defined(OS_LINUX) || \
    (defined(OS_ANDROID) && !defined(ADDRESS_SANITIZER))
IN_PROC_BROWSER_TEST_F(InteractionMediaQueriesDynamicTest,
                       PointerMediaQueriesDynamic) {
  RenderViewHost* rvh = shell()->web_contents()->GetRenderViewHost();
  ui::SetAvailablePointerAndHoverTypesForTesting(ui::POINTER_TYPE_NONE,
                                                 ui::HOVER_TYPE_NONE);
  rvh->OnWebkitPreferencesChanged();

  GURL test_url = GetTestUrl("", "interaction-mq-dynamic.html");
  const base::string16 kSuccessTitle(base::ASCIIToUTF16("SUCCESS"));
  TitleWatcher title_watcher(shell()->web_contents(), kSuccessTitle);
  NavigateToURL(shell(), test_url);

  ui::SetAvailablePointerAndHoverTypesForTesting(ui::POINTER_TYPE_COARSE,
                                                 ui::HOVER_TYPE_HOVER);
  rvh->OnWebkitPreferencesChanged();
  EXPECT_EQ(kSuccessTitle, title_watcher.WaitAndGetTitle());
}
#endif

}  //  namespace host
