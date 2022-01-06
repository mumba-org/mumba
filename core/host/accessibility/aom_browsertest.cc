// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/logging.h"
#include "core/host/accessibility/browser_accessibility.h"
#include "core/host/accessibility/browser_accessibility_manager.h"
#include "core/host/application/application_contents.h"
#include "core/common/content_switches.h"
#include "core/public/test/browser_test_utils.h"
#include "core/public/test/content_browser_test.h"
#include "core/public/test/content_browser_test_utils.h"
#include "core/public/test/test_utils.h"
#include "core/domain/browser/shell.h"
#include "core/test/accessibility_browser_test_utils.h"
#include "net/base/data_url.h"
#include "net/test/embedded_test_server/embedded_test_server.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/gurl.h"

namespace host {

namespace {

class AccessibilityObjectModelBrowserTest : public ContentBrowserTest {
 public:
  AccessibilityObjectModelBrowserTest() {}
  ~AccessibilityObjectModelBrowserTest() override {}

  void SetUpCommandLine(base::CommandLine* command_line) override {
    ContentBrowserTest::SetUpCommandLine(command_line);
    base::CommandLine::ForCurrentProcess()->AppendSwitchASCII(
        switches::kEnableBlinkFeatures, "AccessibilityObjectModel");
  }

 protected:
  BrowserAccessibility* FindNode(ax::mojom::Role role,
                                 const std::string& name) {
    BrowserAccessibility* root = GetManager()->GetRoot();
    CHECK(root);
    return FindNodeInSubtree(*root, role, name);
  }

  BrowserAccessibilityManager* GetManager() {
    ApplicationContents* application_contents =
        static_cast<ApplicationContents*>(shell()->application_contents());
    return application_contents->GetRootBrowserAccessibilityManager();
  }

 private:
  BrowserAccessibility* FindNodeInSubtree(BrowserAccessibility& node,
                                          ax::mojom::Role role,
                                          const std::string& name) {
    if (node.GetRole() == role &&
        node.GetStringAttribute(ax::mojom::StringAttribute::kName) == name)
      return &node;
    for (unsigned int i = 0; i < node.PlatformChildCount(); ++i) {
      BrowserAccessibility* result =
          FindNodeInSubtree(*node.PlatformGetChild(i), role, name);
      if (result)
        return result;
    }
    return nullptr;
  }
};

}  // namespace

IN_PROC_BROWSER_TEST_F(AccessibilityObjectModelBrowserTest,
                       EventListenerOnVirtualNode) {
  ASSERT_TRUE(embedded_test_server()->Start());
  NavigateToURL(shell(), GURL(url::kAboutBlankURL));

  AccessibilityNotificationWaiter waiter(shell()->application_contents(),
                                         ui::kAXModeComplete,
                                         ax::mojom::Event::kLoadComplete);
  GURL url(embedded_test_server()->GetURL(
      "/accessibility/aom/event-listener-on-virtual-node.html"));
  NavigateToURL(shell(), url);
  waiter.WaitForNotification();

  BrowserAccessibility* button = FindNode(ax::mojom::Role::kButton, "FocusMe");
  ASSERT_NE(nullptr, button);

  BrowserAccessibility* link = FindNode(ax::mojom::Role::kLink, "ClickMe");
  ASSERT_NE(nullptr, link);

  AccessibilityNotificationWaiter waiter2(
      shell()->application_contents(), ui::kAXModeComplete, ax::mojom::Event::kFocus);
  GetManager()->DoDefaultAction(*link);
  waiter2.WaitForNotification();

  BrowserAccessibility* focus = GetManager()->GetFocus();
  EXPECT_EQ(focus->GetId(), button->GetId());
}

}  // namespace host
