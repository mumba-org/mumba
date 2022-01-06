// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/logging.h"
#include "core/host/accessibility/browser_accessibility.h"
#include "core/host/accessibility/browser_accessibility_manager.h"
#include "core/host/application/application_contents.h"
#include "core/public/test/browser_test_utils.h"
#include "core/public/test/content_browser_test.h"
#include "core/public/test/content_browser_test_utils.h"
#include "core/domain/browser/shell.h"
#include "core/test/accessibility_browser_test_utils.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace host {

class AccessibilityFullscreenBrowserTest : public ContentBrowserTest {
 public:
  AccessibilityFullscreenBrowserTest() = default;
  ~AccessibilityFullscreenBrowserTest() override = default;

 protected:
  BrowserAccessibility* FindButton(BrowserAccessibility* node) {
    if (node->GetRole() == ax::mojom::Role::kButton)
      return node;
    for (unsigned i = 0; i < node->PlatformChildCount(); i++) {
      if (BrowserAccessibility* button = FindButton(node->PlatformGetChild(i)))
        return button;
    }
    return nullptr;
  }

  int CountLinks(BrowserAccessibility* node) {
    if (node->GetRole() == ax::mojom::Role::kLink)
      return 1;
    int links_in_children = 0;
    for (unsigned i = 0; i < node->PlatformChildCount(); i++) {
      links_in_children += CountLinks(node->PlatformGetChild(i));
    }
    return links_in_children;
  }
};

namespace {

// FakeFullscreenDelegate simply stores the latest requested mod and reports it
// back, which is all that is required for the renderer to enter fullscreen.
class FakeFullscreenDelegate : public WebContentsDelegate {
 public:
  FakeFullscreenDelegate() = default;
  ~FakeFullscreenDelegate() override = default;

  void EnterFullscreenModeForTab(ApplicationContents*, const GURL&) override {
    is_fullscreen_ = true;
  }

  void ExitFullscreenModeForTab(ApplicationContents*) override {
    is_fullscreen_ = false;
  }

  bool IsFullscreenForTabOrPending(const ApplicationContents*) const override {
    return is_fullscreen_;
  }

 private:
  bool is_fullscreen_ = false;
  DISALLOW_COPY_AND_ASSIGN(FakeFullscreenDelegate);
};

}  // namespace

IN_PROC_BROWSER_TEST_F(AccessibilityFullscreenBrowserTest,
                       IgnoreElementsOutsideFullscreenElement) {
  ASSERT_TRUE(embedded_test_server()->Start());

  FakeFullscreenDelegate delegate;
  shell()->application_contents()->SetDelegate(&delegate);

  AccessibilityNotificationWaiter waiter(shell()->application_contents(),
                                         ui::kAXModeComplete,
                                         ax::mojom::Event::kLoadComplete);
  GURL url(
      embedded_test_server()->GetURL("/accessibility/fullscreen/links.html"));
  NavigateToURL(shell(), url);
  waiter.WaitForNotification();

  ApplicationContents* application_contents =
      static_cast<ApplicationContents*>(shell()->application_contents());
  BrowserAccessibilityManager* manager =
      application_contents->GetRootBrowserAccessibilityManager();

  // Initially there are 3 links in the accessiblity tree.
  EXPECT_EQ(3, CountLinks(manager->GetRoot()));

  // Enter fullscreen by finding the button and performing the default action,
  // which is to click it.
  BrowserAccessibility* button = FindButton(manager->GetRoot());
  ASSERT_NE(nullptr, button);
  manager->DoDefaultAction(*button);

  // Upon entering fullscreen, the page will change the button text to "Done".
  WaitForAccessibilityTreeToContainNodeWithName(application_contents, "Done");

  // Now, the two links outside of the fullscreen element are gone.
  EXPECT_EQ(1, CountLinks(manager->GetRoot()));
}

// Fails flakily on all platforms: crbug.com/825735
IN_PROC_BROWSER_TEST_F(AccessibilityFullscreenBrowserTest,
                       DISABLED_InsideIFrame) {
  ASSERT_TRUE(embedded_test_server()->Start());

  FakeFullscreenDelegate delegate;
  shell()->application_contents()->SetDelegate(&delegate);

  AccessibilityNotificationWaiter waiter(shell()->application_contents(),
                                         ui::kAXModeComplete,
                                         ax::mojom::Event::kLoadComplete);
  GURL url(
      embedded_test_server()->GetURL("/accessibility/fullscreen/iframe.html"));
  NavigateToURL(shell(), url);
  waiter.WaitForNotification();

  ApplicationContents* application_contents =
      static_cast<ApplicationContents*>(shell()->application_contents());
  BrowserAccessibilityManager* manager =
      application_contents->GetRootBrowserAccessibilityManager();

  // Initially there's just one link, in the top frame.
  EXPECT_EQ(1, CountLinks(manager->GetRoot()));

  // Enter fullscreen by finding the button and performing the default action,
  // which is to click it.
  BrowserAccessibility* button = FindButton(manager->GetRoot());
  ASSERT_NE(nullptr, button);
  manager->DoDefaultAction(*button);

  // After entering fullscreen, the page will add an iframe with a link inside
  // in the inert part of the page, then exit fullscreen and change the button
  // text to "Done". Then the link inside the iframe should also be exposed.
  WaitForAccessibilityTreeToContainNodeWithName(application_contents, "Done");
  EXPECT_EQ(2, CountLinks(manager->GetRoot()));
}

}  // namespace host
