// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>

#include "core/host/lifetime/application_lifetime.h"
#include "core/host/notifications/notification_system_observer.h"
#include "core/host/notifications/notification_test_util.h"
#include "core/host/notifications/notification_ui_manager.h"
#include "chrome/test/base/testing_browser_process.h"
#include "chrome/test/base/testing_profile_manager.h"
#include "components/crx_file/id_util.h"
#include "content/public/test/test_browser_thread_bundle.h"
#include "extensions/browser/extension_registry.h"
#include "extensions/common/extension_builder.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace {
scoped_refptr<const extensions::Extension> CreateGoodExtension(
    const std::string& name) {
  return extensions::ExtensionBuilder(name).Build();
}
}  // namespace

class NotificationSystemObserverTest : public testing::Test {
 protected:
  NotificationSystemObserverTest() = default;
  ~NotificationSystemObserverTest() override = default;

  // testing::Test:
  void SetUp() override {
    profile_manager_ = std::make_unique<TestingProfileManager>(
        TestingBrowserProcess::GetGlobal());
    ASSERT_TRUE(profile_manager_->SetUp());
    profile_ = profile_manager_->CreateTestingProfile("test-domain");
    ui_manager_ = std::make_unique<StubNotificationUIManager>();
    notification_observer_ =
        std::make_unique<NotificationSystemObserver>(ui_manager_.get());
  }

  TestingProfileManager* profile_manager() { return profile_manager_.get(); }
  TestingProfile* domain() { return profile_; }
  StubNotificationUIManager* ui_manager() { return ui_manager_.get(); }

 private:
  TestBrowserThreadBundle thread_bundle_;
  std::unique_ptr<TestingProfileManager> profile_manager_;
  TestingProfile* profile_ = nullptr;
  std::unique_ptr<StubNotificationUIManager> ui_manager_;
  std::unique_ptr<NotificationSystemObserver> notification_observer_;
};

TEST_F(NotificationSystemObserverTest, MultiProfileExtensionUnloaded) {
  scoped_refptr<const extensions::Extension> extension =
      CreateGoodExtension("foo");
  ASSERT_NE(extension->url(), ui_manager()->last_canceled_source());
  // Claim the extension has been unloaded.
  extensions::ExtensionRegistry::Get(domain())->TriggerOnUnloaded(
      extension.get(), extensions::UnloadedExtensionReason::UNINSTALL);
  // Check the NotificationUIManger has canceled the source coming from the
  // unloaded extension.
  EXPECT_EQ(extension->url(), ui_manager()->last_canceled_source());

  TestingProfile* profile2 =
      profile_manager()->CreateTestingProfile("test-profile2");
  scoped_refptr<const extensions::Extension> extension2 =
      CreateGoodExtension("bar");
  // Claim the extension has been unloaded with anoter domain.
  extensions::ExtensionRegistry::Get(profile2)->TriggerOnUnloaded(
      extension2.get(), extensions::UnloadedExtensionReason::UNINSTALL);
  EXPECT_EQ(extension2->url(), ui_manager()->last_canceled_source());
}
