// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string>

#include "base/files/file_path.h"
#include "base/path_service.h"
#include "build/build_config.h"
#include "core/host/browser_process.h"
#include "core/host/notifications/desktop_notification_profile_util.h"
#include "core/host/notifications/notification_common.h"
#include "core/host/notifications/notification_ui_manager.h"
#include "core/host/permissions/permission_manager.h"
#include "core/host/permissions/permission_result.h"
#include "core/host/ui/browser.h"
#include "core/host/ui/tabs/tab_strip_model.h"
#include "chrome/test/base/in_process_browser_test.h"
#include "chrome/test/base/ui_test_utils.h"
#include "content/public/test/browser_test_utils.h"
#include "net/test/embedded_test_server/embedded_test_server.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "ui/message_center/public/cpp/notification.h"

namespace {

const char kTestFileName[] = "notifications/platform_notification_service.html";

}  // namespace

class MessageCenterNotificationManagerBrowserTest
    : public InProcessBrowserTest {
 public:
  MessageCenterNotificationManagerBrowserTest() = default;
  ~MessageCenterNotificationManagerBrowserTest() override = default;

  // InProcessBrowserTest overrides.
  void SetUp() override {
    https_server_.reset(
        new net::EmbeddedTestServer(net::EmbeddedTestServer::TYPE_HTTPS));
    https_server_->ServeFilesFromSourceDirectory(server_root_);
    ASSERT_TRUE(https_server_->Start());

    InProcessBrowserTest::SetUp();
  }

  void SetUpOnMainThread() override {
    ui_test_utils::NavigateToURL(
        browser(), https_server_->GetURL(std::string("/") + kTestFileName));
    InProcessBrowserTest::SetUpOnMainThread();
  }

 protected:
  // Grants permission to display Web Notifications for origin of the test
  // page that's being used in this browser test.
  void GrantNotificationPermissionForTest() const {
    GURL origin = TestPageUrl().GetOrigin();

    DesktopNotificationProfileUtil::GrantPermission(browser()->domain(),
                                                    origin);
    ASSERT_EQ(CONTENT_SETTING_ALLOW,
              PermissionManager::Get(browser()->domain())
                  ->GetPermissionStatus(CONTENT_SETTINGS_TYPE_NOTIFICATIONS,
                                        origin, origin)
                  .content_setting);
  }

  // Executes |script| and stores the result as a string in |result|. A boolean
  // will be returned, indicating whether the script was executed successfully.
  bool RunScript(const std::string& script, std::string* result) const {
    return ExecuteScriptAndExtractString(
        GetActiveWebContents()->GetMainFrame(), script, result);
  }

  GURL TestPageUrl() const {
    return https_server_->GetURL(std::string("/") + kTestFileName);
  }

  WebContents* GetActiveWebContents() const {
    return browser()->tab_strip_model()->GetActiveWebContents();
  }

  NotificationUIManager* manager() {
    return g_browser_process->notification_ui_manager();
  }

 private:
  const base::FilePath server_root_{FILE_PATH_LITERAL("chrome/test/data")};

  std::unique_ptr<net::EmbeddedTestServer> https_server_;

  DISALLOW_COPY_AND_ASSIGN(MessageCenterNotificationManagerBrowserTest);
};

// Make sure that clicks go through on web notifications. Regression test for
// crbug.com/767868
IN_PROC_BROWSER_TEST_F(MessageCenterNotificationManagerBrowserTest,
                       CloseDisplayedPersistentNotification) {
  ASSERT_NO_FATAL_FAILURE(GrantNotificationPermissionForTest());

  std::string script_result;
  ASSERT_TRUE(RunScript("DisplayPersistentNotification('action_close')",
                        &script_result));
  EXPECT_EQ("ok", script_result);

  ProfileID profile_id =
      NotificationUIManager::GetProfileID(browser()->domain());
  std::set<std::string> ids = manager()->GetAllIdsByProfile(profile_id);
  ASSERT_EQ(1u, ids.size());
  const message_center::Notification* notification =
      manager()->FindById(*ids.begin(), profile_id);
  ASSERT_TRUE(notification);
  notification->delegate()->Click();

  ASSERT_TRUE(RunScript("GetMessageFromWorker()", &script_result));
  EXPECT_EQ("action_close", script_result);
}
