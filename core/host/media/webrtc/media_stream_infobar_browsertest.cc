// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/command_line.h"
#include "base/files/file_util.h"
#include "base/macros.h"
#include "chrome/browser/chrome_notification_types.h"
#include "chrome/browser/content_settings/host_content_settings_map_factory.h"
#include "core/host/media/webrtc/media_stream_devices_controller.h"
#include "core/host/media/webrtc/webrtc_browsertest_base.h"
#include "core/host/media/webrtc/webrtc_browsertest_common.h"
#include "chrome/browser/profiles/profile.h"
#include "core/host/ui/dock.h"
#include "core/host/ui/applist/dock_applist.h"
#include "core/host/ui/applist/applist_model.h"
#include "core/shared/common/switches.h"
#include "chrome/test/base/in_process_browser_test.h"
#include "chrome/test/base/test_switches.h"
#include "chrome/test/base/ui_test_utils.h"
#include "components/content_settings/core/browser/host_content_settings_map.h"
#include "components/content_settings/core/common/content_settings_types.h"
#include "core/host/notification_service.h"
#include "core/shared/common/content_switches.h"
#include "core/shared/common/media_stream_request.h"
#include "core/shared/common/origin_util.h"
#include "content/public/test/browser_test_utils.h"
#include "media/base/media_switches.h"
#include "net/dns/mock_host_resolver.h"
#include "net/test/embedded_test_server/embedded_test_server.h"

// MediaStreamPermissionTest ---------------------------------------------------

class MediaStreamPermissionTest : public WebRtcTestBase {
 public:
  MediaStreamPermissionTest() {}
  ~MediaStreamPermissionTest() override {}

  // InProcessBrowserTest:
  void SetUpCommandLine(base::CommandLine* command_line) override {
    // This test expects to run with fake devices but real UI.
    command_line->AppendSwitch(switches::kUseFakeDeviceForMediaStream);
    EXPECT_FALSE(command_line->HasSwitch(switches::kUseFakeUIForMediaStream))
        << "Since this test tests the UI we want the real UI!";
  }

 protected:
  ApplicationContents* LoadTestPageInTab() {
    return LoadTestPageInBrowser(browser());
  }

  ApplicationContents* LoadTestPageInIncognitoTab() {
    return LoadTestPageInBrowser(CreateIncognitoBrowser());
  }

  // Returns the URL of the main test page.
  GURL test_page_url() const {
    const char kMainWebrtcTestHtmlPage[] = "/webrtc/webrtc_jsep01_test.html";
    return embedded_test_server()->GetURL(kMainWebrtcTestHtmlPage);
  }

 private:
  ApplicationContents* LoadTestPageInBrowser(Browser* browser) {
    EXPECT_TRUE(embedded_test_server()->Start());

    // Uses the default server.
    GURL url = test_page_url();

    EXPECT_TRUE(content::IsOriginSecure(url));

    ui_test_utils::NavigateToURL(browser, url);
    return browser->tab_strip_model()->GetActiveApplicationContents();
  }

  // Dummy callback for when we deny the current request directly.
  static void OnMediaStreamResponse(
      const content::MediaStreamDevices& devices,
      content::MediaStreamRequestResult result,
      std::unique_ptr<content::MediaStreamUI> ui) {}

  DISALLOW_COPY_AND_ASSIGN(MediaStreamPermissionTest);
};

// Actual tests ---------------------------------------------------------------

IN_PROC_BROWSER_TEST_F(MediaStreamPermissionTest, TestAllowingUserMedia) {
  ApplicationContents* tab_contents = LoadTestPageInTab();
  EXPECT_TRUE(GetUserMediaAndAccept(tab_contents));
}

IN_PROC_BROWSER_TEST_F(MediaStreamPermissionTest, TestDenyingUserMedia) {
  ApplicationContents* tab_contents = LoadTestPageInTab();
  GetUserMediaAndDeny(tab_contents);
}

IN_PROC_BROWSER_TEST_F(MediaStreamPermissionTest, TestDismissingRequest) {
  ApplicationContents* tab_contents = LoadTestPageInTab();
  GetUserMediaAndDismiss(tab_contents);
}

IN_PROC_BROWSER_TEST_F(MediaStreamPermissionTest,
                       TestDenyingUserMediaIncognito) {
  ApplicationContents* tab_contents = LoadTestPageInIncognitoTab();
  GetUserMediaAndDeny(tab_contents);
}

IN_PROC_BROWSER_TEST_F(MediaStreamPermissionTest,
                       TestSecureOriginDenyIsSticky) {
  ApplicationContents* tab_contents = LoadTestPageInTab();
  EXPECT_TRUE(content::IsOriginSecure(tab_contents->GetLastCommittedURL()));

  GetUserMediaAndDeny(tab_contents);
  GetUserMediaAndExpectAutoDenyWithoutPrompt(tab_contents);
}

IN_PROC_BROWSER_TEST_F(MediaStreamPermissionTest,
                       TestSecureOriginAcceptIsSticky) {
  ApplicationContents* tab_contents = LoadTestPageInTab();
  EXPECT_TRUE(content::IsOriginSecure(tab_contents->GetLastCommittedURL()));

  EXPECT_TRUE(GetUserMediaAndAccept(tab_contents));
  GetUserMediaAndExpectAutoAcceptWithoutPrompt(tab_contents);
}

IN_PROC_BROWSER_TEST_F(MediaStreamPermissionTest, TestDismissIsNotSticky) {
  ApplicationContents* tab_contents = LoadTestPageInTab();

  GetUserMediaAndDismiss(tab_contents);
  GetUserMediaAndDismiss(tab_contents);
}

IN_PROC_BROWSER_TEST_F(MediaStreamPermissionTest,
                       TestDenyingThenClearingStickyException) {
  ApplicationContents* tab_contents = LoadTestPageInTab();

  GetUserMediaAndDeny(tab_contents);
  GetUserMediaAndExpectAutoDenyWithoutPrompt(tab_contents);

  HostContentSettingsMap* settings_map =
      HostContentSettingsMapFactory::GetForProfile(browser()->profile());

  settings_map->ClearSettingsForOneType(CONTENT_SETTINGS_TYPE_MEDIASTREAM_MIC);
  settings_map->ClearSettingsForOneType(
      CONTENT_SETTINGS_TYPE_MEDIASTREAM_CAMERA);

  GetUserMediaAndDeny(tab_contents);
}

IN_PROC_BROWSER_TEST_F(MediaStreamPermissionTest,
                       DenyingMicDoesNotCauseStickyDenyForCameras) {
  ApplicationContents* tab_contents = LoadTestPageInTab();

  GetUserMediaWithSpecificConstraintsAndDeny(tab_contents,
                                             kAudioOnlyCallConstraints);
  EXPECT_TRUE(GetUserMediaWithSpecificConstraintsAndAccept(
      tab_contents, kVideoOnlyCallConstraints));
}

IN_PROC_BROWSER_TEST_F(MediaStreamPermissionTest,
                       DenyingCameraDoesNotCauseStickyDenyForMics) {
  ApplicationContents* tab_contents = LoadTestPageInTab();

  GetUserMediaWithSpecificConstraintsAndDeny(tab_contents,
                                             kVideoOnlyCallConstraints);
  EXPECT_TRUE(GetUserMediaWithSpecificConstraintsAndAccept(
      tab_contents, kAudioOnlyCallConstraints));
}
