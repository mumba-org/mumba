// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/media_session.h"

#include "base/command_line.h"
#include "base/run_loop.h"
#include "base/strings/utf_string_conversions.h"
#include "core/host/application/render_frame_host.h"
#include "core/host/application/application_contents.h"
#include "core/host/application/application_contents_observer.h"
#include "content/public/test/browser_test_utils.h"
#include "content/public/test/content_browser_test.h"
#include "content/public/test/content_browser_test_utils.h"
#include "content/domain/browser/shell.h"
#include "media/base/media_switches.h"

namespace host {

namespace {

// Integration tests for content::MediaSession that do not take into
// consideration the implementation details contrary to
// MediaSessionImplBrowserTest.
class MediaSessionBrowserTest : public ContentBrowserTest {
 public:
  MediaSessionBrowserTest() = default;

  void SetUpCommandLine(base::CommandLine* command_line) override {
    command_line->AppendSwitchASCII(
        switches::kAutoplayPolicy,
        switches::autoplay::kNoUserGestureRequiredPolicy);
  }

  void EnableInternalMediaSesion() {
#if !defined(OS_ANDROID)
    base::CommandLine::ForCurrentProcess()->AppendSwitch(
        switches::kEnableInternalMediaSession);
#endif  // !defined(OS_ANDROID)
  }

  void StartPlaybackAndWait(Domain* shell, const std::string& id) {
    shell->web_contents()->GetMainFrame()->ExecuteJavaScriptForTests(
        base::ASCIIToUTF16("document.querySelector('#" + id + "').play();"));
    WaitForStart(shell);
  }

  void StopPlaybackAndWait(Domain* shell, const std::string& id) {
    shell->web_contents()->GetMainFrame()->ExecuteJavaScriptForTests(
        base::ASCIIToUTF16("document.querySelector('#" + id + "').pause();"));
    WaitForStop(shell);
  }

  void WaitForStart(Domain* shell) {
    MediaStartStopObserver observer(shell->web_contents(),
                                    MediaStartStopObserver::Type::kStart);
    observer.Wait();
  }

  void WaitForStop(Domain* shell) {
    MediaStartStopObserver observer(shell->web_contents(),
                                    MediaStartStopObserver::Type::kStop);
    observer.Wait();
  }

  bool IsPlaying(Domain* shell, const std::string& id) {
    bool result;
    EXPECT_TRUE(
        ExecuteScriptAndExtractBool(shell->web_contents(),
                                    "window.domAutomationController.send("
                                    "!document.querySelector('#" +
                                        id + "').paused);",
                                    &result));
    return result;
  }

 private:
  class MediaStartStopObserver : public ApplicationContentsObserver {
   public:
    enum class Type { kStart, kStop };

    MediaStartStopObserver(ApplicationContents* web_contents, Type type)
        : ApplicationContentsObserver(web_contents), type_(type) {}

    void MediaStartedPlaying(const MediaPlayerInfo& info,
                             const MediaPlayerId& id) override {
      if (type_ != Type::kStart)
        return;

      run_loop_.Quit();
    }

    void MediaStoppedPlaying(
        const MediaPlayerInfo& info,
        const MediaPlayerId& id,
        ApplicationContentsObserver::MediaStoppedReason reason) override {
      if (type_ != Type::kStop)
        return;

      run_loop_.Quit();
    }

    void Wait() { run_loop_.Run(); }

   private:
    base::RunLoop run_loop_;
    Type type_;

    DISALLOW_COPY_AND_ASSIGN(MediaStartStopObserver);
  };

  DISALLOW_COPY_AND_ASSIGN(MediaSessionBrowserTest);
};

}  // anonymous namespace

#if !defined(OS_ANDROID) && !defined(OS_CHROMEOS)
// The feature can't be disabled on Android and Chrome OS.
IN_PROC_BROWSER_TEST_F(MediaSessionBrowserTest, MediaSessionNoOpWhenDisabled) {
  NavigateToURL(shell(), GetTestUrl("media/session", "media-session.html"));

  MediaSession* media_session = MediaSession::Get(shell()->web_contents());
  ASSERT_NE(nullptr, media_session);

  StartPlaybackAndWait(shell(), "long-video");
  StartPlaybackAndWait(shell(), "long-audio");

  media_session->Suspend(MediaSession::SuspendType::SYSTEM);
  StopPlaybackAndWait(shell(), "long-audio");

  // At that point, only "long-audio" is paused.
  EXPECT_FALSE(IsPlaying(shell(), "long-audio"));
  EXPECT_TRUE(IsPlaying(shell(), "long-video"));
}
#endif  // !defined(OS_ANDROID) && !defined(OS_CHROMEOS)

IN_PROC_BROWSER_TEST_F(MediaSessionBrowserTest, SimplePlayPause) {
  EnableInternalMediaSesion();

  NavigateToURL(shell(), GetTestUrl("media/session", "media-session.html"));

  MediaSession* media_session = MediaSession::Get(shell()->web_contents());
  ASSERT_NE(nullptr, media_session);

  StartPlaybackAndWait(shell(), "long-video");

  media_session->Suspend(MediaSession::SuspendType::SYSTEM);
  WaitForStop(shell());
  EXPECT_FALSE(IsPlaying(shell(), "long-video"));

  media_session->Resume(MediaSession::SuspendType::SYSTEM);
  WaitForStart(shell());
  EXPECT_TRUE(IsPlaying(shell(), "long-video"));
}

IN_PROC_BROWSER_TEST_F(MediaSessionBrowserTest, MultiplePlayersPlayPause) {
  EnableInternalMediaSesion();

  NavigateToURL(shell(), GetTestUrl("media/session", "media-session.html"));

  MediaSession* media_session = MediaSession::Get(shell()->web_contents());
  ASSERT_NE(nullptr, media_session);

  StartPlaybackAndWait(shell(), "long-video");
  StartPlaybackAndWait(shell(), "long-audio");

  media_session->Suspend(MediaSession::SuspendType::SYSTEM);
  WaitForStop(shell());
  EXPECT_FALSE(IsPlaying(shell(), "long-video"));
  EXPECT_FALSE(IsPlaying(shell(), "long-audio"));

  media_session->Resume(MediaSession::SuspendType::SYSTEM);
  WaitForStart(shell());
  EXPECT_TRUE(IsPlaying(shell(), "long-video"));
  EXPECT_TRUE(IsPlaying(shell(), "long-audio"));
}

#if !defined(OS_ANDROID)
// On Android, System Audio Focus would break this test.
IN_PROC_BROWSER_TEST_F(MediaSessionBrowserTest, MultipleTabsPlayPause) {
  EnableInternalMediaSesion();

  Domain* other_shell = CreateBrowser();

  NavigateToURL(shell(), GetTestUrl("media/session", "media-session.html"));
  NavigateToURL(other_shell, GetTestUrl("media/session", "media-session.html"));

  MediaSession* media_session = MediaSession::Get(shell()->web_contents());
  MediaSession* other_media_session =
      MediaSession::Get(other_shell->web_contents());
  ASSERT_NE(nullptr, media_session);
  ASSERT_NE(nullptr, other_media_session);

  StartPlaybackAndWait(shell(), "long-video");
  StartPlaybackAndWait(other_shell, "long-video");

  media_session->Suspend(MediaSession::SuspendType::SYSTEM);
  WaitForStop(shell());
  EXPECT_FALSE(IsPlaying(shell(), "long-video"));
  EXPECT_TRUE(IsPlaying(other_shell, "long-video"));

  other_media_session->Suspend(MediaSession::SuspendType::SYSTEM);
  WaitForStop(other_shell);
  EXPECT_FALSE(IsPlaying(shell(), "long-video"));
  EXPECT_FALSE(IsPlaying(other_shell, "long-video"));

  media_session->Resume(MediaSession::SuspendType::SYSTEM);
  WaitForStart(shell());
  EXPECT_TRUE(IsPlaying(shell(), "long-video"));
  EXPECT_FALSE(IsPlaying(other_shell, "long-video"));

  other_media_session->Resume(MediaSession::SuspendType::SYSTEM);
  WaitForStart(other_shell);
  EXPECT_TRUE(IsPlaying(shell(), "long-video"));
  EXPECT_TRUE(IsPlaying(other_shell, "long-video"));
}
#endif  // defined(OS_ANDROID)

}  // namespace host
