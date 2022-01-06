// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <utility>

#include "base/bind.h"
#include "base/command_line.h"
#include "base/macros.h"
#include "base/run_loop.h"
#include "base/strings/utf_string_conversions.h"
#include "build/build_config.h"
#include "core/host/application/input/synthetic_gesture.h"
#include "core/host/application/input/synthetic_smooth_scroll_gesture.h"
#include "core/host/application/application_window_host.h"
#include "core/host/web_contents/web_contents_impl.h"
#include "core/common/input/synthetic_gesture_params.h"
#include "core/common/input/synthetic_smooth_scroll_gesture_params.h"
#include "core/host/application_window_host.h"
#include "core/common/content_switches.h"
#include "content/public/test/browser_test_utils.h"
#include "content/public/test/content_browser_test.h"
#include "content/public/test/content_browser_test_utils.h"
#include "content/public/test/test_utils.h"
#include "content/domain/browser/shell.h"
#include "ui/gfx/geometry/angle_conversions.h"

namespace {

const char kCompositedScrollingDataURL[] =
    "data:text/html;charset=utf-8,"
    "<!DOCTYPE html>"
    "<meta name='viewport' content='width=device-width'/>"
    "<style>"
    "#scroller {"
    "  width:500px;"
    "  height:500px;"
    "  overflow:scroll;"
    "  transform: rotateX(-30deg);"
    "}"

    "#content {"
    "  background-color:red;"
    "  width:1000px;"
    "  height:1000px;"
    "}"
    "</style>"
    "<div id='scroller'>"
    "  <div id='content'>"
    "  </div>"
    "</div>"
    "<script>"
    "  document.title='ready';"
    "</script>";

}  // namespace

namespace host {


class CompositedScrollingBrowserTest : public ContentBrowserTest {
 public:
  CompositedScrollingBrowserTest() {}
  ~CompositedScrollingBrowserTest() override {}

  void SetUpCommandLine(base::CommandLine* cmd) override {
    cmd->AppendSwitch(switches::kEnablePreferCompositingToLCDText);
  }

  ApplicationWindowHost* GetWidgetHost() {
    return ApplicationWindowHost::From(
        shell()->web_contents()->GetRenderViewHost()->GetWidget());
  }

  void OnSyntheticGestureCompleted(SyntheticGesture::Result result) {
    EXPECT_EQ(SyntheticGesture::GESTURE_FINISHED, result);
    runner_->Quit();
  }

 protected:
  void LoadURL() {
    const GURL data_url(kCompositedScrollingDataURL);
    NavigateToURL(shell(), data_url);

    ApplicationWindowHost* host = GetWidgetHost();
    MainThreadFrameObserver observer(host);
    host->GetView()->SetSize(gfx::Size(400, 400));

    base::string16 ready_title(base::ASCIIToUTF16("ready"));
    TitleWatcher watcher(shell()->web_contents(), ready_title);
    ignore_result(watcher.WaitAndGetTitle());

    // We need to wait until at least one frame has been composited
    // otherwise the injection of the synthetic gestures may get
    // dropped because of MainThread/Impl thread sync of touch event
    // regions.
    observer.Wait();
  }

  // ContentBrowserTest:
  int ExecuteScriptAndExtractInt(const std::string& script) {
    int value = 0;
    EXPECT_TRUE(content::ExecuteScriptAndExtractInt(
        shell(), "domAutomationController.send(" + script + ")", &value));
    return value;
  }

  int GetScrollTop() {
    return ExecuteScriptAndExtractInt(
        "document.getElementById(\"scroller\").scrollTop");
  }

  // Generate touch events for a synthetic scroll from |point| for |distance|.
  // Returns the distance scrolled.
  int DoTouchScroll(const gfx::Point& point, const gfx::Vector2d& distance) {
    EXPECT_EQ(0, GetScrollTop());

    int scroll_height = ExecuteScriptAndExtractInt(
        "document.getElementById('scroller').scrollHeight");
    EXPECT_EQ(1000, scroll_height);

    SyntheticSmoothScrollGestureParams params;
    params.gesture_source_type = SyntheticGestureParams::TOUCH_INPUT;
    params.anchor = gfx::PointF(point);
    params.distances.push_back(-distance);

    runner_ = new MessageLoopRunner();

    std::unique_ptr<SyntheticSmoothScrollGesture> gesture(
        new SyntheticSmoothScrollGesture(params));
    GetWidgetHost()->QueueSyntheticGesture(
        std::move(gesture),
        base::BindOnce(
            &CompositedScrollingBrowserTest::OnSyntheticGestureCompleted,
            base::Unretained(this)));

    // Runs until we get the OnSyntheticGestureCompleted callback
    runner_->Run();
    runner_ = nullptr;

    return GetScrollTop();
  }

 private:
  scoped_refptr<MessageLoopRunner> runner_;

  DISALLOW_COPY_AND_ASSIGN(CompositedScrollingBrowserTest);
};

// Verify transforming a scroller doesn't prevent it from scrolling. See
// crbug.com/543655 for a case where this was broken.
// Disabled on MacOS because it doesn't support touch input.
// Disabled on Android due to flakiness, see https://crbug.com/376668.
// Flaky on Windows: crbug.com/804009
#if defined(OS_MACOSX) || defined(OS_ANDROID) || defined(OS_WIN)
#define MAYBE_Scroll3DTransformedScroller DISABLED_Scroll3DTransformedScroller
#else
#define MAYBE_Scroll3DTransformedScroller Scroll3DTransformedScroller
#endif
IN_PROC_BROWSER_TEST_F(CompositedScrollingBrowserTest,
                       MAYBE_Scroll3DTransformedScroller) {
  LoadURL();
  int scroll_distance =
      DoTouchScroll(gfx::Point(50, 150), gfx::Vector2d(0, 100));
  // The scroll distance is increased due to the rotation of the scroller.
  EXPECT_EQ(std::floor(100 / std::cos(gfx::DegToRad(30.f))) - 1,
            scroll_distance);
}

}  // namespace host
