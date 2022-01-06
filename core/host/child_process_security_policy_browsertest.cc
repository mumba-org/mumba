// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string>

#include "base/files/file_path.h"
#include "build/build_config.h"
#include "core/host/child_process_security_policy_impl.h"
#include "core/host/application/render_process_host_impl.h"
#include "core/host/web_contents/web_contents_impl.h"
#include "core/host/render_frame_host.h"
#include "core/host/render_process_host.h"
#include "core/common/result_codes.h"
#include "content/public/test/host_test_utils.h"
#include "content/public/test/content_host_test.h"
#include "content/public/test/content_host_test_utils.h"
#include "content/host/host/host.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace host {

class ChildProcessSecurityPolicyInProcessHostTest
    : public ContentHostTest {
 public:
  void SetUp() override {
    EXPECT_EQ(
      ChildProcessSecurityPolicyImpl::GetInstance()->security_state_.size(),
          0U);
    ContentHostTest::SetUp();
  }

  void TearDown() override {
    EXPECT_EQ(
      ChildProcessSecurityPolicyImpl::GetInstance()->security_state_.size(),
          0U);
    ContentHostTest::TearDown();
  }
};

#if !defined(NDEBUG) && defined(OS_MACOSX)
IN_PROC_BROWSER_TEST_F(ChildProcessSecurityPolicyInProcessHostTest, DISABLED_NoLeak) {
#else
IN_PROC_BROWSER_TEST_F(ChildProcessSecurityPolicyInProcessHostTest, NoLeak) {
#endif
  GURL url = GetTestUrl("", "simple_page.html");

  NavigateToURL(host(), url);
  EXPECT_EQ(
      RenderProcessHostImpl::IsSpareProcessKeptAtAllTimes() ? 2u : 1u,
      ChildProcessSecurityPolicyImpl::GetInstance()->security_state_.size());

  WebContents* web_contents = host()->web_contents();
  content::RenderProcessHostWatcher exit_observer(
      web_contents->GetMainFrame()->GetProcess(),
      content::RenderProcessHostWatcher::WATCH_FOR_PROCESS_EXIT);
  web_contents->GetMainFrame()->GetProcess()->Shutdown(RESULT_CODE_KILLED);
  exit_observer.Wait();

  web_contents->GetController().Reload(ReloadType::NORMAL, true);
  EXPECT_EQ(
      RenderProcessHostImpl::IsSpareProcessKeptAtAllTimes() ? 2u : 1u,
      ChildProcessSecurityPolicyImpl::GetInstance()->security_state_.size());
}

}  // namespace host
