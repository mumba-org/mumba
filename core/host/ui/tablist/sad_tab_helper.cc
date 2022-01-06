// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/ui/tablist/sad_tab_helper.h"

#include "base/logging.h"
#include "build/build_config.h"
//#include "chrome/browser/browser_shutdown.h"
#include "core/host/ui/tablist/sad_tab.h"
#include "core/host/application/application_contents.h"

DEFINE_WEB_CONTENTS_USER_DATA_KEY(host::SadTabHelper);

namespace host {

namespace {

SadTabKind SadTabKindFromTerminationStatus(base::TerminationStatus status) {
  switch (status) {
#if defined(OS_CHROMEOS)
    case base::TERMINATION_STATUS_PROCESS_WAS_KILLED_BY_OOM:
      return SAD_TAB_KIND_KILLED_BY_OOM;
#endif
    case base::TERMINATION_STATUS_PROCESS_WAS_KILLED:
    case base::TERMINATION_STATUS_LAUNCH_FAILED:
      return SAD_TAB_KIND_KILLED;
    case base::TERMINATION_STATUS_OOM:
      return SAD_TAB_KIND_OOM;
    default:
      return SAD_TAB_KIND_CRASHED;
  }
}

}  // namespace

SadTabHelper::~SadTabHelper() {
  //DLOG(INFO) << "~SadTabHelper: " << this;
}

SadTabHelper::SadTabHelper(ApplicationContents* app_contents)
    : ApplicationContentsObserver(app_contents) {
}

void SadTabHelper::ReinstallInApplicationView() {
  if (sad_tab_)
    sad_tab_->ReinstallInApplicationView();
}

void SadTabHelper::ApplicationWindowReady() {
  sad_tab_.reset();
}

void SadTabHelper::ApplicationProcessGone(base::TerminationStatus status) {
  // Only show the sad tab if we're not in browser shutdown, so that WebContents
  // objects that are not in a browser (e.g., HTML dialogs) and thus are
  // visible do not flash a sad tab page.
  //if (browser_shutdown::GetShutdownType() != browser_shutdown::NOT_VALID)
  //  return;

  if (sad_tab_) {
    return;
  }

  if (SadTab::ShouldShow(status)) {
    InstallSadTab(status);
  }
}

void SadTabHelper::InstallSadTab(base::TerminationStatus status) {
  sad_tab_.reset(
      SadTab::Create(application_contents(), SadTabKindFromTerminationStatus(status)));
}

}