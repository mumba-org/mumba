// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/ui/application_contents_close_handler.h"

#include "core/host/ui/application_contents_close_handler_delegate.h"

namespace host {

ApplicationContentsCloseHandler::ApplicationContentsCloseHandler(
    ApplicationContentsCloseHandlerDelegate* delegate)
    : delegate_(delegate),
      in_close_(false),
      tab_changed_after_clone_(false) {
}

ApplicationContentsCloseHandler::~ApplicationContentsCloseHandler() {
}

void ApplicationContentsCloseHandler::TabInserted() {
  //DLOG(INFO) << "ApplicationContentsCloseHandler::TabInserted";
  // Tests may end up reviving a TabStrip that is empty.
  if (!in_close_)
    return;
  in_close_ = false;
  delegate_->DestroyClonedLayer();
}

void ApplicationContentsCloseHandler::ActiveTabChanged() {
  if (in_close_)
    tab_changed_after_clone_ = true;
  else
    delegate_->DestroyClonedLayer();
}

void ApplicationContentsCloseHandler::WillCloseAllTabs() {
  DCHECK(!in_close_);
  in_close_ = true;
  tab_changed_after_clone_ = false;
  delegate_->CloneApplicationContentsLayer();
  timer_.Stop();
}

void ApplicationContentsCloseHandler::CloseAllTabsCanceled() {
  DCHECK(in_close_);
  in_close_ = false;
  if (tab_changed_after_clone_) {
    // If the tab changed, destroy immediately. That way we make sure we aren't
    // showing the wrong thing.
    delegate_->DestroyClonedLayer();
  } else {
    // The most common reason for a close to be canceled is a before unload
    // handler. Often times the tab still ends up closing, but only after we get
    // back a response from the renderer. Assume this is going to happen and
    // keep around the cloned layer for a bit more time.
    timer_.Start(FROM_HERE, base::TimeDelta::FromMilliseconds(500),
                 this, &ApplicationContentsCloseHandler::OnStillHaventClosed);
  }
}

void ApplicationContentsCloseHandler::OnStillHaventClosed() {
  delegate_->DestroyClonedLayer();
}

}
