// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/application/application_contents_observer.h"

#include "core/host/application/application_contents.h"
//#include "core/host/application/navigation_details.h"
#include "core/host/application/application_window_host.h"
#include "core/host/host_thread.h"

namespace host {

ApplicationContentsObserver::ApplicationContentsObserver(ApplicationContents* application_contents)
    : application_contents_(nullptr),
      weak_factory_(this) {
  Observe(application_contents);
}

ApplicationContentsObserver::ApplicationContentsObserver()
    : application_contents_(nullptr),
      weak_factory_(this) {
} 

ApplicationContentsObserver::~ApplicationContentsObserver() {
  ////DLOG(INFO) << "~ApplicationContentsObserver: " << this << " application_contents_ = " << application_contents_;
  
  // FIXME: this is a hack designed for the likes of URLLoaderFactory that will be destroyed
  //        on IOThread but giving we are using WeakPtrs now, for safety reasons
  //        the WeakPtr<X>.get() checks the thread and RemoveObserver compare
  //        heap address to remove the observer, so it crashes when called from
  //        any other thread except for UI.
  //                
  //        For URLLoaderFactory this is ok, giving it only destroy itself
  //        when the Contents warn its going to be destroyed on its own destructor
  //        so it doesnt matter if it deregister itself as a observer
  //        of a contents that is going to be deleted.
  //        But in other cases, this might be not the case.. 
  //        so a better approach is needed (keeping WeakPtrs on the observers)

  //        WeakPtr's on Observers: theres no garantee that a observer will 
  //        be alive at the time of the Contents destruction, and some of them
  //        dont, so the WeakPtrs help us to be able to check before calling
  //        any of them

  if (application_contents_ && HostThread::CurrentlyOn(HostThread::UI))
    application_contents_->RemoveObserver(this);
}

ApplicationContents* ApplicationContentsObserver::application_contents() const {
  return application_contents_;
}

void ApplicationContentsObserver::Observe(ApplicationContents* application_contents) {
  if (application_contents == application_contents_) {
    // Early exit to avoid infinite loops if we're in the middle of a callback.
    //DLOG(INFO) << "ApplicationContentsObserver::Observe: current app contents and new are the same. cancelling";
    return;
  }
  if (application_contents_)
    application_contents_->RemoveObserver(this);
  application_contents_ = application_contents;
  if (application_contents_) {
    application_contents_->AddObserver(weak_factory_.GetWeakPtr());
  }
}

bool ApplicationContentsObserver::OnMessageReceived(
    const IPC::Message& message,
    ApplicationWindowHost* application_window_host) {
    //RenderFrameHost* render_frame_host) {
  return false;
}

bool ApplicationContentsObserver::OnMessageReceived(const IPC::Message& message) {
  return false;
}

void ApplicationContentsObserver::ResetApplicationContents() {
  if (application_contents_) {
    application_contents_->RemoveObserver(this);
    application_contents_ = nullptr;
  }
}

}  // namespace host
