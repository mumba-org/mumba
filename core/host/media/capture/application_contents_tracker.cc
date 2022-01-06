// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/media/capture/application_contents_tracker.h"

#include "base/threading/thread_task_runner_handle.h"
#include "core/host/host_thread.h"
#include "core/host/application/application_window_host.h"
#include "core/host/application/application_window_host_view.h"
#include "core/host/application/application_contents.h"

namespace host {

ApplicationContentsTracker::ApplicationContentsTracker(bool track_fullscreen_rwhv)
    : track_fullscreen_rwhv_(track_fullscreen_rwhv),
      last_target_view_(nullptr) {
  DLOG(INFO) << "ApplicationContentsTracker: " << this;
}

ApplicationContentsTracker::~ApplicationContentsTracker() {
  // Likely unintentional BUG if Stop() was not called before this point.
  //DLOG(INFO) << "~ApplicationContentsTracker: " << this;
  DCHECK(!application_contents());
}

void ApplicationContentsTracker::Start(int app_process_id, int main_render_frame_id,
                                       const ChangeCallback& callback) {
  DCHECK(!task_runner_ || task_runner_->BelongsToCurrentThread());

  task_runner_ = base::ThreadTaskRunnerHandle::Get();
  DCHECK(task_runner_);
  callback_ = callback;

  if (HostThread::CurrentlyOn(HostThread::UI)) {
    StartObservingApplicationContents(app_process_id, main_render_frame_id);
  } else {
    HostThread::PostTask(
        HostThread::UI, FROM_HERE,
        base::BindOnce(&ApplicationContentsTracker::StartObservingApplicationContents, this,
                       app_process_id, main_render_frame_id));
  }
}

void ApplicationContentsTracker::Stop() {
  DCHECK(task_runner_->BelongsToCurrentThread());

  callback_.Reset();
  resize_callback_.Reset();

  if (HostThread::CurrentlyOn(HostThread::UI)) {
    ApplicationContentsObserver::Observe(nullptr);
  } else {
    HostThread::PostTask(HostThread::UI, FROM_HERE,
                         base::BindOnce(&ApplicationContentsTracker::Observe, this,
                                        static_cast<ApplicationContents*>(nullptr)));
  }
}

ApplicationWindowHostView* ApplicationContentsTracker::GetTargetView() const {
  DCHECK_CURRENTLY_ON(HostThread::UI);

  ApplicationContents* const ac = application_contents();
  if (!ac)
    return nullptr;

  if (track_fullscreen_rwhv_) {
    if (auto* view = ac->GetFullscreenApplicationWindowHostView())
      return view;
  }

  if (auto* view = ac->GetApplicationWindowHostView()) {
    // Make sure the RWHV is still associated with a RWH before considering the
    // view "alive." This is because a null RWH indicates the RWHV has had its
    // Destroy() method called.
    if (view->GetApplicationWindowHost())
      return view;
  }
  return nullptr;
}

void ApplicationContentsTracker::SetResizeChangeCallback(
    const base::Closure& callback) {
  DCHECK(!task_runner_ || task_runner_->BelongsToCurrentThread());
  resize_callback_ = callback;
}

void ApplicationContentsTracker::OnPossibleTargetChange(bool force_callback_run) {
  DCHECK_CURRENTLY_ON(HostThread::UI);

  ApplicationWindowHostView* const rwhv = GetTargetView();
  if (rwhv == last_target_view_ && !force_callback_run) {
    DVLOG(1) << "No target view change (ApplicationWindowHostView@" << rwhv << ')';
    return;
  }
  DVLOG(1) << "Will report target change from ApplicationWindowHostView@"
           << last_target_view_ << " to ApplicationWindowHostView@" << rwhv;
  last_target_view_ = rwhv;

  if (task_runner_->BelongsToCurrentThread()) {
    MaybeDoCallback(is_still_tracking());
    return;
  }

  task_runner_->PostTask(
      FROM_HERE, base::BindOnce(&ApplicationContentsTracker::MaybeDoCallback, this,
                                is_still_tracking()));
}

void ApplicationContentsTracker::MaybeDoCallback(bool was_still_tracking) {
  DCHECK(task_runner_->BelongsToCurrentThread());

  // Notify of a size change just before notifying of a new target. This allows
  // the downstream implementation to capture the first frame from the new
  // target at the correct resolution. http://crbug.com/704277
  if (was_still_tracking)
    MaybeDoResizeCallback();
  if (!callback_.is_null())
    callback_.Run(was_still_tracking);
}

void ApplicationContentsTracker::MaybeDoResizeCallback() {
  DCHECK(task_runner_->BelongsToCurrentThread());

  if (!resize_callback_.is_null())
    resize_callback_.Run();
}

void ApplicationContentsTracker::StartObservingApplicationContents(
  int app_process_id,
  int main_render_frame_id) {
  
  DCHECK_CURRENTLY_ON(HostThread::UI);

  Observe(ApplicationContents::FromApplicationWindowHost(ApplicationWindowHost::FromID(
      app_process_id, main_render_frame_id)));
  DVLOG_IF(1, !application_contents())
      << "Could not find ApplicationContents associated with main RenderFrameHost "
      << "referenced by render_process_id=" << app_process_id
      << ", routing_id=" << main_render_frame_id;

  OnPossibleTargetChange(true);
}

void ApplicationContentsTracker::ApplicationWindowCreated(
    ApplicationWindowHost* app_window_host) {
  DVLOG(1) << "RenderFrameCreated(rfh=" << app_window_host << ')';
  OnPossibleTargetChange(false);
}

void ApplicationContentsTracker::ApplicationWindowDeleted(
    ApplicationWindowHost* app_window_host) {
  DVLOG(1) << "RenderFrameDeleted(rfh=" << app_window_host << ')';
  OnPossibleTargetChange(false);
}

void ApplicationContentsTracker::ApplicationWindowChanged(
  ApplicationWindowHost* old_host,
  ApplicationWindowHost* new_host) {
  DVLOG(1) << "RenderFrameHostChanged(old=" << old_host << ", new=" << new_host
           << ')';
  OnPossibleTargetChange(false);
}

void ApplicationContentsTracker::WindowWasResized(bool width_changed) {
  DCHECK_CURRENTLY_ON(HostThread::UI);

  if (task_runner_->BelongsToCurrentThread()) {
    MaybeDoResizeCallback();
    return;
  }

  task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&ApplicationContentsTracker::MaybeDoResizeCallback, this));
}

void ApplicationContentsTracker::ApplicationContentsDestroyed() {
  DVLOG(1) << "ApplicationContentsDestroyed()";
  Observe(nullptr);
  OnPossibleTargetChange(true);
}

void ApplicationContentsTracker::DidShowFullscreenWindow() {
  DVLOG(1) << "DidShowFullscreenWindow()";
  OnPossibleTargetChange(false);
}

void ApplicationContentsTracker::DidDestroyFullscreenWindow() {
  DVLOG(1) << "DidDestroyFullscreenWindow()";
  OnPossibleTargetChange(false);
}

}  // namespace host
