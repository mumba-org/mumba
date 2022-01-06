// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/media/capture/application_contents_video_capture_device.h"

#include "base/bind.h"
#include "base/location.h"
#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/memory/weak_ptr.h"
#include "base/threading/thread_task_runner_handle.h"
#include "core/host/application/application_window_host_view_base.h"
#include "core/host/application/render_frame_host.h"
#include "core/host/application/application_contents.h"
#include "core/host/application_contents_media_capture_id.h"
#include "core/host/application/application_contents_observer.h"
#include "media/capture/video_capture_types.h"
#include "ui/base/layout.h"
#include "ui/gfx/geometry/dip_util.h"
#include "ui/gfx/geometry/size.h"
#include "ui/gfx/native_widget_types.h"

namespace host {

// Threading note: This is constructed on the device thread, while the
// destructor and the rest of the class will run exclusively on the UI thread.
class ApplicationContentsVideoCaptureDevice::FrameTracker
    : public ApplicationContentsObserver,
      public base::SupportsWeakPtr<
          ApplicationContentsVideoCaptureDevice::FrameTracker> {
 public:
  FrameTracker(base::WeakPtr<ApplicationContentsVideoCaptureDevice> device,
               CursorRenderer* cursor_renderer,
               int render_process_id,
               int main_render_frame_id)
      : device_(std::move(device)),
        device_task_runner_(base::ThreadTaskRunnerHandle::Get()),
        cursor_renderer_(cursor_renderer) {
    DCHECK(device_task_runner_);
    DCHECK(cursor_renderer_);
    DLOG(INFO) << "ApplicationContentsVideoCaptureDevice::FrameTracker: " << this;
    HostThread::PostTask(
        HostThread::UI, FROM_HERE,
        base::BindOnce(
            [](base::WeakPtr<FrameTracker> self, int process_id, int frame_id) {
              if (self) {
                self->Observe(ApplicationContents::FromRenderFrameHost(
                    RenderFrameHost::FromID(process_id, frame_id)));
                self->OnPossibleTargetChange();
              }
            },
            AsWeakPtr(), render_process_id, main_render_frame_id));
  }

  ~FrameTracker() final { 
    DCHECK_CURRENTLY_ON(HostThread::UI); 
    DLOG(INFO) << "ApplicationContentsVideoCaptureDevice::~FrameTracker: " << this;
  }

  void WillStartCapturingApplicationContents(const gfx::Size& capture_size) {
    DCHECK_CURRENTLY_ON(HostThread::UI);

    auto* contents = web_contents();
    if (!contents) {
      return;
    }

    // Increment the ApplicationContents's capturer count, providing ApplicationContents with a
    // preferred size override during its capture. The preferred size is a
    // strong suggestion to UI layout code to size the view such that its
    // physical rendering size matches the exact capture size. This helps to
    // eliminate redundant scaling operations during capture.
    //
    // TODO(crbug.com/350491): Propagate capture frame size changes as new
    // "preferred size" updates, rather than just using the max frame size. This
    // would also fix an issue where the view may move to a different screen
    // that has a different device scale factor while being captured.
    gfx::Size preferred_size;
    if (auto* view = GetCurrentView()) {
      preferred_size =
          gfx::ConvertSizeToDIP(view->GetDeviceScaleFactor(), capture_size);
    }
    if (preferred_size.IsEmpty()) {
      preferred_size = capture_size;
    }
    VLOG(1) << "Computed preferred ApplicationContents size as "
            << preferred_size.ToString() << " from a capture size of "
            << capture_size.ToString();
    contents->IncrementCapturerCount(preferred_size);
  }

  void DidStopCapturingApplicationContents() {
    DCHECK_CURRENTLY_ON(HostThread::UI);

    if (auto* contents = web_contents()) {
      contents->DecrementCapturerCount();
    }
  }

 private:
  // Find the view associated with the entirety of displayed content of the
  // current ApplicationContents, whether that be a fullscreen view or the regular view.
  ApplicationWindowHostView* GetCurrentView() const {
    DCHECK_CURRENTLY_ON(HostThread::UI);

    ApplicationContents* const contents = web_contents();
    if (!contents || contents->IsCrashed()) {
      return nullptr;
    }

    ApplicationWindowHostView* view = contents->GetFullscreenApplicationWindowHostView();
    if (!view) {
      view = contents->GetApplicationWindowHostView();
    }
    // Make sure the RWHV is still associated with a RWH before considering the
    // view "alive." This is because a null RWH indicates the RWHV has had its
    // Destroy() method called.
    if (!view || !view->GetApplicationWindowHost()) {
      return nullptr;
    }
    return view;
  }

  // ApplicationContentsObserver overrides.
  void RenderFrameCreated(RenderFrameHost* render_frame_host) final {
    OnPossibleTargetChange();
  }
  void RenderFrameDeleted(RenderFrameHost* render_frame_host) final {
    OnPossibleTargetChange();
  }
  void RenderFrameHostChanged(RenderFrameHost* old_host,
                              RenderFrameHost* new_host) final {
    OnPossibleTargetChange();
  }
  void DidShowFullscreenWidget() final { OnPossibleTargetChange(); }
  void DidDestroyFullscreenWidget() final { OnPossibleTargetChange(); }
  void ApplicationContentsDestroyed() final {
    Observe(nullptr);
    OnPossibleTargetChange();
  }

  // Re-evaluates whether a new frame sink or native view should be targeted for
  // capture and notifies the device. If the ApplicationContents instance is no longer
  // being observed, the device is notified that the capture target has been
  // permanently lost.
  void OnPossibleTargetChange() {
    DCHECK_CURRENTLY_ON(HostThread::UI);

    if (web_contents()) {
      viz::FrameSinkId frame_sink_id;
      gfx::NativeView native_view = gfx::NativeView();
      if (auto* const view = GetCurrentView()) {
        // Inside content, down-casting from the public interface class is
        // safe.
        auto* const view_impl = static_cast<ApplicationWindowHostViewBase*>(view);
        frame_sink_id = view_impl->GetFrameSinkId();
        native_view = view_impl->GetNativeView();
      }

      if (frame_sink_id != target_frame_sink_id_) {
        target_frame_sink_id_ = frame_sink_id;
        device_task_runner_->PostTask(
            FROM_HERE,
            base::BindOnce(&ApplicationContentsVideoCaptureDevice::OnTargetChanged,
                           device_, frame_sink_id));
      }

      if (native_view != target_native_view_) {
        target_native_view_ = native_view;
        // Note: CursorRenderer runs on the UI thread. It's also important that
        // SetTargetView() be called in the current stack while |native_view| is
        // known to be a valid pointer. http://crbug.com/818679
        cursor_renderer_->SetTargetView(native_view);
      }
    } else {
      device_task_runner_->PostTask(
          FROM_HERE,
          base::BindOnce(
              &ApplicationContentsVideoCaptureDevice::OnTargetPermanentlyLost,
              device_));
      cursor_renderer_->SetTargetView(gfx::NativeView());
    }
  }

  // |device_| may be dereferenced only by tasks run by |device_task_runner_|.
  const base::WeakPtr<ApplicationContentsVideoCaptureDevice> device_;
  const scoped_refptr<base::SingleThreadTaskRunner> device_task_runner_;

  // Owned by FrameSinkVideoCaptureDevice. This will be valid for the life of
  // FrameTracker because the FrameTracker deleter task will be posted to the UI
  // thread before the CursorRenderer deleter task.
  CursorRenderer* const cursor_renderer_;

  viz::FrameSinkId target_frame_sink_id_;
  gfx::NativeView target_native_view_ = gfx::NativeView();

  DISALLOW_COPY_AND_ASSIGN(FrameTracker);
};

ApplicationContentsVideoCaptureDevice::ApplicationContentsVideoCaptureDevice(
    int render_process_id,
    int main_render_frame_id)
    : tracker_(new FrameTracker(AsWeakPtr(),
                                cursor_renderer(),
                                render_process_id,
                                main_render_frame_id)) {}

ApplicationContentsVideoCaptureDevice::~ApplicationContentsVideoCaptureDevice() = default;

// static
std::unique_ptr<ApplicationContentsVideoCaptureDevice>
ApplicationContentsVideoCaptureDevice::Create(const std::string& device_id) {
  // Parse device_id into render_process_id and main_render_frame_id.
  ApplicationContentsMediaCaptureId media_id;
  if (!ApplicationContentsMediaCaptureId::Parse(device_id, &media_id)) {
    return nullptr;
  }
  return std::make_unique<ApplicationContentsVideoCaptureDevice>(
      media_id.render_process_id, media_id.main_render_frame_id);
}

void ApplicationContentsVideoCaptureDevice::WillStart() {
  HostThread::PostTask(
      HostThread::UI, FROM_HERE,
      base::BindOnce(&FrameTracker::WillStartCapturingApplicationContents,
                     tracker_->AsWeakPtr(),
                     capture_params().SuggestConstraints().max_frame_size));
}

void ApplicationContentsVideoCaptureDevice::DidStop() {
  HostThread::PostTask(
      HostThread::UI, FROM_HERE,
      base::BindOnce(&FrameTracker::DidStopCapturingApplicationContents,
                     tracker_->AsWeakPtr()));
}

}  // namespace host
