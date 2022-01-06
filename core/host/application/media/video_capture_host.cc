// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/application/media/video_capture_host.h"

#include <memory>

#include "base/bind.h"
#include "base/bind_helpers.h"
#include "core/host/host_main_loop.h"
#include "core/host/application/media/media_stream_manager.h"
#include "core/host/application/media/video_capture_manager.h"
#include "core/host/application/application_process_host.h"
#include "core/host/host_thread.h"
#include "mojo/common/values_struct_traits.h"
#include "mojo/public/cpp/bindings/strong_binding.h"

namespace host {

VideoCaptureHost::ApplicationProcessHostDelegate::~ApplicationProcessHostDelegate() =
    default;

// Looks up a ApplicationProcessHost on demand based on a given |render_process_id|
// and invokes OnMediaStreamAdded() and OnMediaStreamRemoved(). It should be
// called and destroyed on UI thread.
class VideoCaptureHost::ApplicationProcessHostDelegateImpl
    : public VideoCaptureHost::ApplicationProcessHostDelegate {
 public:
  explicit ApplicationProcessHostDelegateImpl(uint32_t render_process_id)
      : render_process_id_(render_process_id) {}

  ~ApplicationProcessHostDelegateImpl() override {
    DCHECK_CURRENTLY_ON(HostThread::UI);
  }

  // Helper functions that are used for notifying Browser-side ApplicationProcessHost
  // if renderer is currently consuming video capture. This information is then
  // used to determine if the renderer process should be backgrounded or not.
  void NotifyStreamAdded() override {
    DCHECK_CURRENTLY_ON(HostThread::UI);
    ApplicationProcessHost* host = ApplicationProcessHost::FromID(render_process_id_);
    if (host)
      host->OnMediaStreamAdded();
  }

  void NotifyStreamRemoved() override {
    DCHECK_CURRENTLY_ON(HostThread::UI);
    ApplicationProcessHost* host = ApplicationProcessHost::FromID(render_process_id_);
    if (host)
      host->OnMediaStreamRemoved();
  }

 private:
  const uint32_t render_process_id_;
  DISALLOW_COPY_AND_ASSIGN(ApplicationProcessHostDelegateImpl);
};

VideoCaptureHost::VideoCaptureHost(uint32_t render_process_id,
                                   MediaStreamManager* media_stream_manager)
    : VideoCaptureHost(
          std::make_unique<ApplicationProcessHostDelegateImpl>(render_process_id),
          media_stream_manager) {}

VideoCaptureHost::VideoCaptureHost(
    std::unique_ptr<ApplicationProcessHostDelegate> delegate,
    MediaStreamManager* media_stream_manager)
    : render_process_host_delegate_(std::move(delegate)),
      media_stream_manager_(media_stream_manager),
      weak_factory_(this) {
  DVLOG(1) << __func__;
  DCHECK_CURRENTLY_ON(HostThread::IO);
}

// static
void VideoCaptureHost::Create(uint32_t render_process_id,
                              MediaStreamManager* media_stream_manager,
                              media::mojom::VideoCaptureHostRequest request) {
  DVLOG(1) << __func__;
  DCHECK_CURRENTLY_ON(HostThread::IO);
  mojo::MakeStrongBinding(std::make_unique<VideoCaptureHost>(
                              render_process_id, media_stream_manager),
                          std::move(request));
}

VideoCaptureHost::~VideoCaptureHost() {
  DCHECK_CURRENTLY_ON(HostThread::IO);
  for (auto it = controllers_.begin(); it != controllers_.end(); ) {
    const base::WeakPtr<VideoCaptureController>& controller = it->second;
    //VideoCaptureController* controller = it->second;
    if (controller) {
      const VideoCaptureControllerID controller_id(it->first);
      media_stream_manager_->video_capture_manager()->DisconnectClient(
          controller.get(), controller_id, this, false);
          //controller, controller_id, this, false);
      ++it;
    } else {
      // Remove the entry for this controller_id so that when the controller
      // is added, the controller will be notified to stop for this client
      // in DoControllerAdded.
      controllers_.erase(it++);
    }
  }

  NotifyAllStreamsRemoved();
  HostThread::DeleteSoon(HostThread::UI, FROM_HERE,
                            render_process_host_delegate_.release());
}

void VideoCaptureHost::OnError(VideoCaptureControllerID controller_id) {
  DVLOG(1) << __func__;
  DCHECK_CURRENTLY_ON(HostThread::IO);
  HostThread::PostTask(
      HostThread::IO, FROM_HERE,
      base::BindOnce(&VideoCaptureHost::DoError, base::Unretained(this),//weak_factory_.GetWeakPtr(),
                     controller_id));
}

void VideoCaptureHost::OnBufferCreated(VideoCaptureControllerID controller_id,
                                       mojo::ScopedSharedBufferHandle handle,
                                       int length,
                                       int buffer_id) {
  DCHECK_CURRENTLY_ON(HostThread::IO);
  if (controllers_.find(controller_id) == controllers_.end())
    return;

  if (base::ContainsKey(device_id_to_observer_map_, controller_id)) {
    device_id_to_observer_map_[controller_id]->OnBufferCreated(
        buffer_id, std::move(handle));
  }
}

void VideoCaptureHost::OnBufferDestroyed(VideoCaptureControllerID controller_id,
                                         int buffer_id) {
  DCHECK_CURRENTLY_ON(HostThread::IO);
  if (controllers_.find(controller_id) == controllers_.end())
    return;

  if (base::ContainsKey(device_id_to_observer_map_, controller_id))
    device_id_to_observer_map_[controller_id]->OnBufferDestroyed(buffer_id);
}

void VideoCaptureHost::OnBufferReady(
    VideoCaptureControllerID controller_id,
    int buffer_id,
    const media::mojom::VideoFrameInfoPtr& frame_info) {
  DCHECK_CURRENTLY_ON(HostThread::IO);
  if (controllers_.find(controller_id) == controllers_.end())
    return;

  if (!base::ContainsKey(device_id_to_observer_map_, controller_id))
    return;

  device_id_to_observer_map_[controller_id]->OnBufferReady(buffer_id,
                                                           frame_info.Clone());
}

void VideoCaptureHost::OnEnded(VideoCaptureControllerID controller_id) {
  DVLOG(1) << __func__;
  DCHECK_CURRENTLY_ON(HostThread::IO);
  HostThread::PostTask(
      HostThread::IO, FROM_HERE,
      base::BindOnce(&VideoCaptureHost::DoEnded, base::Unretained(this),//weak_factory_.GetWeakPtr(),
                     controller_id));
}

void VideoCaptureHost::OnStarted(VideoCaptureControllerID controller_id) {
  DVLOG(1) << __func__;
  DCHECK_CURRENTLY_ON(HostThread::IO);
  if (controllers_.find(controller_id) == controllers_.end())
    return;

  if (base::ContainsKey(device_id_to_observer_map_, controller_id)) {
    device_id_to_observer_map_[controller_id]->OnStateChanged(
        media::mojom::VideoCaptureState::STARTED);
    NotifyStreamAdded();
  }
}

void VideoCaptureHost::OnStartedUsingGpuDecode(VideoCaptureControllerID id) {}

void VideoCaptureHost::Start(int32_t device_id,
                             int32_t session_id,
                             const media::VideoCaptureParams& params,
                             media::mojom::VideoCaptureObserverPtr observer) {
  DVLOG(1) << __func__ << " session_id=" << session_id
           << ", device_id=" << device_id << ", format="
           << media::VideoCaptureFormat::ToString(params.requested_format);
  DCHECK_CURRENTLY_ON(HostThread::IO);

  DCHECK(!base::ContainsKey(device_id_to_observer_map_, device_id));
  device_id_to_observer_map_[device_id] = std::move(observer);

  const VideoCaptureControllerID controller_id(device_id);
  if (controllers_.find(controller_id) != controllers_.end()) {
    device_id_to_observer_map_[device_id]->OnStateChanged(
        media::mojom::VideoCaptureState::STARTED);
    NotifyStreamAdded();
    return;
  }

  controllers_[controller_id] = base::WeakPtr<VideoCaptureController>();
  media_stream_manager_->video_capture_manager()->ConnectClient(
      session_id, params, controller_id, this,
       base::Bind(&VideoCaptureHost::OnControllerAdded,
                  weak_factory_.GetWeakPtr(), device_id));
                  //base::Unretained(this), device_id));
}

void VideoCaptureHost::Stop(int32_t device_id) {
  DVLOG(1) << __func__ << " " << device_id;
  DCHECK_CURRENTLY_ON(HostThread::IO);

  VideoCaptureControllerID controller_id(device_id);

  if (base::ContainsKey(device_id_to_observer_map_, device_id)) {
    device_id_to_observer_map_[device_id]->OnStateChanged(
        media::mojom::VideoCaptureState::STOPPED);
  }
  device_id_to_observer_map_.erase(controller_id);

  DeleteVideoCaptureController(controller_id, false);
  NotifyStreamRemoved();
}

void VideoCaptureHost::Pause(int32_t device_id) {
  DVLOG(1) << __func__ << " " << device_id;
  DCHECK_CURRENTLY_ON(HostThread::IO);

  VideoCaptureControllerID controller_id(device_id);
  auto it = controllers_.find(controller_id);
  if (it == controllers_.end() || !it->second)
    return;

  media_stream_manager_->video_capture_manager()->PauseCaptureForClient(
      it->second.get(), controller_id, this);
      //it->second, controller_id, this);
  if (base::ContainsKey(device_id_to_observer_map_, device_id)) {
    device_id_to_observer_map_[device_id]->OnStateChanged(
        media::mojom::VideoCaptureState::PAUSED);
  }
}

void VideoCaptureHost::Resume(int32_t device_id,
                              int32_t session_id,
                              const media::VideoCaptureParams& params) {
  DVLOG(1) << __func__ << " " << device_id;
  DCHECK_CURRENTLY_ON(HostThread::IO);

  VideoCaptureControllerID controller_id(device_id);
  auto it = controllers_.find(controller_id);
  if (it == controllers_.end() || !it->second)
    return;

  media_stream_manager_->video_capture_manager()->ResumeCaptureForClient(
      session_id, params, it->second.get(), controller_id, this);
      //session_id, params, it->second, controller_id, this);
  if (base::ContainsKey(device_id_to_observer_map_, device_id)) {
    device_id_to_observer_map_[device_id]->OnStateChanged(
        media::mojom::VideoCaptureState::RESUMED);
  }
}

void VideoCaptureHost::RequestRefreshFrame(int32_t device_id) {
  DVLOG(1) << __func__ << " " << device_id;
  DCHECK_CURRENTLY_ON(HostThread::IO);

  VideoCaptureControllerID controller_id(device_id);
  auto it = controllers_.find(controller_id);
  if (it == controllers_.end())
    return;

  if (VideoCaptureController* controller = it->second.get()) {
  //if (VideoCaptureController* controller = it->second) {
    media_stream_manager_->video_capture_manager()
        ->RequestRefreshFrameForClient(controller);
  }
}

void VideoCaptureHost::ReleaseBuffer(int32_t device_id,
                                     int32_t buffer_id,
                                     double consumer_resource_utilization) {
  DCHECK_CURRENTLY_ON(HostThread::IO);

  VideoCaptureControllerID controller_id(device_id);
  auto it = controllers_.find(controller_id);
  if (it == controllers_.end())
    return;

  const base::WeakPtr<VideoCaptureController>& controller = it->second;
  //VideoCaptureController* controller = it->second;
  if (controller) {
    controller->ReturnBuffer(controller_id, this, buffer_id,
                             consumer_resource_utilization);
  }
}

void VideoCaptureHost::GetDeviceSupportedFormats(
    int32_t device_id,
    int32_t session_id,
    GetDeviceSupportedFormatsCallback callback) {
  DVLOG(1) << __func__ << " " << device_id;
  DCHECK_CURRENTLY_ON(HostThread::IO);
  media::VideoCaptureFormats supported_formats;
  if (!media_stream_manager_->video_capture_manager()
           ->GetDeviceSupportedFormats(session_id, &supported_formats)) {
    DLOG(WARNING) << "Could not retrieve device supported formats";
  }
  std::move(callback).Run(supported_formats);
}

void VideoCaptureHost::GetDeviceFormatsInUse(
    int32_t device_id,
    int32_t session_id,
    GetDeviceFormatsInUseCallback callback) {
  DVLOG(1) << __func__ << " " << device_id;
  DCHECK_CURRENTLY_ON(HostThread::IO);
  media::VideoCaptureFormats formats_in_use;
  if (!media_stream_manager_->video_capture_manager()->GetDeviceFormatsInUse(
           session_id, &formats_in_use)) {
    DLOG(WARNING) << "Could not retrieve device format(s) in use";
  }
  std::move(callback).Run(formats_in_use);
}

void VideoCaptureHost::DoError(VideoCaptureControllerID controller_id) {
  DVLOG(1) << __func__;
  DCHECK_CURRENTLY_ON(HostThread::IO);
  if (controllers_.find(controller_id) == controllers_.end())
    return;

  if (base::ContainsKey(device_id_to_observer_map_, controller_id)) {
    device_id_to_observer_map_[controller_id]->OnStateChanged(
        media::mojom::VideoCaptureState::FAILED);
  }

  DeleteVideoCaptureController(controller_id, true);
  NotifyStreamRemoved();
}

void VideoCaptureHost::DoEnded(VideoCaptureControllerID controller_id) {
  DVLOG(1) << __func__;
  DCHECK_CURRENTLY_ON(HostThread::IO);
  if (controllers_.find(controller_id) == controllers_.end())
    return;

  if (base::ContainsKey(device_id_to_observer_map_, controller_id)) {
    device_id_to_observer_map_[controller_id]->OnStateChanged(
        media::mojom::VideoCaptureState::ENDED);
  }

  DeleteVideoCaptureController(controller_id, false);
  NotifyStreamRemoved();
}

void VideoCaptureHost::OnControllerAdded(
     int device_id,
     const base::WeakPtr<VideoCaptureController>& controller) {
//void VideoCaptureHost::OnControllerAdded(
//  int device_id,
//  VideoCaptureController* controller) {
  DCHECK_CURRENTLY_ON(HostThread::IO);
  VideoCaptureControllerID controller_id(device_id);
  auto it = controllers_.find(controller_id);
  if (it == controllers_.end()) {
    if (controller) {
      media_stream_manager_->video_capture_manager()->DisconnectClient(
          controller.get(), controller_id, this, false);
          //controller, controller_id, this, false);
    }
    return;
  }

  if (!controller) {
    if (base::ContainsKey(device_id_to_observer_map_, controller_id)) {
      device_id_to_observer_map_[device_id]->OnStateChanged(
          media::mojom::VideoCaptureState::FAILED);
    }
    controllers_.erase(controller_id);
    return;
  }

  DCHECK(!it->second);
  it->second = controller;
}

void VideoCaptureHost::DeleteVideoCaptureController(
    VideoCaptureControllerID controller_id, bool on_error) {
  DCHECK_CURRENTLY_ON(HostThread::IO);

  auto it = controllers_.find(controller_id);
  if (it == controllers_.end())
    return;

  const base::WeakPtr<VideoCaptureController> controller = it->second;
  //VideoCaptureController* controller = it->second;
  controllers_.erase(it);
  if (!controller)
    return;

  media_stream_manager_->video_capture_manager()->DisconnectClient(
      //controller, controller_id, this, on_error);
      controller.get(), controller_id, this, on_error);
}

void VideoCaptureHost::NotifyStreamAdded() {
  DCHECK_CURRENTLY_ON(HostThread::IO);
  ++number_of_active_streams_;
  // base::Unretained() usage is safe because |render_process_host_delegate_|
  // is destroyed on UI thread.
  HostThread::PostTask(
      HostThread::UI, FROM_HERE,
      base::BindOnce(&ApplicationProcessHostDelegate::NotifyStreamAdded,
                     base::Unretained(render_process_host_delegate_.get())));
}

void VideoCaptureHost::NotifyStreamRemoved() {
  DCHECK_CURRENTLY_ON(HostThread::IO);
  // DoError() from camera side failure can be followed by Stop() from JS
  // side, so we should check before going to negative.
  // TODO(emircan): Investigate all edge cases and add more browsertests.
  // https://crbug.com/754765
  if (number_of_active_streams_ == 0)
    return;
  --number_of_active_streams_;
  // base::Unretained() usage is safe because |render_process_host_delegate_| is
  // destroyed on UI thread.
  HostThread::PostTask(
      HostThread::UI, FROM_HERE,
      base::BindOnce(&ApplicationProcessHostDelegate::NotifyStreamRemoved,
                     base::Unretained(render_process_host_delegate_.get())));
}

void VideoCaptureHost::NotifyAllStreamsRemoved() {
  DCHECK_CURRENTLY_ON(HostThread::IO);
  while (number_of_active_streams_ > 0)
    NotifyStreamRemoved();
}

}  // namespace host
