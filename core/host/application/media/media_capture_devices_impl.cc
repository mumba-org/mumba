// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/application/media/media_capture_devices_impl.h"

#include "core/host/host_main_loop.h"
#include "core/host/application/media/media_stream_manager.h"
#include "core/host/host_thread.h"

namespace host {

namespace {

void EnsureMonitorCaptureDevices() {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  HostThread::PostTask(
      HostThread::IO, FROM_HERE,
      base::BindOnce(
          &MediaStreamManager::EnsureDeviceMonitorStarted,
          base::Unretained(
              HostMainLoop::GetInstance()->media_stream_manager())));
}

}  // namespace

MediaCaptureDevices* MediaCaptureDevices::GetInstance() {
  return MediaCaptureDevicesImpl::GetInstance();
}

MediaCaptureDevicesImpl* MediaCaptureDevicesImpl::GetInstance() {
  MediaCaptureDevicesImpl* instance = base::Singleton<MediaCaptureDevicesImpl>::get();
  DLOG(INFO) << "MediaCaptureDevicesImpl::GetInstance: instance = " << instance;
  return instance;
}

const common::MediaStreamDevices&
MediaCaptureDevicesImpl::GetAudioCaptureDevices() {
  DLOG(INFO) << "MediaCaptureDevicesImpl::GetAudioCaptureDevices";
  DCHECK_CURRENTLY_ON(HostThread::UI);
  if (!devices_enumerated_) {
    EnsureMonitorCaptureDevices();
    devices_enumerated_ = true;
  }
  return audio_devices_;
}

const common::MediaStreamDevices&
MediaCaptureDevicesImpl::GetVideoCaptureDevices() {
  DLOG(INFO) << "MediaCaptureDevicesImpl::GetVideoCaptureDevices";
  DCHECK_CURRENTLY_ON(HostThread::UI);
  if (!devices_enumerated_) {
    EnsureMonitorCaptureDevices();
    devices_enumerated_ = true;
  }
  return video_devices_;
}

void MediaCaptureDevicesImpl::AddVideoCaptureObserver(
    media::VideoCaptureObserver* observer) {
  DLOG(INFO) << "MediaCaptureDevicesImpl::AddVideoCaptureObserver";
  MediaStreamManager* media_stream_manager =
      HostMainLoop::GetInstance()->media_stream_manager();
  if (media_stream_manager != nullptr) {
    HostThread::PostTask(
        HostThread::IO, FROM_HERE,
        base::BindOnce(&MediaStreamManager::AddVideoCaptureObserver,
                       base::Unretained(media_stream_manager), observer));
  } else {
    DVLOG(3) << "media_stream_manager is null.";
  }
}

void MediaCaptureDevicesImpl::RemoveAllVideoCaptureObservers() {
  DLOG(INFO) << "MediaCaptureDevicesImpl::RemoveAllVideoCaptureObservers";
  
  MediaStreamManager* media_stream_manager =
      HostMainLoop::GetInstance()->media_stream_manager();
  if (media_stream_manager != nullptr) {
    HostThread::PostTask(
        HostThread::IO, FROM_HERE,
        base::BindOnce(&MediaStreamManager::RemoveAllVideoCaptureObservers,
                       base::Unretained(media_stream_manager)));
  } else {
    DVLOG(3) << "media_stream_manager is null.";
  }
}

void MediaCaptureDevicesImpl::OnAudioCaptureDevicesChanged(
    const common::MediaStreamDevices& devices) {
  DLOG(INFO) << "MediaCaptureDevicesImpl::OnAudioCaptureDevicesChanged";

  if (HostThread::CurrentlyOn(HostThread::UI)) {
    UpdateAudioDevicesOnUIThread(devices);
  } else {
    HostThread::PostTask(
        HostThread::UI, FROM_HERE,
        base::BindOnce(&MediaCaptureDevicesImpl::UpdateAudioDevicesOnUIThread,
                       base::Unretained(this), devices));
  }
}

void MediaCaptureDevicesImpl::OnVideoCaptureDevicesChanged(
    const common::MediaStreamDevices& devices) {
  DLOG(INFO) << "MediaCaptureDevicesImpl::OnVideoCaptureDevicesChanged";
  if (HostThread::CurrentlyOn(HostThread::UI)) {
    UpdateVideoDevicesOnUIThread(devices);
  } else {
    HostThread::PostTask(
        HostThread::UI, FROM_HERE,
        base::BindOnce(&MediaCaptureDevicesImpl::UpdateVideoDevicesOnUIThread,
                       base::Unretained(this), devices));
  }
}

MediaCaptureDevicesImpl::MediaCaptureDevicesImpl()
    : devices_enumerated_(false) {
}

MediaCaptureDevicesImpl::~MediaCaptureDevicesImpl() {
}

void MediaCaptureDevicesImpl::UpdateAudioDevicesOnUIThread(
    const common::MediaStreamDevices& devices) {
  DLOG(INFO) << "MediaCaptureDevicesImpl::UpdateAudioDevicesOnUIThread";
  
  DCHECK_CURRENTLY_ON(HostThread::UI);
  devices_enumerated_ = true;
  audio_devices_ = devices;
}

void MediaCaptureDevicesImpl::UpdateVideoDevicesOnUIThread(
    const common::MediaStreamDevices& devices) {
  DLOG(INFO) << "MediaCaptureDevicesImpl::UpdateVideoDevicesOnUIThread";
  DCHECK_CURRENTLY_ON(HostThread::UI);
  devices_enumerated_ = true;
  video_devices_ = devices;
}

}  // namespace host
