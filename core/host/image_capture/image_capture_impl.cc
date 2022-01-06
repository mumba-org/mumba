// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/image_capture/image_capture_impl.h"

#include <utility>

#include "base/bind_helpers.h"
#include "core/host/host_main_loop.h"
#include "core/host/application/media/media_stream_manager.h"
#include "core/host/application/media/video_capture_manager.h"
#include "core/host/host_thread.h"
#include "core/shared/common/content_features.h"
#include "core/shared/common/media_stream_request.h"
#include "media/base/bind_to_current_loop.h"
#include "media/capture/mojom/image_capture_types.h"
#include "media/capture/video/video_capture_device.h"
#include "mojo/public/cpp/bindings/callback_helpers.h"
#include "mojo/public/cpp/bindings/strong_binding.h"

namespace host {

namespace {

void GetPhotoStateOnIOThread(const std::string& source_id,
                             MediaStreamManager* media_stream_manager,
                             ImageCaptureImpl::GetPhotoStateCallback callback) {
  DCHECK_CURRENTLY_ON(HostThread::IO);

  const int session_id =
      media_stream_manager->VideoDeviceIdToSessionId(source_id);

  if (session_id == common::MediaStreamDevice::kNoId)
    return;
  media_stream_manager->video_capture_manager()->GetPhotoState(
      session_id, std::move(callback));
}

void SetOptionsOnIOThread(const std::string& source_id,
                          MediaStreamManager* media_stream_manager,
                          media::mojom::PhotoSettingsPtr settings,
                          ImageCaptureImpl::SetOptionsCallback callback) {
  DCHECK_CURRENTLY_ON(HostThread::IO);

  const int session_id =
      media_stream_manager->VideoDeviceIdToSessionId(source_id);

  if (session_id == common::MediaStreamDevice::kNoId)
    return;
  media_stream_manager->video_capture_manager()->SetPhotoOptions(
      session_id, std::move(settings), std::move(callback));
}

void TakePhotoOnIOThread(const std::string& source_id,
                         MediaStreamManager* media_stream_manager,
                         ImageCaptureImpl::TakePhotoCallback callback) {
  DCHECK_CURRENTLY_ON(HostThread::IO);

  const int session_id =
      media_stream_manager->VideoDeviceIdToSessionId(source_id);

  if (session_id == common::MediaStreamDevice::kNoId)
    return;
  media_stream_manager->video_capture_manager()->TakePhoto(session_id,
                                                           std::move(callback));
}

}  // anonymous namespace

ImageCaptureImpl::ImageCaptureImpl() {}

ImageCaptureImpl::~ImageCaptureImpl() {}

// static
void ImageCaptureImpl::Create(
    media::mojom::ImageCaptureRequest request) {
  if (!base::FeatureList::IsEnabled(features::kImageCaptureAPI))
    return;

  mojo::MakeStrongBinding(std::make_unique<ImageCaptureImpl>(),
                          std::move(request));
}

void ImageCaptureImpl::GetPhotoState(const std::string& source_id,
                                     GetPhotoStateCallback callback) {
  DCHECK_CURRENTLY_ON(HostThread::UI);

  GetPhotoStateCallback scoped_callback =
      mojo::WrapCallbackWithDefaultInvokeIfNotRun(
          media::BindToCurrentLoop(std::move(callback)),
          mojo::CreateEmptyPhotoState());
  HostThread::PostTask(
      HostThread::IO, FROM_HERE,
      base::BindOnce(&GetPhotoStateOnIOThread, source_id,
                     HostMainLoop::GetInstance()->media_stream_manager(),
                     std::move(scoped_callback)));
}

void ImageCaptureImpl::SetOptions(const std::string& source_id,
                                  media::mojom::PhotoSettingsPtr settings,
                                  SetOptionsCallback callback) {
  DCHECK_CURRENTLY_ON(HostThread::UI);

  SetOptionsCallback scoped_callback =
      mojo::WrapCallbackWithDefaultInvokeIfNotRun(
          media::BindToCurrentLoop(std::move(callback)), false);
  HostThread::PostTask(
      HostThread::IO, FROM_HERE,
      base::BindOnce(&SetOptionsOnIOThread, source_id,
                     HostMainLoop::GetInstance()->media_stream_manager(),
                     std::move(settings), std::move(scoped_callback)));
}

void ImageCaptureImpl::TakePhoto(const std::string& source_id,
                                 TakePhotoCallback callback) {
  DCHECK_CURRENTLY_ON(HostThread::UI);

  TakePhotoCallback scoped_callback =
      mojo::WrapCallbackWithDefaultInvokeIfNotRun(
          media::BindToCurrentLoop(std::move(callback)),
          media::mojom::Blob::New());
  HostThread::PostTask(
      HostThread::IO, FROM_HERE,
      base::BindOnce(&TakePhotoOnIOThread, source_id,
                     HostMainLoop::GetInstance()->media_stream_manager(),
                     std::move(scoped_callback)));
}

}  // namespace host
