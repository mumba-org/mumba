// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_RENDERER_MEDIA_STREAM_MEDIA_STREAM_DEVICE_OBSERVER_H_
#define CONTENT_RENDERER_MEDIA_STREAM_MEDIA_STREAM_DEVICE_OBSERVER_H_

#include <list>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "base/gtest_prod_util.h"
#include "base/macros.h"
#include "base/memory/weak_ptr.h"
#include "base/threading/thread_checker.h"
#include "core/shared/common/content_export.h"
#include "core/shared/common/media/media_stream.mojom.h"
#include "core/shared/common/media_stream_request.h"
#include "core/shared/application/application_window_dispatcher.h"
#include "mojo/public/cpp/bindings/binding.h"
#include "services/service_manager/public/cpp/binder_registry.h"

namespace application {

class MediaStreamDispatcherEventHandler;

// This class implements a Mojo object that receives device stopped
// notifications and forwards them to MediaStreamDispatcherEventHandler.
class CONTENT_EXPORT MediaStreamDeviceObserver
    : public ApplicationWindowDispatcherObserver,
      public common::mojom::MediaStreamDeviceObserver {
 public:
  explicit MediaStreamDeviceObserver(ApplicationWindowDispatcher* dispatcher);
  ~MediaStreamDeviceObserver() override;

  // Get all the media devices of video capture, e.g. webcam. This is the set
  // of devices that should be suspended when the content frame is no longer
  // being shown to the user.
  common::MediaStreamDevices GetNonScreenCaptureDevices();

  void AddStream(
      const std::string& label,
      const common::MediaStreamDevices& audio_devices,
      const common::MediaStreamDevices& video_devices,
      const base::WeakPtr<MediaStreamDispatcherEventHandler>& event_handler);
  void AddStream(const std::string& label, const common::MediaStreamDevice& device);
  bool RemoveStream(const std::string& label);
  void RemoveStreamDevice(const common::MediaStreamDevice& device);

  // Get the video session_id given a label. The label identifies a stream.
  int video_session_id(const std::string& label);
  // Returns an audio session_id given a label.
  int audio_session_id(const std::string& label);

 private:
  FRIEND_TEST_ALL_PREFIXES(MediaStreamDeviceObserverTest,
                           GetNonScreenCaptureDevices);

  // Private class for keeping track of opened devices and who have
  // opened it.
  struct Stream;

  // RenderFrameObserver override.
  void OnInterfaceRequestForFrame(
      const std::string& interface_name,
      mojo::ScopedMessagePipeHandle* interface_pipe) override;
  //void OnDestruct() override;

  // common::mojom::MediaStreamDeviceObserver implementation.
  void OnDeviceStopped(const std::string& label,
                       const common::MediaStreamDevice& device) override;

  void BindMediaStreamDeviceObserverRequest(
      common::mojom::MediaStreamDeviceObserverRequest request);

  mojo::Binding<common::mojom::MediaStreamDeviceObserver> binding_;

  // Used for DCHECKs so methods calls won't execute in the wrong thread.
  base::ThreadChecker thread_checker_;

  typedef std::map<std::string, Stream> LabelStreamMap;
  LabelStreamMap label_stream_map_;

  service_manager::BinderRegistry registry_;

  DISALLOW_COPY_AND_ASSIGN(MediaStreamDeviceObserver);
};

}  // namespace application

#endif  // CONTENT_RENDERER_MEDIA_STREAM_MEDIA_STREAM_DEVICE_OBSERVER_H_