// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_MEDIA_WEBRTC_MEDIA_CAPTURE_DEVICES_DISPATCHER_H_
#define CHROME_BROWSER_MEDIA_WEBRTC_MEDIA_CAPTURE_DEVICES_DISPATCHER_H_

#include <list>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "base/callback.h"
#include "base/macros.h"
#include "base/memory/singleton.h"
#include "base/observer_list.h"
#include "core/host/media/media_observer.h"
#include "core/host/application/application_contents_delegate.h"
#include "core/shared/common/media_stream_request.h"

//namespace extensions {
//class Extension;
//}

//namespace user_prefs {
//class PrefRegistrySyncable;
//}

namespace host {
class DesktopStreamsRegistry;
class MediaAccessHandler;
class MediaStreamCaptureIndicator;
class Workspace;

// This singleton is used to receive updates about media events from the content
// layer.
class MediaCaptureDevicesDispatcher : public MediaObserver {
 public:
  class Observer {
   public:
    // Handle an information update consisting of a up-to-date audio capture
    // device lists. This happens when a microphone is plugged in or unplugged.
    virtual void OnUpdateAudioDevices(
        const common::MediaStreamDevices& devices) {}

    // Handle an information update consisting of a up-to-date video capture
    // device lists. This happens when a camera is plugged in or unplugged.
    virtual void OnUpdateVideoDevices(
        const common::MediaStreamDevices& devices) {}

    // Handle an information update related to a media stream request.
    virtual void OnRequestUpdate(
        int render_process_id,
        int render_frame_id,
        common::MediaStreamType stream_type,
        const MediaRequestState state) {}

    // Handle an information update that a new stream is being created.
    virtual void OnCreatingAudioStream(int render_process_id,
                                       int render_frame_id) {}

    virtual ~Observer() {}
  };

  static MediaCaptureDevicesDispatcher* GetInstance();

  // Registers the preferences related to Media Stream default devices.
  //static void RegisterProfilePrefs(user_prefs::PrefRegistrySyncable* registry);

  // Returns true if the security origin is associated with casting.
  static bool IsOriginForCasting(const GURL& origin);

  // Methods for observers. Called on UI thread.
  // Observers should add themselves on construction and remove themselves
  // on destruction.
  void AddObserver(Observer* observer);
  void RemoveObserver(Observer* observer);
  const common::MediaStreamDevices& GetAudioCaptureDevices();
  const common::MediaStreamDevices& GetVideoCaptureDevices();

  // Method called from WebCapturerDelegate implementations to process access
  // requests. |extension| is set to NULL if request was made from a drive-by
  // page.
  void ProcessMediaAccessRequest(
      ApplicationContents* app_contents,
      const common::MediaStreamRequest& request,
      const common::MediaResponseCallback& callback);//,
      //const extensions::Extension* extension);

  // Method called from WebCapturerDelegate implementations to check media
  // access permission. Note that this does not query the user.
  bool CheckMediaAccessPermission(ApplicationWindowHost* render_frame_host,
                                  const GURL& security_origin,
                                  common::MediaStreamType type);

    // Helper to get the default devices which can be used by the media request.
  // Uses the first available devices if the default devices are not available.
  // If the return list is empty, it means there is no available device on the
  // OS.
  // Called on the UI thread.
  void GetDefaultDevicesForProfile(scoped_refptr<Workspace> profile,
                                   bool audio,
                                   bool video,
                                   common::MediaStreamDevices* devices);

  // Helper to get default device IDs. If the returned value is an empty string,
  // it means that there is no default device for the given device |type|. The
  // only supported |type| values are content::MEDIA_DEVICE_AUDIO_CAPTURE and
  // content::MEDIA_DEVICE_VIDEO_CAPTURE.
  // Must be called on the UI thread.
  std::string GetDefaultDeviceIDForProfile(scoped_refptr<Workspace> profile,
                                           common::MediaStreamType type);

  // Helpers for picking particular requested devices, identified by raw id.
  // If the device requested is not available it will return NULL.
  const common::MediaStreamDevice*
  GetRequestedAudioDevice(const std::string& requested_audio_device_id);
  const common::MediaStreamDevice*
  GetRequestedVideoDevice(const std::string& requested_video_device_id);

  // Returns the first available audio or video device, or NULL if no devices
  // are available.
  const common::MediaStreamDevice* GetFirstAvailableAudioDevice();
  const common::MediaStreamDevice* GetFirstAvailableVideoDevice();

  // Unittests that do not require actual device enumeration should call this
  // API on the singleton. It is safe to call this multiple times on the
  // signleton.
  void DisableDeviceEnumerationForTesting();

  // Overridden from content::MediaObserver:
  void OnAudioCaptureDevicesChanged() override;
  void OnVideoCaptureDevicesChanged() override;
  void OnMediaRequestStateChanged(int render_process_id,
                                  int render_frame_id,
                                  int page_request_id,
                                  const GURL& security_origin,
                                  common::MediaStreamType stream_type,
                                  MediaRequestState state) override;
  void OnCreatingAudioStream(int render_process_id,
                             int render_frame_id) override;
  void OnSetCapturingLinkSecured(int render_process_id,
                                 int render_frame_id,
                                 int page_request_id,
                                 common::MediaStreamType stream_type,
                                 bool is_secure) override;

  scoped_refptr<MediaStreamCaptureIndicator> GetMediaStreamCaptureIndicator();

  DesktopStreamsRegistry* GetDesktopStreamsRegistry();

  // Return true if there is any ongoing insecured capturing. The capturing is
  // deemed secure if all connected video sinks are reported secure and the
  // extension is trusted.
  bool IsInsecureCapturingInProgress(int render_process_id,
                                     int render_frame_id);

  // Only for testing.
  void SetTestAudioCaptureDevices(const common::MediaStreamDevices& devices);
  void SetTestVideoCaptureDevices(const common::MediaStreamDevices& devices);

 private:
  friend struct base::DefaultSingletonTraits<MediaCaptureDevicesDispatcher>;

  MediaCaptureDevicesDispatcher();
  ~MediaCaptureDevicesDispatcher() override;

  // Called by the MediaObserver() functions, executed on UI thread.
  void NotifyAudioDevicesChangedOnUIThread();
  void NotifyVideoDevicesChangedOnUIThread();
  void UpdateMediaRequestStateOnUIThread(
      int render_process_id,
      int render_frame_id,
      int page_request_id,
      const GURL& security_origin,
      common::MediaStreamType stream_type,
      MediaRequestState state);
  void OnCreatingAudioStreamOnUIThread(int render_process_id,
                                       int render_frame_id);
  void UpdateCapturingLinkSecured(int render_process_id,
                                  int render_frame_id,
                                  int page_request_id,
                                  common::MediaStreamType stream_type,
                                  bool is_secure);

  // Only for testing, a list of cached audio capture devices.
  common::MediaStreamDevices test_audio_devices_;

  // Only for testing, a list of cached video capture devices.
  common::MediaStreamDevices test_video_devices_;

  // A list of observers for the device update notifications.
  base::ObserverList<Observer> observers_;

  // Flag used by unittests to disable device enumeration.
  bool is_device_enumeration_disabled_;

  scoped_refptr<MediaStreamCaptureIndicator> media_stream_capture_indicator_;

  std::unique_ptr<DesktopStreamsRegistry> desktop_streams_registry_;

  // Handlers for processing media access requests.
  std::vector<std::unique_ptr<MediaAccessHandler>> media_access_handlers_;

  DISALLOW_COPY_AND_ASSIGN(MediaCaptureDevicesDispatcher);
};

}

#endif  // CHROME_BROWSER_MEDIA_WEBRTC_MEDIA_CAPTURE_DEVICES_DISPATCHER_H_
