// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_MEDIA_MEDIA_INTERNALS_H_
#define MUMBA_HOST_MEDIA_MEDIA_INTERNALS_H_

#include <list>
#include <map>
#include <memory>
#include <string>
#include <tuple>
#include <vector>

#include "base/callback_forward.h"
#include "base/compiler_specific.h"
#include "base/macros.h"
#include "base/strings/string16.h"
#include "base/synchronization/lock.h"
#include "base/values.h"
#include "core/shared/common/content_export.h"
#include "core/host/notification_observer.h"
#include "core/host/notification_registrar.h"
#include "media/audio/audio_logging.h"
#include "media/base/media_log.h"
#include "media/capture/video/video_capture_device_descriptor.h"
#include "media/capture/video_capture_types.h"
#include "media/mojo/interfaces/audio_logging.mojom.h"

namespace media {
struct MediaLogEvent;
}

namespace host {

// This class stores information about currently active media.
// TODO(crbug.com/812557): Remove inheritance from media::AudioLogFactory once
// the creation of the AudioManager instance moves to the audio service.
class CONTENT_EXPORT MediaInternals : public media::AudioLogFactory,
                                      public NotificationObserver {
 public:
  // Called with the update string.
  typedef base::Callback<void(const base::string16&)> UpdateCallback;

  static MediaInternals* GetInstance();

  ~MediaInternals() override;

  // NotificationObserver implementation.
  void Observe(int type,
               const NotificationSource& source,
               const NotificationDetails& details) override;

  // Called when a MediaEvent occurs.
  void OnMediaEvents(int render_process_id,
                     const std::vector<media::MediaLogEvent>& events);

  // Add/remove update callbacks (see above). Must be called on the UI thread.
  // The callbacks must also be fired on UI thread.
  void AddUpdateCallback(const UpdateCallback& callback);
  void RemoveUpdateCallback(const UpdateCallback& callback);

  // Whether there are any update callbacks available. Can be called on any
  // thread.
  bool CanUpdate();

  // Replay all saved media events.
  void SendHistoricalMediaEvents();

  // Sends all audio cached data to each registered UpdateCallback.
  void SendAudioStreamData();

  // Sends all video capture capabilities cached data to each registered
  // UpdateCallback.
  void SendVideoCaptureDeviceCapabilities();

  // Called to inform of the capabilities enumerated for video devices.
  void UpdateVideoCaptureDeviceCapabilities(
      const std::vector<std::tuple<media::VideoCaptureDeviceDescriptor,
                                   media::VideoCaptureFormats>>&
          descriptors_and_formats);

  // media::AudioLogFactory implementation.  Safe to call from any thread.
  std::unique_ptr<media::AudioLog> CreateAudioLog(AudioComponent component,
                                                  int component_id) override;

  // Creates a media::mojom::AudioLogPtr strongly bound to a new
  // media::mojom::AudioLog instance. Safe to call from any thread.
  media::mojom::AudioLogPtr CreateMojoAudioLog(
      AudioComponent component,
      int component_id,
      int render_process_id = -1,
      int render_frame_id = MSG_ROUTING_NONE);

  void OnProcessTerminatedForTesting(int process_id);

 private:
  // Inner class to handle reporting pipelinestatus to UMA
  class MediaInternalsUMAHandler;

  friend class AudioLogImpl;

  MediaInternals();

  // Sends |update| to each registered UpdateCallback.  Safe to call from any
  // thread, but will forward to the IO thread.
  void SendUpdate(const base::string16& update);

  // Saves |event| so that it can be sent later in SendHistoricalMediaEvents().
  void SaveEvent(int process_id, const media::MediaLogEvent& event);

  // Caches |value| under |cache_key| so that future UpdateAudioLog() calls
  // will include the current data.  Calls JavaScript |function|(|value|) for
  // each registered UpdateCallback (if any).
  enum AudioLogUpdateType {
    CREATE,             // Creates a new AudioLog cache entry.
    UPDATE_IF_EXISTS,   // Updates an existing AudioLog cache entry, does
                        // nothing if it doesn't exist.
    UPDATE_AND_DELETE,  // Deletes an existing AudioLog cache entry.
  };
  void UpdateAudioLog(AudioLogUpdateType type,
                      const std::string& cache_key,
                      const std::string& function,
                      const base::DictionaryValue* value);

  // Must only be accessed on the UI thread.
  std::vector<UpdateCallback> update_callbacks_;

  // Saved events by process ID for showing recent players in the UI.
  std::map<int, std::list<media::MediaLogEvent>> saved_events_by_process_;

  // Must only be accessed on the IO thread.
  base::ListValue video_capture_capabilities_cached_data_;

  NotificationRegistrar registrar_;

  // All variables below must be accessed under |lock_|.
  base::Lock lock_;
  bool can_update_;
  base::DictionaryValue audio_streams_cached_data_;
  int owner_ids_[media::AudioLogFactory::AUDIO_COMPONENT_MAX];
  std::unique_ptr<MediaInternalsUMAHandler> uma_handler_;

  DISALLOW_COPY_AND_ASSIGN(MediaInternals);
};

}  // namespace host

#endif  // MUMBA_HOST_MEDIA_MEDIA_INTERNALS_H_
