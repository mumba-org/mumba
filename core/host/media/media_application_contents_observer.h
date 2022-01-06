// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_MEDIA_MEDIA_WEB_CONTENTS_OBSERVER_H_
#define MUMBA_HOST_MEDIA_MEDIA_WEB_CONTENTS_OBSERVER_H_

#include <stdint.h>

#include <map>
#include <memory>
#include <set>

#include "base/macros.h"
#include "core/host/media/session/media_session_controllers_manager.h"
#include "core/shared/common/content_export.h"
#include "core/host/application/application_contents_observer.h"
#include "services/device/public/mojom/wake_lock.mojom.h"

#if defined(OS_ANDROID)
#include "ui/android/view_android.h"
#endif  // OS_ANDROID

namespace blink {
enum class WebFullscreenVideoStatus;
}  // namespace blink

namespace media {
enum class MediaContentType;
}  // namespace media

namespace gfx {
class Size;
}  // namespace size

namespace host {

// This class manages all RenderFrame based media related managers at the
// browser side. It receives IPC messages from media RenderFrameObservers and
// forwards them to the corresponding managers. The managers are responsible
// for sending IPCs back to the RenderFrameObservers at the render side.
class CONTENT_EXPORT MediaApplicationContentsObserver : public ApplicationContentsObserver {
 public:
  explicit MediaApplicationContentsObserver(ApplicationContents* app_contents);
  ~MediaApplicationContentsObserver() override;

  using PlayerSet = std::set<int>;
  using ActiveMediaPlayerMap = std::map<ApplicationWindowHost*, PlayerSet>;

  // Called by ApplicationContents when the audible state may have changed.
  void MaybeUpdateAudibleState();

  // Called by ApplicationContents to know if an active player is effectively
  // fullscreen. That means that the video is either fullscreen or it is the
  // content of a fullscreen page (in other words, a fullscreen video with
  // custom controls).
  // It should only be called while the ApplicationContents is fullscreen.
  bool HasActiveEffectivelyFullscreenVideo() const;

  // Called by ApplicationContents to know if Picture-in-Picture can be triggered
  // for the current active effectively fullscreen player.
  // It should only be called while the ApplicationContents is fullscreen.
  bool IsPictureInPictureAllowedForFullscreenVideo() const;

  // Gets the MediaPlayerId of the fullscreen video if it exists.
  const base::Optional<MediaPlayerId>& GetFullscreenVideoMediaPlayerId() const;

  // Gets the MediaPlayerId of the picture in picture video if it exists.
  const base::Optional<MediaPlayerId>& GetPictureInPictureVideoMediaPlayerId()
      const;

  // ApplicationContentsObserver implementation.
  void ApplicationContentsDestroyed() override;
  void ApplicationWindowDeleted(ApplicationWindowHost* app_window_host) override;
  bool OnMessageReceived(const IPC::Message& message,
                         ApplicationWindowHost* app_window_host) override;
  void OnVisibilityChanged(Visibility visibility) override;

  // TODO(zqzhang): this method is temporarily in MediaApplicationContentsObserver as
  // the effectively fullscreen video code is also here. We need to consider
  // merging the logic of effectively fullscreen, hiding media controls and
  // fullscreening video element to the same portal.
  void RequestPersistentVideo(bool value);

  // Returns whether or not the given player id is active.
  bool IsPlayerActive(const MediaPlayerId& player_id) const;

  bool has_audio_wake_lock_for_testing() const {
    return has_audio_wake_lock_for_testing_;
  }

  bool has_video_wake_lock_for_testing() const {
    return has_video_wake_lock_for_testing_;
  }

 protected:
  MediaSessionControllersManager* session_controllers_manager() {
    return &session_controllers_manager_;
  }

 private:
  void OnMediaDestroyed(ApplicationWindowHost* application_window_host, int delegate_id);
  void OnMediaPaused(ApplicationWindowHost* application_window_host,
                     int delegate_id,
                     bool reached_end_of_stream);
  void OnMediaPlaying(ApplicationWindowHost* application_window_host,
                      int delegate_id,
                      bool has_video,
                      bool has_audio,
                      bool is_remote,
                      media::MediaContentType media_content_type);
  void OnMediaEffectivelyFullscreenChanged(
      ApplicationWindowHost* application_window_host,
      int delegate_id,
      blink::WebFullscreenVideoStatus fullscreen_status);
  void OnMediaSizeChanged(ApplicationWindowHost* application_window_host,
                          int delegate_id,
                          const gfx::Size& size);
  void OnMediaMutedStatusChanged(ApplicationWindowHost* application_window_host,
                                 int delegate_id,
                                 bool muted);
  void OnPictureInPictureSourceChanged(ApplicationWindowHost* application_window_host,
                                       int delegate_id);
  void OnPictureInPictureModeEnded(ApplicationWindowHost* application_window_host,
                                   int delegate_id);

  // Clear |application_window_host|'s tracking entry for its WakeLocks.
  void ClearWakeLocks(ApplicationWindowHost* application_window_host);

  device::mojom::WakeLock* GetAudioWakeLock();
  device::mojom::WakeLock* GetVideoWakeLock();

  void LockAudio();
  void LockVideo();

  void CancelAudioLock();
  void CancelVideoLock();
  void MaybeCancelVideoLock();

  // Helper methods for adding or removing player entries in |player_map|.
  void AddMediaPlayerEntry(const MediaPlayerId& id,
                           ActiveMediaPlayerMap* player_map);
  // Returns true if an entry is actually removed.
  bool RemoveMediaPlayerEntry(const MediaPlayerId& id,
                              ActiveMediaPlayerMap* player_map);
  // Removes all entries from |player_map| for |application_window_host|. Removed
  // entries are added to |removed_players|.
  void RemoveAllMediaPlayerEntries(ApplicationWindowHost* application_window_host,
                                   ActiveMediaPlayerMap* player_map,
                                   std::set<MediaPlayerId>* removed_players);

  // Tracking variables and associated wake locks for media playback.
  ActiveMediaPlayerMap active_audio_players_;
  ActiveMediaPlayerMap active_video_players_;
  device::mojom::WakeLockPtr audio_wake_lock_;
  device::mojom::WakeLockPtr video_wake_lock_;
  base::Optional<MediaPlayerId> fullscreen_player_;
  base::Optional<MediaPlayerId> pip_player_;
  base::Optional<bool> picture_in_picture_allowed_in_fullscreen_;
  bool has_audio_wake_lock_for_testing_ = false;
  bool has_video_wake_lock_for_testing_ = false;

  MediaSessionControllersManager session_controllers_manager_;

  DISALLOW_COPY_AND_ASSIGN(MediaApplicationContentsObserver);
};

}  // namespace host

#endif  // MUMBA_HOST_MEDIA_MEDIA_WEB_CONTENTS_OBSERVER_H_
