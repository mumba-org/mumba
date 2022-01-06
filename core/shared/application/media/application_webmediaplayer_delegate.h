// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_RENDERER_MEDIA_RENDERER_WEBMEDIAPLAYER_DELEGATE_H_
#define CONTENT_RENDERER_MEDIA_RENDERER_WEBMEDIAPLAYER_DELEGATE_H_

#include <map>
#include <memory>
#include <set>

#include "base/containers/id_map.h"
#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/memory/weak_ptr.h"
#include "base/single_thread_task_runner.h"
#include "base/time/default_tick_clock.h"
#include "base/timer/timer.h"
#include "components/viz/common/surfaces/surface_id.h"
#include "core/shared/common/content_export.h"
//#include "core/shared/application/render_frame_observer.h"
#include "media/blink/webmediaplayer_delegate.h"
#include "runtime/MumbaShims/ApplicationHandler.h"

#if defined(OS_ANDROID)
#include "base/time/time.h"
#endif  // OS_ANDROID

namespace blink {
enum class WebFullscreenVideoStatus;
}

namespace application {
class ApplicationThread;  
}

namespace IPC {
class Message;  
}

namespace blink {
class WebLocalFrame;  
}

namespace media {

enum class MediaContentType;

// Standard implementation of WebMediaPlayerDelegate; communicates state to
// the MediaPlayerDelegateHost.
// This is a wrapper to the real delegate on Swift side
class CONTENT_EXPORT ApplicationWebMediaPlayerDelegate
    : //public application::RenderFrameObserver,
      public WebMediaPlayerDelegate,
      public base::SupportsWeakPtr<ApplicationWebMediaPlayerDelegate> {
 public:
  explicit ApplicationWebMediaPlayerDelegate(
      application::ApplicationThread* application_thread,
      blink::WebLocalFrame* web_frame,
      void* delegate_state,
      WebMediaPlayerDelegateCallbacks callbacks);
  ~ApplicationWebMediaPlayerDelegate() override;

  application::ApplicationThread* application_thread() const {
    return application_thread_;
  }
  
  blink::WebLocalFrame* web_frame() const {
    return web_frame_;
  }

  // WebMediaPlayerDelegate implementation.
  bool IsFrameHidden() override;
  bool IsFrameClosed() override;
  int AddObserver(Observer* observer) override;
  void RemoveObserver(int player_id) override;
  void DidPlay(int player_id,
               bool has_video,
               bool has_audio,
               MediaContentType media_content_type) override;
  void DidPause(int player_id) override;
  void PlayerGone(int player_id) override;
  void SetIdle(int player_id, bool is_idle) override;
  bool IsIdle(int player_id) override;
  void ClearStaleFlag(int player_id) override;
  bool IsStale(int player_id) override;
  void SetIsEffectivelyFullscreen(
      int player_id,
      blink::WebFullscreenVideoStatus fullscreen_video_status) override;
  void DidPlayerSizeChange(int delegate_id, const gfx::Size& size) override;
  void DidPlayerMutedStatusChange(int delegate_id, bool muted) override;
  //void DidPictureInPictureModeStart(
  //    int delegate_id,
  //    const viz::SurfaceId&,
  //    const gfx::Size&,
  //    blink::WebMediaPlayer::PipWindowOpenedCallback) override;
  void DidPictureInPictureModeEnd(int delegate_id) override;
  void DidPictureInPictureSourceChange(int delegate_id) override;
//   void RegisterPictureInPictureWindowResizeCallback(
//       int player_id,
//       blink::WebMediaPlayer::PipWindowResizedCallback) override;

  // application::RenderFrameObserver overrides.
  bool OnMessageReceived(const IPC::Message& msg);// override;
  void OnDestruct(); //override;

  void OnPictureInPictureSurfaceIdUpdated(
    int delegate_id,
    const viz::SurfaceId& surface_id,
    const gfx::Size& natural_size);

  void OnExitPictureInPicture(int delegate_id);

 private:
  void OnMediaDelegatePause(int player_id);
  void OnMediaDelegatePlay(int player_id);
  void OnMediaDelegateSeekForward(int player_id, base::TimeDelta seek_time);
  void OnMediaDelegateSeekBackward(int player_id, base::TimeDelta seek_time);
  void OnMediaDelegateSuspendAllMediaPlayers();
  void OnMediaDelegateVolumeMultiplierUpdate(int player_id, double multiplier);
  void OnMediaDelegateBecamePersistentVideo(int player_id, bool value);
  void OnPictureInPictureModeEnded(int player_id);
  void OnPictureInPictureControlClicked(int player_id,
                                        const std::string& control_id);
  void OnPictureInPictureModeEndedAck(int player_id, int request_id);
  void OnPictureInPictureModeStartedAck(int player_id,
                                        int request_id,
                                        const gfx::Size&);
  void OnPictureInPictureWindowResize(int player_id, const gfx::Size&);

  // Schedules UpdateTask() to run soon.
 // void ScheduleUpdateTask();

  // Processes state changes, dispatches CleanupIdlePlayers().
 // void UpdateTask();

  // Records UMAs about background playback.
 // void RecordBackgroundVideoPlayback();

  // Runs periodically to notify stale players in |idle_player_map_| which
  // have been idle for longer than |timeout|.
 // void CleanUpIdlePlayers(base::TimeDelta timeout);

  application::ApplicationThread* application_thread_;
  blink::WebLocalFrame* web_frame_;
  void* delegate_state_;
  WebMediaPlayerDelegateCallbacks callbacks_;

  DISALLOW_COPY_AND_ASSIGN(ApplicationWebMediaPlayerDelegate);
};

}  // namespace media

#endif  // CONTENT_RENDERER_MEDIA_RENDERER_WEBMEDIAPLAYER_DELEGATE_H_