// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/application/media/application_webmediaplayer_delegate.h"

#include <stdint.h>

#include "base/auto_reset.h"
#include "base/metrics/histogram_macros.h"
#include "base/metrics/user_metrics_action.h"
#include "base/sys_info.h"
#include "core/shared/common/media/media_player_delegate_messages.h"
#include "core/shared/common/client.h"
//#include "core/shared/application/content_renderer_client.h"
//#include "core/shared/application/render_frame.h"
#include "core/shared/application/application_thread.h"
#include "third_party/blink/public/platform/web_fullscreen_video_status.h"
#include "third_party/blink/public/platform/web_size.h"
#include "third_party/blink/public/web/web_scoped_user_gesture.h"
#include "ui/gfx/geometry/size.h"

#if defined(OS_ANDROID)
#include "base/android/build_info.h"
#endif

//namespace {

//void RecordAction(const base::UserMetricsAction& action) {
  //application::ApplicationThread::current()->RecordAction(action);
//}

//}  // namespace

namespace media {

ApplicationWebMediaPlayerDelegate::ApplicationWebMediaPlayerDelegate(
    application::ApplicationThread* application_thread,
    blink::WebLocalFrame* web_frame,
    void* delegate_state,
    WebMediaPlayerDelegateCallbacks callbacks)
    //application::RenderFrame* render_frame)
    : //RenderFrameObserver(render_frame),
      application_thread_(application_thread),
      web_frame_(web_frame),
      delegate_state_(delegate_state),
      callbacks_(callbacks) {
//   idle_cleanup_interval_ = base::TimeDelta::FromSeconds(5);
//   idle_timeout_ = base::TimeDelta::FromSeconds(15);

//   is_jelly_bean_ = false;

// #if defined(OS_ANDROID)
//   // On Android, due to the instability of the OS level media components, we
//   // consider all pre-KitKat devices to be potentially buggy.
//   is_jelly_bean_ |= base::android::BuildInfo::GetInstance()->sdk_int() <=
//                     base::android::SDK_VERSION_JELLY_BEAN_MR2;
// #endif

//   idle_cleanup_timer_.SetTaskRunner(
//       render_frame->GetTaskRunner(blink::TaskType::kInternalMedia));
}

ApplicationWebMediaPlayerDelegate::~ApplicationWebMediaPlayerDelegate() {}

bool ApplicationWebMediaPlayerDelegate::IsFrameHidden() {
  return callbacks_.IsFrameHidden(delegate_state_) != 0;
}

bool ApplicationWebMediaPlayerDelegate::IsFrameClosed() {
  return callbacks_.IsFrameClosed(delegate_state_) != 0;
}

int ApplicationWebMediaPlayerDelegate::AddObserver(Observer* observer) {
  return callbacks_.AddObserver(delegate_state_, observer);
}

void ApplicationWebMediaPlayerDelegate::RemoveObserver(int player_id) {
  //DCHECK(id_map_.Lookup(player_id));
  //id_map_.Remove(player_id);
  //idle_player_map_.erase(player_id);
  //stale_players_.erase(player_id);
  //playing_videos_.erase(player_id);

  //Send(
  //    new MediaPlayerDelegateHostMsg_OnMediaDestroyed(routing_id(), player_id));

  //ScheduleUpdateTask();
  //DCHECK(false);
  //observer_count_--;
  callbacks_.RemoveObserver(delegate_state_, player_id);
}

void ApplicationWebMediaPlayerDelegate::DidPlay(
    int player_id,
    bool has_video,
    bool has_audio,
    MediaContentType media_content_type) {
  callbacks_.DidPlay(delegate_state_, player_id, has_video, has_audio, static_cast<int>(media_content_type));
}

void ApplicationWebMediaPlayerDelegate::DidPlayerMutedStatusChange(int delegate_id,
                                                                bool muted) {
   callbacks_.DidPlayerMutedStatusChange(delegate_state_, delegate_id, muted ? 1 : 0);
}

// void ApplicationWebMediaPlayerDelegate::DidPictureInPictureModeStart(
//     int delegate_id,
//     const viz::SurfaceId& surface_id,
//     const gfx::Size& natural_size,
//     blink::WebMediaPlayer::PipWindowOpenedCallback callback) {
//   callbacks_.DidPictureInPictureModeStart(delegate_state_, delegate_id, surface_id, natural_size.width(), natural_size.height());
// }

void ApplicationWebMediaPlayerDelegate::DidPictureInPictureModeEnd(
    int delegate_id) {
  callbacks_.DidPictureInPictureModeEnd(delegate_state_, delegate_id);
}

void ApplicationWebMediaPlayerDelegate::DidPictureInPictureSourceChange(
    int delegate_id) {
   callbacks_.DidPictureInPictureSourceChange(delegate_state_, delegate_id);
}

// void ApplicationWebMediaPlayerDelegate::
//     RegisterPictureInPictureWindowResizeCallback(
//         int player_id,
//         blink::WebMediaPlayer::PipWindowResizedCallback callback) {
  
// }

void ApplicationWebMediaPlayerDelegate::DidPause(int player_id) {
  callbacks_.DidPause(delegate_state_, player_id);
}

void ApplicationWebMediaPlayerDelegate::PlayerGone(int player_id) {
  callbacks_.PlayerGone(delegate_state_, player_id);
}

void ApplicationWebMediaPlayerDelegate::SetIdle(int player_id, bool is_idle) {
  callbacks_.SetIdle(delegate_state_, player_id, is_idle ? 1 : 0);
}

bool ApplicationWebMediaPlayerDelegate::IsIdle(int player_id) {
  return callbacks_.IsIdle(delegate_state_, player_id) != 0;
}

void ApplicationWebMediaPlayerDelegate::ClearStaleFlag(int player_id) {
  callbacks_.ClearStaleFlag(delegate_state_, player_id);
}

bool ApplicationWebMediaPlayerDelegate::IsStale(int player_id) {
  return callbacks_.IsStale(delegate_state_, player_id) != 0;
}

void ApplicationWebMediaPlayerDelegate::SetIsEffectivelyFullscreen(
    int player_id,
    blink::WebFullscreenVideoStatus fullscreen_video_status) {
  callbacks_.SetIsEffectivelyFullscreen(delegate_state_, player_id, static_cast<int>(fullscreen_video_status));
}

void ApplicationWebMediaPlayerDelegate::DidPlayerSizeChange(
    int delegate_id,
    const gfx::Size& size) {
  callbacks_.DidPlayerSizeChange(delegate_state_, delegate_id, size.width(), size.height());
}

bool ApplicationWebMediaPlayerDelegate::OnMessageReceived(
    const IPC::Message& msg) {
  IPC_BEGIN_MESSAGE_MAP(ApplicationWebMediaPlayerDelegate, msg)
    IPC_MESSAGE_HANDLER(MediaPlayerDelegateMsg_Pause, OnMediaDelegatePause)
    IPC_MESSAGE_HANDLER(MediaPlayerDelegateMsg_Play, OnMediaDelegatePlay)
    IPC_MESSAGE_HANDLER(MediaPlayerDelegateMsg_SeekForward,
                        OnMediaDelegateSeekForward)
    IPC_MESSAGE_HANDLER(MediaPlayerDelegateMsg_SeekBackward,
                        OnMediaDelegateSeekBackward)
    IPC_MESSAGE_HANDLER(MediaPlayerDelegateMsg_SuspendAllMediaPlayers,
                        OnMediaDelegateSuspendAllMediaPlayers)
    IPC_MESSAGE_HANDLER(MediaPlayerDelegateMsg_UpdateVolumeMultiplier,
                        OnMediaDelegateVolumeMultiplierUpdate)
    IPC_MESSAGE_HANDLER(MediaPlayerDelegateMsg_BecamePersistentVideo,
                        OnMediaDelegateBecamePersistentVideo)
    IPC_MESSAGE_HANDLER(MediaPlayerDelegateMsg_EndPictureInPictureMode,
                        OnPictureInPictureModeEnded)
    //IPC_MESSAGE_HANDLER(MediaPlayerDelegateMsg_ClickPictureInPictureControl,
    //                    OnPictureInPictureControlClicked)
    //IPC_MESSAGE_HANDLER(MediaPlayerDelegateMsg_OnPictureInPictureModeEnded_ACK,
    //                    OnPictureInPictureModeEndedAck)
    //IPC_MESSAGE_HANDLER(
    //    MediaPlayerDelegateMsg_OnPictureInPictureModeStarted_ACK,
    //    OnPictureInPictureModeStartedAck)
    //IPC_MESSAGE_HANDLER(MediaPlayerDelegateMsg_OnPictureInPictureWindowResize,
    //                    OnPictureInPictureWindowResize)
    IPC_MESSAGE_UNHANDLED(return false)
  IPC_END_MESSAGE_MAP()
  return true;
}


void ApplicationWebMediaPlayerDelegate::OnMediaDelegatePause(int player_id) {
//   RecordAction(base::UserMetricsAction("Media.Controls.RemotePause"));

//   Observer* observer = id_map_.Lookup(player_id);
//   if (observer) {
//     // TODO(avayvod): remove when default play/pause is handled via
//     // the MediaSession code path.
//     std::unique_ptr<blink::WebScopedUserGesture> gesture(
//         render_frame()
//             ? new blink::WebScopedUserGesture(render_frame()->GetWebFrame())
//             : nullptr);
//     observer->OnPause();
//   }
  callbacks_.OnMediaDelegatePause(delegate_state_, player_id);
}

void ApplicationWebMediaPlayerDelegate::OnMediaDelegatePlay(int player_id) {
//   RecordAction(base::UserMetricsAction("Media.Controls.RemotePlay"));

//   Observer* observer = id_map_.Lookup(player_id);
//   if (observer) {
//     // TODO(avayvod): remove when default play/pause is handled via
//     // the MediaSession code path.
//     std::unique_ptr<blink::WebScopedUserGesture> gesture(
//         render_frame()
//             ? new blink::WebScopedUserGesture(render_frame()->GetWebFrame())
//             : nullptr);
//     observer->OnPlay();
//   }
  callbacks_.OnMediaDelegatePlay(delegate_state_, player_id);
}

void ApplicationWebMediaPlayerDelegate::OnMediaDelegateSeekForward(
    int player_id,
    base::TimeDelta seek_time) {
//   RecordAction(base::UserMetricsAction("Media.Controls.RemoteSeekForward"));

//   Observer* observer = id_map_.Lookup(player_id);
//   if (observer)
//     observer->OnSeekForward(seek_time.InSecondsF());
  callbacks_.OnMediaDelegateSeekForward(delegate_state_, player_id, seek_time.InMilliseconds());
}

void ApplicationWebMediaPlayerDelegate::OnMediaDelegateSeekBackward(
    int player_id,
    base::TimeDelta seek_time) {
//   RecordAction(base::UserMetricsAction("Media.Controls.RemoteSeekBackward"));

//   Observer* observer = id_map_.Lookup(player_id);
//   if (observer)
//     observer->OnSeekBackward(seek_time.InSecondsF());
  callbacks_.OnMediaDelegateSeekBackward(delegate_state_, player_id, seek_time.InMilliseconds());
}

void ApplicationWebMediaPlayerDelegate::OnMediaDelegateSuspendAllMediaPlayers() {
//   is_frame_closed_ = true;

//   for (base::IDMap<Observer*>::iterator it(&id_map_); !it.IsAtEnd();
//        it.Advance())
//     it.GetCurrentValue()->OnFrameClosed();
  callbacks_.OnMediaDelegateSuspendAllMediaPlayers(delegate_state_);
}

void ApplicationWebMediaPlayerDelegate::OnMediaDelegateVolumeMultiplierUpdate(
    int player_id,
    double multiplier) {
//   Observer* observer = id_map_.Lookup(player_id);
//   if (observer)
//     observer->OnVolumeMultiplierUpdate(multiplier);
  callbacks_.OnMediaDelegateVolumeMultiplierUpdate(delegate_state_, player_id, multiplier);
}

void ApplicationWebMediaPlayerDelegate::OnMediaDelegateBecamePersistentVideo(
    int player_id,
    bool value) {
//   Observer* observer = id_map_.Lookup(player_id);
//   if (observer)
//     observer->OnBecamePersistentVideo(value);
  callbacks_.OnMediaDelegateBecamePersistentVideo(delegate_state_, player_id, value ? 1 : 0);
}

void ApplicationWebMediaPlayerDelegate::OnPictureInPictureModeEnded(
    int player_id) {
//   Observer* observer = id_map_.Lookup(player_id);
//   if (observer)
//     observer->OnPictureInPictureModeEnded();
  callbacks_.OnPictureInPictureModeEnded(delegate_state_, player_id);
}

void ApplicationWebMediaPlayerDelegate::OnPictureInPictureControlClicked(
    int player_id,
    const std::string& control_id) {
//   Observer* observer = id_map_.Lookup(player_id);
//   if (observer)
//     observer->OnPictureInPictureControlClicked(control_id);
}

void ApplicationWebMediaPlayerDelegate::OnPictureInPictureModeEndedAck(
    int player_id,
    int request_id) {
//   auto iter = exit_picture_in_picture_callback_map_.find(request_id);
//   DCHECK(iter != exit_picture_in_picture_callback_map_.end());

//   std::move(iter->second).Run();
//   exit_picture_in_picture_callback_map_.erase(iter);
}

void ApplicationWebMediaPlayerDelegate::OnPictureInPictureModeStartedAck(
    int player_id,
    int request_id,
    const gfx::Size& window_size) {
//   auto iter = enter_picture_in_picture_callback_map_.find(request_id);
//   DCHECK(iter != enter_picture_in_picture_callback_map_.end());

//   std::move(iter->second).Run(blink::WebSize(window_size));
//   enter_picture_in_picture_callback_map_.erase(iter);
}

void ApplicationWebMediaPlayerDelegate::OnPictureInPictureWindowResize(
    int player_id,
    const gfx::Size& window_size) {
//   if (!picture_in_picture_window_resize_observer_ ||
//       picture_in_picture_window_resize_observer_->first != player_id) {
//     return;
//   }

//   picture_in_picture_window_resize_observer_->second.Run(
//       blink::WebSize(window_size));
}

//void ApplicationWebMediaPlayerDelegate::ScheduleUpdateTask() {
//   if (!pending_update_task_) {
//     base::ThreadTaskRunnerHandle::Get()->PostTask(
//         FROM_HERE, base::BindOnce(&ApplicationWebMediaPlayerDelegate::UpdateTask,
//                                   AsWeakPtr()));
//     pending_update_task_ = true;
//   }
//}

//void ApplicationWebMediaPlayerDelegate::UpdateTask() {
//   DVLOG(3) << __func__;
//   pending_update_task_ = false;

//   // Check whether a player was played since the last UpdateTask(). We basically
//   // treat this as a parameter to UpdateTask(), except that it can be changed
//   // between posting the task and UpdateTask() executing.
//   bool has_played_video_since_last_update_task = has_played_video_;
//   has_played_video_ = false;

//   // Record UMAs for background video playback.
//   RecordBackgroundVideoPlayback();

//   if (!allow_idle_cleanup_)
//     return;

//   // Clean up idle players.
//   bool aggressive_cleanup = false;

//   // When we reach the maximum number of idle players, clean them up
//   // aggressively. Values chosen after testing on a Galaxy Nexus device for
//   // http://crbug.com/612909.
//   if (idle_player_map_.size() > (is_jelly_bean_ ? 2u : 8u))
//     aggressive_cleanup = true;

//   // When a player plays on a buggy old device, clean up idle players
//   // aggressively.
//   if (has_played_video_since_last_update_task && is_jelly_bean_)
//     aggressive_cleanup = true;

//   CleanUpIdlePlayers(aggressive_cleanup ? base::TimeDelta() : idle_timeout_);

//   // If there are still idle players, schedule an attempt to clean them up.
//   // This construct ensures that the next callback is always
//   // |idle_cleanup_interval_| from now.
//   idle_cleanup_timer_.Stop();
//   if (!idle_player_map_.empty()) {
//     idle_cleanup_timer_.Start(
//         FROM_HERE, idle_cleanup_interval_,
//         base::Bind(&ApplicationWebMediaPlayerDelegate::UpdateTask,
//                    base::Unretained(this)));
//   }
//}

//void ApplicationWebMediaPlayerDelegate::RecordBackgroundVideoPlayback() {
// #if defined(OS_ANDROID)
//   // TODO(avayvod): This would be useful to collect on desktop too and express
//   // in actual media watch time vs. just elapsed time.
//   // See https://crbug.com/638726.
//   bool has_playing_background_video =
//       IsFrameHidden() && !IsFrameClosed() && !playing_videos_.empty();

//   if (has_playing_background_video != was_playing_background_video_) {
//     was_playing_background_video_ = has_playing_background_video;

//     if (has_playing_background_video) {
//       RecordAction(base::UserMetricsAction("Media.Session.BackgroundResume"));
//       background_video_start_time_ = base::TimeTicks::Now();
//     } else {
//       RecordAction(base::UserMetricsAction("Media.Session.BackgroundSuspend"));
//       UMA_HISTOGRAM_CUSTOM_TIMES(
//           "Media.Android.BackgroundVideoTime",
//           base::TimeTicks::Now() - background_video_start_time_,
//           base::TimeDelta::FromSeconds(7), base::TimeDelta::FromHours(10), 50);
//     }
//   }
// #endif  // OS_ANDROID
//}

// void ApplicationWebMediaPlayerDelegate::CleanUpIdlePlayers(
//     base::TimeDelta timeout) {
//   const base::TimeTicks now = tick_clock_->NowTicks();

//   // Create a list of stale players before making any possibly reentrant calls
//   // to OnIdleTimeout().
//   std::vector<int> stale_players;
//   for (const auto& it : idle_player_map_) {
//     if (now - it.second >= timeout)
//       stale_players.push_back(it.first);
//   }

//   // Notify stale players.
//   for (int player_id : stale_players) {
//     Observer* player = id_map_.Lookup(player_id);
//     if (player && idle_player_map_.erase(player_id)) {
//       stale_players_.insert(player_id);
//       player->OnIdleTimeout();
//     }
//   }
// }

void ApplicationWebMediaPlayerDelegate::OnDestruct() {
  delete this;
}

void ApplicationWebMediaPlayerDelegate::OnPictureInPictureSurfaceIdUpdated(
    int delegate_id,
    const viz::SurfaceId& surface_id,
    const gfx::Size& natural_size) {
  callbacks_.OnPictureInPictureSurfaceIdUpdated(
    delegate_state_,
    delegate_id,
    surface_id.frame_sink_id().client_id(),
    surface_id.frame_sink_id().sink_id(),
    surface_id.local_surface_id().parent_sequence_number(),
    surface_id.local_surface_id().child_sequence_number(),
    surface_id.local_surface_id().embed_token().GetHighForSerialization(), 
    surface_id.local_surface_id().embed_token().GetLowForSerialization(),
    natural_size.width(),
    natural_size.height());
}

void ApplicationWebMediaPlayerDelegate::OnExitPictureInPicture(int delegate_id) {
  callbacks_.OnExitPictureInPicture(delegate_state_, delegate_id);
}

}  // namespace media
