// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/media/media_application_contents_observer.h"

#include <memory>

#include "build/build_config.h"
#include "core/host/media/audible_metrics.h"
#include "core/host/media/audio_stream_monitor.h"
#include "core/host/application/application_contents.h"
#include "core/shared/common/media/media_player_delegate_messages.h"
#include "core/host/application/application_window_host.h"
#include "core/host/application/application_contents.h"
#include "ipc/ipc_message_macros.h"
#include "mojo/public/cpp/bindings/interface_request.h"
#include "services/device/public/mojom/wake_lock_context.mojom.h"
#include "third_party/blink/public/platform/web_fullscreen_video_status.h"
#include "ui/gfx/geometry/size.h"

namespace host {

namespace {

AudibleMetrics* GetAudibleMetrics() {
  static AudibleMetrics* metrics = new AudibleMetrics();
  return metrics;
}

void CheckFullscreenDetectionEnabled(ApplicationContents* app_contents) {
#if defined(OS_ANDROID)
  DCHECK(app_contents->GetApplicationWindowHost()
             ->GetWebkitPreferences()
             .video_fullscreen_detection_enabled)
      << "Attempt to use method relying on fullscreen detection while "
      << "fullscreen detection is disabled.";
#else   // defined(OS_ANDROID)
  NOTREACHED() << "Attempt to use method relying on fullscreen detection, "
               << "which is only enabled on Android.";
#endif  // defined(OS_ANDROID)
}

// Returns true if |player_id| exists in |player_map|.
bool MediaPlayerEntryExists(
    const ApplicationContentsObserver::MediaPlayerId& player_id,
    const MediaApplicationContentsObserver::ActiveMediaPlayerMap& player_map) {
  const auto& players = player_map.find(player_id.first);
  if (players == player_map.end())
    return false;

  return players->second.find(player_id.second) != players->second.end();
}

}  // anonymous namespace

MediaApplicationContentsObserver::MediaApplicationContentsObserver(ApplicationContents* app_contents)
    : ApplicationContentsObserver(app_contents),
      session_controllers_manager_(this) {
  
}

MediaApplicationContentsObserver::~MediaApplicationContentsObserver() {
  //DLOG(INFO) << "~MediaApplicationContentsObserver: " << this;
}

void MediaApplicationContentsObserver::ApplicationContentsDestroyed() {
  GetAudibleMetrics()->UpdateAudibleApplicationContentsState(application_contents(), false);
}

void MediaApplicationContentsObserver::ApplicationWindowDeleted(
    ApplicationWindowHost* application_window_host) {
  ClearWakeLocks(application_window_host);
  session_controllers_manager_.ApplicationWindowDeleted(application_window_host);

  if (fullscreen_player_ && fullscreen_player_->first == application_window_host) {
    picture_in_picture_allowed_in_fullscreen_.reset();
    fullscreen_player_.reset();
  }
}

void MediaApplicationContentsObserver::MaybeUpdateAudibleState() {
  AudioStreamMonitor* audio_stream_monitor =
      application_contents()->audio_stream_monitor();

  if (audio_stream_monitor->WasRecentlyAudible())
    LockAudio();
  else
    CancelAudioLock();

  GetAudibleMetrics()->UpdateAudibleApplicationContentsState(
      application_contents(), audio_stream_monitor->IsCurrentlyAudible());
}

bool MediaApplicationContentsObserver::HasActiveEffectivelyFullscreenVideo() const {
  CheckFullscreenDetectionEnabled(application_contents());
  if (!application_contents()->IsFullscreen() || !fullscreen_player_)
    return false;

  // Check that the player is active.
  return MediaPlayerEntryExists(*fullscreen_player_, active_video_players_);
}

bool MediaApplicationContentsObserver::IsPictureInPictureAllowedForFullscreenVideo()
    const {
  DCHECK(picture_in_picture_allowed_in_fullscreen_.has_value());

  return *picture_in_picture_allowed_in_fullscreen_;
}

const base::Optional<ApplicationContentsObserver::MediaPlayerId>&
MediaApplicationContentsObserver::GetFullscreenVideoMediaPlayerId() const {
  CheckFullscreenDetectionEnabled(application_contents());
  return fullscreen_player_;
}

const base::Optional<ApplicationContentsObserver::MediaPlayerId>&
MediaApplicationContentsObserver::GetPictureInPictureVideoMediaPlayerId() const {
  return pip_player_;
}

bool MediaApplicationContentsObserver::OnMessageReceived(
    const IPC::Message& msg,
    ApplicationWindowHost* application_window_host) {
  bool handled = true;
  IPC_BEGIN_MESSAGE_MAP_WITH_PARAM(MediaApplicationContentsObserver, msg,
                                   application_window_host)
    IPC_MESSAGE_HANDLER(MediaPlayerDelegateHostMsg_OnMediaDestroyed,
                        OnMediaDestroyed)
    IPC_MESSAGE_HANDLER(MediaPlayerDelegateHostMsg_OnMediaPaused, OnMediaPaused)
    IPC_MESSAGE_HANDLER(MediaPlayerDelegateHostMsg_OnMediaPlaying,
                        OnMediaPlaying)
    IPC_MESSAGE_HANDLER(MediaPlayerDelegateHostMsg_OnMutedStatusChanged,
                        OnMediaMutedStatusChanged)
    IPC_MESSAGE_HANDLER(
        MediaPlayerDelegateHostMsg_OnMediaEffectivelyFullscreenChanged,
        OnMediaEffectivelyFullscreenChanged)
    IPC_MESSAGE_HANDLER(MediaPlayerDelegateHostMsg_OnMediaSizeChanged,
                        OnMediaSizeChanged)
    IPC_MESSAGE_HANDLER(
        MediaPlayerDelegateHostMsg_OnPictureInPictureSourceChanged,
        OnPictureInPictureSourceChanged)
    IPC_MESSAGE_HANDLER(MediaPlayerDelegateHostMsg_OnPictureInPictureModeEnded,
                        OnPictureInPictureModeEnded)
    IPC_MESSAGE_UNHANDLED(handled = false)
  IPC_END_MESSAGE_MAP()
  return handled;
}

void MediaApplicationContentsObserver::OnVisibilityChanged(
    Visibility visibility) {
  if (visibility == Visibility::HIDDEN) {
    // If there are entities capturing screenshots or video (e.g., mirroring),
    // don't release the wake lock.
    if (!application_contents()->IsBeingCaptured()) {
      GetVideoWakeLock()->CancelWakeLock();
      has_video_wake_lock_for_testing_ = false;
    }
  } else {
    // TODO(ke.he@intel.com): Determine whether a tab should be allowed to
    // request the wake lock when it's occluded.
    DCHECK(visibility == Visibility::VISIBLE ||
           visibility == Visibility::OCCLUDED);

    // Restore wake lock if there are active video players running.
    if (!active_video_players_.empty())
      LockVideo();
  }
}

void MediaApplicationContentsObserver::RequestPersistentVideo(bool value) {
  if (!fullscreen_player_)
    return;

  // The message is sent to the renderer even though the video is already the
  // fullscreen element itself. It will eventually be handled by Blink.
  ApplicationWindowHost* target_frame = fullscreen_player_->first;
  int delegate_id = fullscreen_player_->second;
  target_frame->Send(new MediaPlayerDelegateMsg_BecamePersistentVideo(
      target_frame->GetRoutingID(), delegate_id, value));
}

bool MediaApplicationContentsObserver::IsPlayerActive(
    const MediaPlayerId& player_id) const {
  if (MediaPlayerEntryExists(player_id, active_video_players_))
    return true;

  return MediaPlayerEntryExists(player_id, active_audio_players_);
}

void MediaApplicationContentsObserver::OnMediaDestroyed(
    ApplicationWindowHost* application_window_host,
    int delegate_id) {
  OnMediaPaused(application_window_host, delegate_id, true);
}

void MediaApplicationContentsObserver::OnMediaPaused(ApplicationWindowHost* application_window_host,
                                             int delegate_id,
                                             bool reached_end_of_stream) {
  const MediaPlayerId player_id(application_window_host, delegate_id);
  const bool removed_audio =
      RemoveMediaPlayerEntry(player_id, &active_audio_players_);
  const bool removed_video =
      RemoveMediaPlayerEntry(player_id, &active_video_players_);
  MaybeCancelVideoLock();

  if (removed_audio || removed_video) {
    // Notify observers the player has been "paused".
    application_contents()->MediaStoppedPlaying(
        ApplicationContentsObserver::MediaPlayerInfo(removed_video, removed_audio),
        player_id,
        reached_end_of_stream
            ? ApplicationContentsObserver::MediaStoppedReason::kReachedEndOfStream
            : ApplicationContentsObserver::MediaStoppedReason::kUnspecified);
  }

  if (reached_end_of_stream)
    session_controllers_manager_.OnEnd(player_id);
  else
    session_controllers_manager_.OnPause(player_id);
}

void MediaApplicationContentsObserver::OnMediaPlaying(
    ApplicationWindowHost* application_window_host,
    int delegate_id,
    bool has_video,
    bool has_audio,
    bool is_remote,
    media::MediaContentType media_content_type) {
  // Ignore the videos playing remotely and don't hold the wake lock for the
  // screen. TODO(dalecurtis): Is this correct? It means observers will not
  // receive play and pause messages.
  if (is_remote)
    return;

  const MediaPlayerId id(application_window_host, delegate_id);
  if (has_audio)
    AddMediaPlayerEntry(id, &active_audio_players_);

  if (has_video) {
    AddMediaPlayerEntry(id, &active_video_players_);

    // If we're not hidden and have just created a player, create a wakelock.
    if (!application_contents()->IsHidden())
      LockVideo();
  }

  if (!session_controllers_manager_.RequestPlay(
          id, has_audio, is_remote, media_content_type)) {
    return;
  }

  // Notify observers of the new player.
  DCHECK(has_audio || has_video);
  application_contents()->MediaStartedPlaying(
      ApplicationContentsObserver::MediaPlayerInfo(has_video, has_audio), id);
}

void MediaApplicationContentsObserver::OnMediaEffectivelyFullscreenChanged(
    ApplicationWindowHost* application_window_host,
    int delegate_id,
    blink::WebFullscreenVideoStatus fullscreen_status) {
  const MediaPlayerId id(application_window_host, delegate_id);

  switch (fullscreen_status) {
    case blink::WebFullscreenVideoStatus::kFullscreenAndPictureInPictureEnabled:
      fullscreen_player_ = id;
      picture_in_picture_allowed_in_fullscreen_ = true;
      break;
    case blink::WebFullscreenVideoStatus::
        kFullscreenAndPictureInPictureDisabled:
      fullscreen_player_ = id;
      picture_in_picture_allowed_in_fullscreen_ = false;
      break;
    case blink::WebFullscreenVideoStatus::kNotEffectivelyFullscreen:
      if (!fullscreen_player_ || *fullscreen_player_ != id)
        return;

      picture_in_picture_allowed_in_fullscreen_.reset();
      fullscreen_player_.reset();
      break;
  }

  bool is_fullscreen =
      (fullscreen_status !=
       blink::WebFullscreenVideoStatus::kNotEffectivelyFullscreen);
  application_contents()->MediaEffectivelyFullscreenChanged(is_fullscreen);
}

void MediaApplicationContentsObserver::OnMediaSizeChanged(
    ApplicationWindowHost* application_window_host,
    int delegate_id,
    const gfx::Size& size) {
  const MediaPlayerId id(application_window_host, delegate_id);
  application_contents()->MediaResized(size, id);
}

void MediaApplicationContentsObserver::OnPictureInPictureSourceChanged(
    ApplicationWindowHost* application_window_host,
    int delegate_id) {
  pip_player_ = MediaPlayerId(application_window_host, delegate_id);
}

void MediaApplicationContentsObserver::OnPictureInPictureModeEnded(
    ApplicationWindowHost* application_window_host,
    int delegate_id) {
  pip_player_.reset();
}

void MediaApplicationContentsObserver::ClearWakeLocks(
    ApplicationWindowHost* application_window_host) {
  std::set<MediaPlayerId> video_players;
  RemoveAllMediaPlayerEntries(application_window_host, &active_video_players_,
                              &video_players);
  std::set<MediaPlayerId> audio_players;
  RemoveAllMediaPlayerEntries(application_window_host, &active_audio_players_,
                              &audio_players);

  std::set<MediaPlayerId> removed_players;
  std::set_union(video_players.begin(), video_players.end(),
                 audio_players.begin(), audio_players.end(),
                 std::inserter(removed_players, removed_players.end()));

  MaybeCancelVideoLock();

  // Notify all observers the player has been "paused".
  for (const auto& id : removed_players) {
    auto it = video_players.find(id);
    bool was_video = (it != video_players.end());
    bool was_audio = (audio_players.find(id) != audio_players.end());
    application_contents()->MediaStoppedPlaying(
        ApplicationContentsObserver::MediaPlayerInfo(was_video, was_audio), id,
        ApplicationContentsObserver::MediaStoppedReason::kUnspecified);
  }
}

device::mojom::WakeLock* MediaApplicationContentsObserver::GetAudioWakeLock() {
  // Here is a lazy binding, and will not reconnect after connection error.
  if (!audio_wake_lock_) {
    device::mojom::WakeLockRequest request =
        mojo::MakeRequest(&audio_wake_lock_);
    device::mojom::WakeLockContext* wake_lock_context =
        application_contents()->GetWakeLockContext();
    if (wake_lock_context) {
      wake_lock_context->GetWakeLock(
          device::mojom::WakeLockType::kPreventAppSuspension,
          device::mojom::WakeLockReason::kAudioPlayback, "Playing audio",
          std::move(request));
    }
  }
  return audio_wake_lock_.get();
}

device::mojom::WakeLock* MediaApplicationContentsObserver::GetVideoWakeLock() {
  // Here is a lazy binding, and will not reconnect after connection error.
  if (!video_wake_lock_) {
    device::mojom::WakeLockRequest request =
        mojo::MakeRequest(&video_wake_lock_);
    device::mojom::WakeLockContext* wake_lock_context =
        application_contents()->GetWakeLockContext();
    if (wake_lock_context) {
      wake_lock_context->GetWakeLock(
          device::mojom::WakeLockType::kPreventDisplaySleep,
          device::mojom::WakeLockReason::kVideoPlayback, "Playing video",
          std::move(request));
    }
  }
  return video_wake_lock_.get();
}

void MediaApplicationContentsObserver::LockAudio() {
  GetAudioWakeLock()->RequestWakeLock();
  has_audio_wake_lock_for_testing_ = true;
}

void MediaApplicationContentsObserver::CancelAudioLock() {
  GetAudioWakeLock()->CancelWakeLock();
  has_audio_wake_lock_for_testing_ = false;
}

void MediaApplicationContentsObserver::LockVideo() {
  DCHECK(!active_video_players_.empty());
  GetVideoWakeLock()->RequestWakeLock();
  has_video_wake_lock_for_testing_ = true;
}

void MediaApplicationContentsObserver::CancelVideoLock() {
  GetVideoWakeLock()->CancelWakeLock();
  has_video_wake_lock_for_testing_ = false;
}

void MediaApplicationContentsObserver::MaybeCancelVideoLock() {
  // If there are no more video players, cancel the video wake lock.
  if (active_video_players_.empty())
    CancelVideoLock();
}

void MediaApplicationContentsObserver::OnMediaMutedStatusChanged(
    ApplicationWindowHost* application_window_host,
    int delegate_id,
    bool muted) {
  const MediaPlayerId id(application_window_host, delegate_id);
  application_contents()->MediaMutedStatusChanged(id, muted);
}

void MediaApplicationContentsObserver::AddMediaPlayerEntry(
    const MediaPlayerId& id,
    ActiveMediaPlayerMap* player_map) {
  (*player_map)[id.first].insert(id.second);
}

bool MediaApplicationContentsObserver::RemoveMediaPlayerEntry(
    const MediaPlayerId& id,
    ActiveMediaPlayerMap* player_map) {
  auto it = player_map->find(id.first);
  if (it == player_map->end())
    return false;

  // Remove the player.
  bool did_remove = it->second.erase(id.second) == 1;
  if (!did_remove)
    return false;

  // If there are no players left, remove the map entry.
  if (it->second.empty())
    player_map->erase(it);

  return true;
}

void MediaApplicationContentsObserver::RemoveAllMediaPlayerEntries(
    ApplicationWindowHost* application_window_host,
    ActiveMediaPlayerMap* player_map,
    std::set<MediaPlayerId>* removed_players) {
  auto it = player_map->find(application_window_host);
  if (it == player_map->end())
    return;

  for (int delegate_id : it->second)
    removed_players->insert(MediaPlayerId(application_window_host, delegate_id));

  player_map->erase(it);
}

}  // namespace host
