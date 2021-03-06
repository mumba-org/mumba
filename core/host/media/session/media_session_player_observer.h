// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_MEDIA_SESSION_MEDIA_SESSION_PLAYER_OBSERVER_H_
#define MUMBA_HOST_MEDIA_SESSION_MEDIA_SESSION_PLAYER_OBSERVER_H_

#include "base/time/time.h"

namespace host {
class ApplicationWindowHost;

class MediaSessionPlayerObserver {
 public:
  MediaSessionPlayerObserver() = default;
  virtual ~MediaSessionPlayerObserver() = default;

  // The given |player_id| has been suspended by the MediaSession.
  virtual void OnSuspend(int player_id) = 0;

  // The given |player_id| has been resumed by the MediaSession.
  virtual void OnResume(int player_id) = 0;

  // The given |player_id| has been seeked forward by the MediaSession.
  virtual void OnSeekForward(int player_id, base::TimeDelta seek_time) = 0;

  // The given |player_id| has been seeked backward by the MediaSession.
  virtual void OnSeekBackward(int player_id, base::TimeDelta seek_time) = 0;

  // The given |player_id| has been set a new volume multiplier by
  // the MediaSession.
  virtual void OnSetVolumeMultiplier(int player_id,
                                     double volume_multiplier) = 0;

  // Returns the ApplicationWindowHost this player observer belongs to. Returns
  // nullptr if unavailable.
  virtual ApplicationWindowHost* application_window_host() const = 0;
};

}  // namespace host

#endif  // MUMBA_HOST_MEDIA_SESSION_MEDIA_SESSION_PLAYER_OBSERVER_H_
