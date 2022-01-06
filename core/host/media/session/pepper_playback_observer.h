// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_MEDIA_SESSION_PEPPER_PLAYBACK_OBSERVER_H_
#define MUMBA_HOST_MEDIA_SESSION_PEPPER_PLAYBACK_OBSERVER_H_

#include <stdint.h>
#include <map>
#include <memory>
#include <utility>

#include "base/macros.h"

namespace host {

class PepperPlayerDelegate;
class RenderFrameHost;
class ApplicationContents;

// Class observing Pepper playback changes from ApplicationContents, and update
// MediaSession accordingly. Can only be a member of ApplicationContents and must be
// destroyed in ~ApplicationContents().
class PepperPlaybackObserver {
 public:
  explicit PepperPlaybackObserver(ApplicationContents* contents);
  virtual ~PepperPlaybackObserver();

  void RenderFrameDeleted(RenderFrameHost* render_frame_host);

  void PepperInstanceCreated(RenderFrameHost* render_frame_host,
                             int32_t pp_instance);
  void PepperInstanceDeleted(RenderFrameHost* render_frame_host,
                             int32_t pp_instance);
  // This method is called when a Pepper instance starts making sound.
  void PepperStartsPlayback(RenderFrameHost* render_frame_host,
                            int32_t pp_instance);
  // This method is called when a Pepper instance stops making sound.
  void PepperStopsPlayback(RenderFrameHost* render_frame_host,
                           int32_t pp_instance);

 private:
  using PlayerId = std::pair<RenderFrameHost*, int32_t>;

  // Owning PepperPlayerDelegates.
  using PlayersMap = std::map<PlayerId, std::unique_ptr<PepperPlayerDelegate>>;
  PlayersMap players_map_;

  // Map for whether Pepper players have ever played sound.
  // Used for recording UMA.
  //
  // The mapped player ids must be a super-set of player ids in |players_map_|,
  // and the map is also used for cleaning up when RenderFrame is deleted or
  // ApplicationContents is destructed.
  using PlayersPlayedSoundMap = std::map<PlayerId, bool>;
  PlayersPlayedSoundMap players_played_sound_map_;

  // Weak reference to ApplicationContents.
  ApplicationContents* contents_;

  DISALLOW_COPY_AND_ASSIGN(PepperPlaybackObserver);
};

}  // namespace host

#endif  // MUMBA_HOST_MEDIA_SESSION_PEPPER_PLAYBACK_OBSERVER_H_
