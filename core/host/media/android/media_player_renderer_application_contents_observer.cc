// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/media/android/media_player_renderer_application_contents_observer.h"

#include "core/host/media/android/media_player_renderer.h"

DEFINE_WEB_CONTENTS_USER_DATA_KEY(
    content::MediaPlayerRendererApplicationContentsObserver);

namespace host {

MediaPlayerRendererApplicationContentsObserver::MediaPlayerRendererApplicationContentsObserver(
    ApplicationContents* web_contents)
    : ApplicationContentsObserver(web_contents) {
  DLOG(INFO) << "MediaPlayerRendererApplicationContentsObserver: " << this;
}

MediaPlayerRendererApplicationContentsObserver::
    ~MediaPlayerRendererApplicationContentsObserver() {

  //DLOG(INFO) << "~MediaPlayerRendererApplicationContentsObserver: " << this;
}

void MediaPlayerRendererApplicationContentsObserver::AddMediaPlayerRenderer(
    MediaPlayerRenderer* player) {
  DCHECK(player);
  DCHECK(players_.find(player) == players_.end());
  players_.insert(player);
}

void MediaPlayerRendererApplicationContentsObserver::RemoveMediaPlayerRenderer(
    MediaPlayerRenderer* player) {
  DCHECK(player);
  auto erase_result = players_.erase(player);
  DCHECK_EQ(1u, erase_result);
}

void MediaPlayerRendererApplicationContentsObserver::DidUpdateAudioMutingState(
    bool muted) {
  for (MediaPlayerRenderer* player : players_)
    player->OnUpdateAudioMutingState(muted);
}

void MediaPlayerRendererApplicationContentsObserver::ApplicationContentsDestroyed() {
  for (MediaPlayerRenderer* player : players_)
    player->OnApplicationContentsDestroyed();
  players_.clear();
}

}  // namespace host
