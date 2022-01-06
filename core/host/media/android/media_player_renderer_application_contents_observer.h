// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_MEDIA_ANDROID_MEDIA_PLAYER_RENDERER_WEB_CONTENTS_OBSERVER_H_
#define MUMBA_HOST_MEDIA_ANDROID_MEDIA_PLAYER_RENDERER_WEB_CONTENTS_OBSERVER_H_

#include "base/containers/flat_set.h"
#include "core/host/application/application_contents_observer.h"
#include "core/host/application/application_contents_user_data.h"

namespace host {

class MediaPlayerRenderer;

// This class propagates ApplicationContents muting updates to MediaPlayerRenderers.
// This allows us to avoid adding N ApplicationContentsObservers for N
// MediaPlayerRenderers on a page. Essentially, this is a call-stack filter to
// prevent uninteresting observer methods from calling into the
// MediaPlayerRenderers.
class MediaPlayerRendererApplicationContentsObserver
    : public ApplicationContentsObserver,
      public ApplicationContentsUserData<MediaPlayerRendererApplicationContentsObserver> {
 public:
  ~MediaPlayerRendererApplicationContentsObserver() override;

  void AddMediaPlayerRenderer(MediaPlayerRenderer* player);
  void RemoveMediaPlayerRenderer(MediaPlayerRenderer* player);

  // ApplicationContentsObserver implementation.
  void DidUpdateAudioMutingState(bool muted) override;
  void ApplicationContentsDestroyed() override;

 private:
  explicit MediaPlayerRendererApplicationContentsObserver(ApplicationContents* web_contents);
  friend class ApplicationContentsUserData<MediaPlayerRendererApplicationContentsObserver>;

  base::flat_set<MediaPlayerRenderer*> players_;

  DISALLOW_COPY_AND_ASSIGN(MediaPlayerRendererApplicationContentsObserver);
};

}  // namespace host

#endif  // MUMBA_HOST_MEDIA_ANDROID_MEDIA_PLAYER_RENDERER_WEB_CONTENTS_OBSERVER_H_
