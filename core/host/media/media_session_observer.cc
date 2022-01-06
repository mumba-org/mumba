// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/media/media_session_observer.h"

#include "core/host/media/session/media_session_impl.h"

namespace host {

MediaSessionObserver::MediaSessionObserver(MediaSession* media_session)
    : media_session_(media_session) {
  if (media_session_)
    media_session_->AddObserver(this);
}

MediaSessionObserver::~MediaSessionObserver() {
  StopObserving();
}

MediaSession* MediaSessionObserver::media_session() const {
  return media_session_;
}

void MediaSessionObserver::StopObserving() {
  if (media_session_)
    media_session_->RemoveObserver(this);
  media_session_ = nullptr;
}

}  // namespace host
