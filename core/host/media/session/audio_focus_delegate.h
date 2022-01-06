// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_MEDIA_SESSION_AUDIO_FOCUS_DELEGATE_H_
#define MUMBA_HOST_MEDIA_SESSION_AUDIO_FOCUS_DELEGATE_H_

#include "core/host/media/session/audio_focus_manager.h"

namespace host {

class MediaSessionImpl;

// AudioFocusDelegate is an interface abstracting audio focus handling for the
// MediaSession class.
class AudioFocusDelegate {
 public:
  // Factory method returning an implementation of AudioFocusDelegate.
  static std::unique_ptr<AudioFocusDelegate> Create(
      MediaSessionImpl* media_session);

  virtual ~AudioFocusDelegate() = default;

  virtual bool RequestAudioFocus(
      AudioFocusManager::AudioFocusType audio_focus_type) = 0;
  virtual void AbandonAudioFocus() = 0;
};

}  // namespace host

#endif  // MUMBA_HOST_MEDIA_SESSION_AUDIO_FOCUS_DELEGATE_H_
