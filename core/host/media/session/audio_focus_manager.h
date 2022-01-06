// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_MEDIA_SESSION_AUDIO_FOCUS_MANAGER_H_
#define MUMBA_HOST_MEDIA_SESSION_AUDIO_FOCUS_MANAGER_H_

#include <list>
#include <unordered_map>

#include "base/memory/singleton.h"
#include "core/shared/common/content_export.h"
#include "core/host/application/application_contents_observer.h"

namespace host {

class MediaSessionImpl;

class CONTENT_EXPORT AudioFocusManager {
 public:
  enum class AudioFocusType {
    Gain,
    GainTransientMayDuck,
  };

  // Returns Chromium's internal AudioFocusManager.
  static AudioFocusManager* GetInstance();

  void RequestAudioFocus(MediaSessionImpl* media_session, AudioFocusType type);

  void AbandonAudioFocus(MediaSessionImpl* media_session);

 private:
  friend struct base::DefaultSingletonTraits<AudioFocusManager>;
  friend class AudioFocusManagerTest;

  AudioFocusManager();
  ~AudioFocusManager();

  void MaybeRemoveFocusEntry(MediaSessionImpl* media_session);

  // Weak reference of managed MediaSessions. A MediaSession must abandon audio
  // foucs before its destruction.
  std::list<MediaSessionImpl*> audio_focus_stack_;
};

}  // namespace host

#endif  // MUMBA_HOST_MEDIA_SESSION_AUDIO_FOCUS_MANAGER_H_
