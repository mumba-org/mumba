// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_MEDIA_SESSION_MOCK_MEDIA_SESSION_OBSERVER_H_
#define MUMBA_HOST_MEDIA_SESSION_MOCK_MEDIA_SESSION_OBSERVER_H_

#include "core/host/media_session_observer.h"
#include "testing/gmock/include/gmock/gmock.h"

namespace host {

class MockMediaSessionObserver : public MediaSessionObserver {
 public:
  MockMediaSessionObserver(MediaSession* media_session);
  virtual ~MockMediaSessionObserver() override;

  MOCK_METHOD0(MediaSessionDestroyed, void());
  MOCK_METHOD2(MediaSessionStateChanged,
               void(bool is_controllable, bool is_suspended));
  MOCK_METHOD1(MediaSessionMetadataChanged,
               void(const base::Optional<MediaMetadata>& metadata));
  MOCK_METHOD1(MediaSessionActionsChanged,
               void(const std::set<blink::mojom::MediaSessionAction>& action));
};
}

#endif  // MUMBA_HOST_MEDIA_SESSION_MOCK_MEDIA_SESSION_OBSERVER_H_
