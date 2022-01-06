// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_MEDIA_SESSION_MEDIA_SESSION_CONTROLLERS_MANAGER_H_
#define MUMBA_HOST_MEDIA_SESSION_MEDIA_SESSION_CONTROLLERS_MANAGER_H_

#include <map>
#include <memory>
#include <utility>

#include "base/macros.h"
#include "base/time/time.h"
#include "core/shared/common/content_export.h"
#include "core/host/application/application_contents_observer.h"  // For MediaPlayerId.

namespace media {
enum class MediaContentType;
}  // namespace media

namespace host {

class MediaSessionController;
class MediaApplicationContentsObserver;
class ApplicationWindowHost;

// MediaSessionControllersManager is a delegate of MediaApplicationContentsObserver that
// handles MediaSessionController instances.
class CONTENT_EXPORT MediaSessionControllersManager {
 public:
  using MediaPlayerId = ApplicationContentsObserver::MediaPlayerId;
  using ControllersMap =
      std::map<MediaPlayerId, std::unique_ptr<MediaSessionController>>;

  explicit MediaSessionControllersManager(
      MediaApplicationContentsObserver* media_application_contents_observer);
  ~MediaSessionControllersManager();

  // Clear all the MediaSessionController associated with the given
  // |render_frame_host|.
  //void RenderFrameDeleted(RenderFrameHost* render_frame_host);
  void ApplicationWindowDeleted(ApplicationWindowHost* app_window_host);

  // Called before a player starts playing. It will be added to the media
  // session and will have a controller associated with it.
  // Returns whether the player was added to the session and can start playing.
  bool RequestPlay(const MediaPlayerId& id,
                   bool has_audio,
                   bool is_remote,
                   media::MediaContentType media_content_type);

  // Called when the given player |id| has paused.
  void OnPause(const MediaPlayerId& id);

  // Called when the given player |id| has ended.
  void OnEnd(const MediaPlayerId& id);

 private:
  friend class MediaSessionControllersManagerTest;

  // Weak pointer because |this| is owned by |media_application_contents_observer_|.
  MediaApplicationContentsObserver* const media_application_contents_observer_;

  ControllersMap controllers_map_;

  DISALLOW_COPY_AND_ASSIGN(MediaSessionControllersManager);
};

}  // namespace host

#endif // MUMBA_HOST_MEDIA_SESSION_MEDIA_SESSION_CONTROLLERS_MANAGER_H_
