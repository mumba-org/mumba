// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_MEDIA_ANDROID_MEDIA_WEB_CONTENTS_OBSERVER_ANDROID_H_
#define MUMBA_HOST_MEDIA_ANDROID_MEDIA_WEB_CONTENTS_OBSERVER_ANDROID_H_

#include <stdint.h>

#include <memory>
#include <unordered_map>

#include "base/macros.h"
#include "core/host/media/media_application_contents_observer.h"
#include "core/shared/common/content_export.h"

namespace media {
enum class MediaContentType;
}  // namespace media

namespace host {

class BrowserMediaPlayerManager;
class BrowserSurfaceViewManager;

// This class adds Android specific extensions to the MediaApplicationContentsObserver.
class CONTENT_EXPORT MediaApplicationContentsObserverAndroid
    : public MediaApplicationContentsObserver {
 public:
  explicit MediaApplicationContentsObserverAndroid(ApplicationContents* web_contents);
  ~MediaApplicationContentsObserverAndroid() override;

  // Returns the android specific observer for a given web contents.
  static MediaApplicationContentsObserverAndroid* FromApplicationContents(
      ApplicationContents* web_contents);

  // Gets one of the managers associated with the given |render_frame_host|.
  // Creates a new one if it doesn't exist. The caller doesn't own the
  // returned pointer.
  BrowserMediaPlayerManager* GetMediaPlayerManager(
      RenderFrameHost* render_frame_host);
  BrowserSurfaceViewManager* GetSurfaceViewManager(
      RenderFrameHost* render_frame_host);

  // Called by the ApplicationContents when a tab has been closed but may still be
  // available for "undo" -- indicates that all media players (even audio only
  // players typically allowed background audio) bound to this ApplicationContents must
  // be suspended.
  void SuspendAllMediaPlayers();

  // Initiates a synchronous MediaSession request for browser side players.
  //
  // TODO(dalecurtis): Delete this method once we're no longer using WMPA and
  // the BrowserMediaPlayerManagers.  Tracked by http://crbug.com/580626
  bool RequestPlay(RenderFrameHost* render_frame_host,
                   int delegate_id,
                   bool has_audio,
                   bool is_remote,
                   media::MediaContentType media_content_type);

  void DisconnectMediaSession(RenderFrameHost* render_frame_host,
                              int delegate_id);

  // MediaApplicationContentsObserver overrides.
  void RenderFrameDeleted(RenderFrameHost* render_frame_host) override;
  bool OnMessageReceived(const IPC::Message& message,
                         RenderFrameHost* render_frame_host) override;

 private:
  // Helper functions to handle media player IPC messages. Returns whether the
  // |message| is handled in the function.
  bool OnMediaPlayerMessageReceived(const IPC::Message& message,
                                    RenderFrameHost* render_frame_host);

  bool OnSurfaceViewManagerMessageReceived(const IPC::Message& message,
                                     RenderFrameHost* render_frame_host);

  // Map from RenderFrameHost* to BrowserMediaPlayerManager.
  using MediaPlayerManagerMap =
      std::unordered_map<RenderFrameHost*,
                         std::unique_ptr<BrowserMediaPlayerManager>>;
  MediaPlayerManagerMap media_player_managers_;

  using SurfaceViewManagerMap =
      std::unordered_map<RenderFrameHost*,
                         std::unique_ptr<BrowserSurfaceViewManager>>;
  SurfaceViewManagerMap surface_view_managers_;

  DISALLOW_COPY_AND_ASSIGN(MediaApplicationContentsObserverAndroid);
};

}  // namespace host

#endif  // MUMBA_HOST_MEDIA_ANDROID_MEDIA_WEB_CONTENTS_OBSERVER_ANDROID_H_
