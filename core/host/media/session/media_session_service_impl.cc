// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/media/session/media_session_service_impl.h"

#include "core/common/result_codes.h"
#include "core/host/media/session/media_metadata_sanitizer.h"
#include "core/host/media/session/media_session_impl.h"
#include "core/host/host_thread.h"
//#include "core/host/application/render_frame_host.h"
#include "core/host/application/application_window_host.h"
#include "core/host/application/application_contents.h"

namespace host {

MediaSessionServiceImpl::MediaSessionServiceImpl(
    ApplicationWindowHost* app_window_host)
    //RenderFrameHost* render_frame_host)
    : app_window_process_id_(app_window_host->GetProcess()->GetID()),
      app_window_routing_id_(app_window_host->GetRoutingID()),
      playback_state_(blink::mojom::MediaSessionPlaybackState::NONE) {
  MediaSessionImpl* session = GetMediaSession();
  if (session)
    session->OnServiceCreated(this);
}

MediaSessionServiceImpl::~MediaSessionServiceImpl() {
  MediaSessionImpl* session = GetMediaSession();
  if (session)
    session->OnServiceDestroyed(this);
}

// static
void MediaSessionServiceImpl::Create(
    ApplicationWindowHost*  app_window_host,
    blink::mojom::MediaSessionServiceRequest request) {
  MediaSessionServiceImpl* impl =
      new MediaSessionServiceImpl(app_window_host);
  impl->Bind(std::move(request));
}

// RenderFrameHost* MediaSessionServiceImpl::GetRenderFrameHost() {
//   return RenderFrameHost::FromID(render_frame_process_id_,
//                                  render_frame_routing_id_);
// }

ApplicationWindowHost* MediaSessionServiceImpl::GetApplicationWindowHost() {
  return ApplicationWindowHost::FromID(app_window_process_id_,
                                       app_window_routing_id_);
}

void MediaSessionServiceImpl::DidFinishNavigation() {
  // At this point the BrowsingContext of the frame has changed, so the members
  // need to be reset, and notify MediaSessionImpl.
  SetPlaybackState(blink::mojom::MediaSessionPlaybackState::NONE);
  SetMetadata(base::nullopt);
  ClearActions();
}

void MediaSessionServiceImpl::SetClient(
    blink::mojom::MediaSessionClientPtr client) {
  client_ = std::move(client);
}

void MediaSessionServiceImpl::SetPlaybackState(
    blink::mojom::MediaSessionPlaybackState state) {
  playback_state_ = state;
  MediaSessionImpl* session = GetMediaSession();
  if (session)
    session->OnMediaSessionPlaybackStateChanged(this);
}

void MediaSessionServiceImpl::SetMetadata(
    const base::Optional<common::MediaMetadata>& metadata) {
  // When receiving a MediaMetadata, the browser process can't trust that it is
  // coming from a known and secure source. It must be processed accordingly.
  if (metadata.has_value() &&
      !MediaMetadataSanitizer::CheckSanity(metadata.value())) {
    ApplicationWindowHost* awh = GetApplicationWindowHost();
    if (awh) {
      awh->GetProcess()->Shutdown(common::RESULT_CODE_KILLED_BAD_MESSAGE);
      //awh->GetProcess()->ShutdownForBadMessage(
      //    ApplicationProcessHost::CrashReportMode::GENERATE_CRASH_DUMP);
    }
    return;
  }
  metadata_ = metadata;

  MediaSessionImpl* session = GetMediaSession();
  if (session)
    session->OnMediaSessionMetadataChanged(this);
}

void MediaSessionServiceImpl::EnableAction(
    blink::mojom::MediaSessionAction action) {
  actions_.insert(action);
  MediaSessionImpl* session = GetMediaSession();
  if (session)
    session->OnMediaSessionActionsChanged(this);
}

void MediaSessionServiceImpl::DisableAction(
    blink::mojom::MediaSessionAction action) {
  actions_.erase(action);
  MediaSessionImpl* session = GetMediaSession();
  if (session)
    session->OnMediaSessionActionsChanged(this);
}

void MediaSessionServiceImpl::ClearActions() {
  actions_.clear();
  MediaSessionImpl* session = GetMediaSession();
  if (session)
    session->OnMediaSessionActionsChanged(this);
}

MediaSessionImpl* MediaSessionServiceImpl::GetMediaSession() {
  ApplicationWindowHost* awh = GetApplicationWindowHost();
  if (!awh)
    return nullptr;

  ApplicationContents* contents = ApplicationContents::FromApplicationWindowHost(awh);
  if (!contents)
    return nullptr;

  return MediaSessionImpl::Get(contents);
}

void MediaSessionServiceImpl::Bind(
    blink::mojom::MediaSessionServiceRequest request) {
  binding_.reset(new mojo::Binding<blink::mojom::MediaSessionService>(
      this, std::move(request)));
}

}  // namespace host
