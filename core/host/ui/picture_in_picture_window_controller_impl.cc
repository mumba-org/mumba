// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/ui/picture_in_picture_window_controller_impl.h"

#include "components/viz/common/surfaces/surface_id.h"
#include "core/host/media/media_application_contents_observer.h"
#include "core/host/ui/overlay_surface_embedder.h"
#include "core/host/application/application_contents.h"
#include "core/shared/common/media/media_player_delegate_messages.h"
#include "core/host/host_client.h"
#include "core/host/ui/overlay_window.h"
#include "core/shared/common/client.h"

namespace host {

DEFINE_WEB_CONTENTS_USER_DATA_KEY(PictureInPictureWindowControllerImpl);

// static
PictureInPictureWindowController*
PictureInPictureWindowController::GetOrCreateForApplicationContents(
    ApplicationContents* application_contents) {
  return PictureInPictureWindowControllerImpl::GetOrCreateForApplicationContents(
      application_contents);
}

// static
PictureInPictureWindowControllerImpl*
PictureInPictureWindowControllerImpl::GetOrCreateForApplicationContents(
    ApplicationContents* application_contents) {
  DCHECK(application_contents);

  // This is a no-op if the controller already exists.
  CreateForApplicationContents(application_contents);
  return FromApplicationContents(application_contents);
}

PictureInPictureWindowControllerImpl::~PictureInPictureWindowControllerImpl() {
  if (window_)
    window_->Close();
}

PictureInPictureWindowControllerImpl::PictureInPictureWindowControllerImpl(
    ApplicationContents* initiator)
    : initiator_(initiator) {
  DCHECK(initiator_);
  window_ = common::GetClient()->host()->CreateWindowForPictureInPicture(this);
  DCHECK(window_) << "Picture in Picture requires a valid window.";
}

void PictureInPictureWindowControllerImpl::Show() {
  DCHECK(window_);
  DCHECK(surface_id_.is_valid());

  window_->Show();
}

void PictureInPictureWindowControllerImpl::Close() {
  DCHECK(window_);
  window_->Hide();

  surface_id_ = viz::SurfaceId();

  MediaApplicationContentsObserver* observer =
      initiator_->media_application_contents_observer();
  base::Optional<ApplicationContentsObserver::MediaPlayerId> player_id =
      observer->GetPictureInPictureVideoMediaPlayerId();
  DCHECK(player_id.has_value());

  if (observer->IsPlayerActive(*player_id))
    player_id->first->Send(new MediaPlayerDelegateMsg_EndPictureInPictureMode(
        player_id->first->GetRoutingID(), player_id->second));
}

void PictureInPictureWindowControllerImpl::EmbedSurface(
    const viz::SurfaceId& surface_id,
    const gfx::Size& natural_size) {
  DCHECK(window_);
  DCHECK(surface_id.is_valid());
  surface_id_ = surface_id;

  window_->UpdateVideoSize(natural_size);

  if (!embedder_)
    embedder_.reset(new OverlaySurfaceEmbedder(window_.get()));
  embedder_->SetPrimarySurfaceId(surface_id_);
}

OverlayWindow* PictureInPictureWindowControllerImpl::GetWindowForTesting() {
  return window_.get();
}

void PictureInPictureWindowControllerImpl::UpdateLayerBounds() {
  if (embedder_)
    embedder_->UpdateLayerBounds();
}

bool PictureInPictureWindowControllerImpl::TogglePlayPause() {
  DCHECK(window_ && window_->IsActive());

  MediaApplicationContentsObserver* observer =
      initiator_->media_application_contents_observer();
  base::Optional<ApplicationContentsObserver::MediaPlayerId> player_id =
      observer->GetPictureInPictureVideoMediaPlayerId();
  DCHECK(player_id.has_value());

  if (observer->IsPlayerActive(*player_id)) {
    player_id->first->Send(new MediaPlayerDelegateMsg_Pause(
        player_id->first->GetRoutingID(), player_id->second));
    return false;
  }

  player_id->first->Send(new MediaPlayerDelegateMsg_Play(
      player_id->first->GetRoutingID(), player_id->second));
  return true;
}

}  // namespace host