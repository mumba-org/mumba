// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/media/session/pepper_player_delegate.h"

#include "base/command_line.h"
#include "core/host/frame_host/render_frame_host_impl.h"
#include "core/host/media/session/pepper_playback_observer.h"
#include "core/common/frame_messages.h"
#include "media/base/media_switches.h"

namespace host {

namespace {

const double kDuckVolume = 0.2f;

}  // anonymous namespace

const int PepperPlayerDelegate::kPlayerId = 0;

PepperPlayerDelegate::PepperPlayerDelegate(
    RenderFrameHost* render_frame_host, int32_t pp_instance)
    : render_frame_host_(render_frame_host),
      pp_instance_(pp_instance) {}

PepperPlayerDelegate::~PepperPlayerDelegate() = default;

void PepperPlayerDelegate::OnSuspend(int player_id) {
  if (!media::IsAudioFocusDuckFlashEnabled())
    return;

  // Pepper player cannot be really suspended. Duck the volume instead.
  DCHECK_EQ(player_id, kPlayerId);
  SetVolume(player_id, kDuckVolume);
}

void PepperPlayerDelegate::OnResume(int player_id) {
  if (!media::IsAudioFocusDuckFlashEnabled())
    return;

  DCHECK_EQ(player_id, kPlayerId);
  SetVolume(player_id, 1.0f);
}

void PepperPlayerDelegate::OnSeekForward(int player_id,
                                         base::TimeDelta seek_time) {
  // Cannot seek pepper player. Do nothing.
}

void PepperPlayerDelegate::OnSeekBackward(int player_id,
                                          base::TimeDelta seek_time) {
  // Cannot seek pepper player. Do nothing.
}

void PepperPlayerDelegate::OnSetVolumeMultiplier(int player_id,
                                                 double volume_multiplier) {
  if (!media::IsAudioFocusDuckFlashEnabled())
    return;

  DCHECK_EQ(player_id, kPlayerId);
  SetVolume(player_id, volume_multiplier);
}

RenderFrameHost* PepperPlayerDelegate::render_frame_host() const {
  return render_frame_host_;
}

void PepperPlayerDelegate::SetVolume(int player_id, double volume) {
  render_frame_host_->Send(new FrameMsg_SetPepperVolume(
      render_frame_host_->GetRoutingID(), pp_instance_, volume));
}

}  // namespace host
