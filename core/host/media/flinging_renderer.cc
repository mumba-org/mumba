// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/media/flinging_renderer.h"

#include "base/memory/ptr_util.h"
#include "core/host/application/application_window_host_delegate.h"
#include "core/host/application/application_window_host.h"
#include "core/host/application/presentation_service_delegate.h"
#include "core/host/host_client.h"
#include "core/shared/common/client.h"

namespace host {

FlingingRenderer::FlingingRenderer(std::unique_ptr<MediaController> controller)
    : controller_(std::move(controller)) {}

FlingingRenderer::~FlingingRenderer() = default;

// static
std::unique_ptr<FlingingRenderer> FlingingRenderer::Create(
    ApplicationWindowHost* app_window_host,
    const std::string& presentation_id) {
  DVLOG(1) << __func__;

  common::Client* content_client = common::GetClient();
  if (!content_client)
    return nullptr;

  HostClient* host_client = content_client->host();
  if (!host_client)
    return nullptr;

  ControllerPresentationServiceDelegate* presentation_delegate =
      host_client->GetControllerPresentationServiceDelegate(
          app_window_host->delegate()->GetAsApplicationContents());

  if (!presentation_delegate)
    return nullptr;

  auto media_controller = presentation_delegate->GetMediaController(
      app_window_host->GetProcess()->GetID(),
      app_window_host->GetRoutingID(), presentation_id);

  if (!media_controller)
    return nullptr;

  return base::WrapUnique<FlingingRenderer>(
      new FlingingRenderer(std::move(media_controller)));
}

// media::Renderer implementation
void FlingingRenderer::Initialize(media::MediaResource* media_resource,
                                  media::RendererClient* client,
                                  const media::PipelineStatusCB& init_cb) {
  DVLOG(2) << __func__;
  init_cb.Run(media::PIPELINE_OK);
}

void FlingingRenderer::SetCdm(media::CdmContext* cdm_context,
                              const media::CdmAttachedCB& cdm_attached_cb) {
  // The flinging renderer does not support playing encrypted content.
  NOTREACHED();
}

void FlingingRenderer::Flush(const base::Closure& flush_cb) {
  DVLOG(2) << __func__;
  // There is nothing to reset, we can no-op the call.
  flush_cb.Run();
}

void FlingingRenderer::StartPlayingFrom(base::TimeDelta time) {
  DVLOG(2) << __func__;
  controller_->Seek(time);
  controller_->Play();
}

void FlingingRenderer::SetPlaybackRate(double playback_rate) {
  DVLOG(2) << __func__;
  if (playback_rate == 0)
    controller_->Pause();
  else
    controller_->Play();
}

void FlingingRenderer::SetVolume(float volume) {
  DVLOG(2) << __func__;
  controller_->SetVolume(volume);
}

base::TimeDelta FlingingRenderer::GetMediaTime() {
  // TODO(https://crbug.com/830871): return correct media time.
  return base::TimeDelta();
}

}  // namespace host
