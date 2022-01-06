// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/application/media/render_media_client.h"

#include "base/command_line.h"
#include "base/logging.h"
#include "base/time/default_tick_clock.h"
#include "core/shared/common/client.h"
//#include "core/shared/application/content_renderer_client.h"
#include "media/base/media_switches.h"
#include "media/base/video_color_space.h"
#include "ui/display/display_switches.h"

namespace application {

void RenderMediaClient::Initialize() {
  static RenderMediaClient* client = new RenderMediaClient();
  media::SetMediaClient(client);
}

RenderMediaClient::RenderMediaClient() {}

RenderMediaClient::~RenderMediaClient() {
}

void RenderMediaClient::AddSupportedKeySystems(
    std::vector<std::unique_ptr<media::KeySystemProperties>>* key_systems) {
  //GetContentClient()->renderer()->AddSupportedKeySystems(key_systems);
  //DLOG(INFO) << "RenderMediaClient::AddSupportedKeySystems";
}

bool RenderMediaClient::IsKeySystemsUpdateNeeded() {
  //return GetContentClient()->renderer()->IsKeySystemsUpdateNeeded();
  //DLOG(INFO) << "RenderMediaClient::IsKeySystemsUpdateNeeded";
  return false;
}

bool RenderMediaClient::IsSupportedAudioConfig(
    const media::AudioConfig& config) {
  //return GetContentClient()->renderer()->IsSupportedAudioConfig(config);
  //DLOG(INFO) << "RenderMediaClient::IsSupportedAudioConfig";
  return true;
}

bool RenderMediaClient::IsSupportedVideoConfig(
    const media::VideoConfig& config) {
  //return GetContentClient()->renderer()->IsSupportedVideoConfig(config);
  //DLOG(INFO) << "RenderMediaClient::IsSupportedVideoConfig";
  return true;
}

bool RenderMediaClient::IsSupportedBitstreamAudioCodec(
    media::AudioCodec codec) {
  //return GetContentClient()->renderer()->IsSupportedBitstreamAudioCodec(codec);
  //DLOG(INFO) << "RenderMediaClient::IsSupportedBitstreamAudioCodec";
  return true;
}

}  // namespace application
