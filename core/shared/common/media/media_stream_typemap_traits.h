// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_COMMON_MEDIA_MEDIA_STREAM_TYPEMAP_TRAITS_H_
#define CONTENT_COMMON_MEDIA_MEDIA_STREAM_TYPEMAP_TRAITS_H_

#include "core/shared/common/media/media_stream.mojom.h"
#include "core/shared/common/media/media_stream_controls.h"
#include "core/shared/common/media_stream_request.h"

namespace mojo {

template <>
struct EnumTraits<common::mojom::MediaStreamType, common::MediaStreamType> {
  static common::mojom::MediaStreamType ToMojom(common::MediaStreamType type);

  static bool FromMojom(common::mojom::MediaStreamType input,
                        common::MediaStreamType* out);
};

template <>
struct EnumTraits<common::mojom::MediaStreamRequestResult,
                  common::MediaStreamRequestResult> {
  static common::mojom::MediaStreamRequestResult ToMojom(
      common::MediaStreamRequestResult result);

  static bool FromMojom(common::mojom::MediaStreamRequestResult input,
                        common::MediaStreamRequestResult* out);
};

template <>
struct StructTraits<common::mojom::TrackControlsDataView,
                    common::TrackControls> {
  static bool requested(const common::TrackControls& controls) {
    return controls.requested;
  }

  static const std::string& stream_source(
      const common::TrackControls& controls) {
    return controls.stream_source;
  }

  static const std::string& device_id(const common::TrackControls& controls) {
    return controls.device_id;
  }

  static bool Read(common::mojom::TrackControlsDataView input,
                   common::TrackControls* out);
};

template <>
struct StructTraits<common::mojom::StreamControlsDataView,
                    common::StreamControls> {
  static const common::TrackControls& audio(
      const common::StreamControls& controls) {
    return controls.audio;
  }

  static const common::TrackControls& video(
      const common::StreamControls& controls) {
    return controls.video;
  }

  static bool hotword_enabled(const common::StreamControls& controls) {
    return controls.hotword_enabled;
  }

  static bool disable_local_echo(const common::StreamControls& controls) {
    return controls.disable_local_echo;
  }

  static bool Read(common::mojom::StreamControlsDataView input,
                   common::StreamControls* out);
};

}  // namespace mojo

#endif  // CONTENT_COMMON_MEDIA_MEDIA_STREAM_TYPEMAP_TRAITS_H_