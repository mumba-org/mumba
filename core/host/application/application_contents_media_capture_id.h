// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_APPLICATION_CONTENTS_MEDIA_CAPTURE_ID_H_
#define MUMBA_HOST_APPLICATION_CONTENTS_MEDIA_CAPTURE_ID_H_

#include <string>

#include "core/shared/common/content_export.h"
#include "ipc/ipc_message.h"

namespace host {

struct CONTENT_EXPORT ApplicationContentsMediaCaptureId {
 public:
  ApplicationContentsMediaCaptureId() = default;
  ApplicationContentsMediaCaptureId(int render_process_id, int main_render_frame_id)
      : render_process_id(render_process_id),
        main_render_frame_id(main_render_frame_id) {}

  ApplicationContentsMediaCaptureId(int render_process_id,
                            int main_render_frame_id,
                            bool enable_auto_throttling,
                            bool disable_local_echo)
      : render_process_id(render_process_id),
        main_render_frame_id(main_render_frame_id),
        enable_auto_throttling(enable_auto_throttling),
        disable_local_echo(disable_local_echo) {}

  bool operator<(const ApplicationContentsMediaCaptureId& other) const;
  bool operator==(const ApplicationContentsMediaCaptureId& other) const;

  // Return true if render_process_id or main_render_frame_id is invalid.
  bool is_null() const;

  std::string ToString() const;

  // Tab video and audio capture need render process id and render frame id.
  int render_process_id = MSG_ROUTING_NONE;
  int main_render_frame_id = MSG_ROUTING_NONE;

  bool enable_auto_throttling = false;
  bool disable_local_echo = false;

  // TODO(qiangchen): Pass structured ID along code paths, instead of doing
  // string conversion back and forth. See crbug/648666.
  // Create WebContentsMediaCaptureId based on a string.
  // Return false if the input string does not represent a
  // WebContentsMediaCaptureId.
  static bool Parse(const std::string& str,
                    ApplicationContentsMediaCaptureId* output_id);
};

}  // namespace host

#endif  // CONTENT_PUBLIC_BROWSER_WEB_CONTENTS_MEDIA_CAPTURE_ID_H_
