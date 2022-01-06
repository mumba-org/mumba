// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/webrtc_log.h"

#include "core/host/application/media/media_stream_manager.h"
#include "core/host/host_thread.h"

namespace host {

// static
void WebRtcLog::SetLogMessageCallback(
    int render_process_id,
    const base::Callback<void(const std::string&)>& callback) {
  DCHECK_CURRENTLY_ON(HostThread::IO);
  MediaStreamManager::RegisterNativeLogCallback(render_process_id, callback);
}

// static
void WebRtcLog::ClearLogMessageCallback(int render_process_id) {
  DCHECK_CURRENTLY_ON(HostThread::IO);
  MediaStreamManager::UnregisterNativeLogCallback(render_process_id);
}

}  // namespace content
