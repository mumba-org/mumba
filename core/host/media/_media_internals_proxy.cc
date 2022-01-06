// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/media/media_internals_proxy.h"

#include "base/bind.h"
#include "base/location.h"
#include "core/host/media/media_internals.h"
#include "core/host/media/media_internals_handler.h"
#include "core/host/host_thread.h"

namespace host {

MediaInternalsProxy::MediaInternalsProxy() {
}

MediaInternalsProxy::~MediaInternalsProxy() {}

void MediaInternalsProxy::Attach(MediaInternalsMessageHandler* handler) {
  DCHECK_CURRENTLY_ON(HostThread::UI);

  handler_ = handler;
  update_callback_ = base::Bind(&MediaInternalsProxy::UpdateUIOnUIThread, this);
  MediaInternals::GetInstance()->AddUpdateCallback(update_callback_);
}

void MediaInternalsProxy::Detach() {
  DCHECK_CURRENTLY_ON(HostThread::UI);

  handler_ = nullptr;
  MediaInternals::GetInstance()->RemoveUpdateCallback(update_callback_);
}

void MediaInternalsProxy::GetEverything() {
  DCHECK_CURRENTLY_ON(HostThread::UI);

  MediaInternals::GetInstance()->SendHistoricalMediaEvents();

  // Ask MediaInternals for its data on IO thread.
  HostThread::PostTask(
      HostThread::IO, FROM_HERE,
      base::BindOnce(&MediaInternalsProxy::GetEverythingOnIOThread, this));
}

void MediaInternalsProxy::GetEverythingOnIOThread() {
  DCHECK_CURRENTLY_ON(HostThread::IO);
  // TODO(xhwang): Investigate whether we can update on UI thread directly.
  MediaInternals::GetInstance()->SendAudioStreamData();
  MediaInternals::GetInstance()->SendVideoCaptureDeviceCapabilities();
}

void MediaInternalsProxy::UpdateUIOnUIThread(const base::string16& update) {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  // Don't forward updates to a destructed UI.
  if (handler_)
    handler_->OnUpdate(update);
}

}  // namespace host
