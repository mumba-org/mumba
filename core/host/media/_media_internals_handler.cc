// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/media/media_internals_handler.h"

#include "base/bind.h"
#include "base/bind_helpers.h"
#include "base/values.h"
#include "core/host/media/media_internals_proxy.h"
#include "core/host/host_thread.h"
#include "core/host/application/render_frame_host.h"
#include "core/host/application/application_contents.h"
#include "core/host/web_ui.h"

namespace host {

MediaInternalsMessageHandler::MediaInternalsMessageHandler()
    : proxy_(new MediaInternalsProxy()),
      page_load_complete_(false) {}

MediaInternalsMessageHandler::~MediaInternalsMessageHandler() {
  proxy_->Detach();
}

void MediaInternalsMessageHandler::RegisterMessages() {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  proxy_->Attach(this);

  web_ui()->RegisterMessageCallback(
      "getEverything",
      base::BindRepeating(&MediaInternalsMessageHandler::OnGetEverything,
                          base::Unretained(this)));
}

void MediaInternalsMessageHandler::OnGetEverything(
    const base::ListValue* list) {
  page_load_complete_ = true;
  proxy_->GetEverything();
}

void MediaInternalsMessageHandler::OnUpdate(const base::string16& update) {
  // Don't try to execute JavaScript in a RenderView that no longer exists nor
  // if the chrome://media-internals page hasn't finished loading.
  RenderFrameHost* host = web_ui()->GetApplicationContents()->GetMainFrame();
  if (host && page_load_complete_)
    host->ExecuteJavaScript(update);
}

}  // namespace host
