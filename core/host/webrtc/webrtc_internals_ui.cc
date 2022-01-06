// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/webrtc/webrtc_internals_ui.h"

#include "core/host/webrtc/webrtc_internals_message_handler.h"
#include "content/grit/content_resources.h"
#include "core/host/web_contents.h"
#include "core/host/web_ui.h"
#include "core/host/web_ui_data_source.h"
#include "core/shared/common/url_constants.h"

namespace host {
namespace {

WebUIDataSource* CreateWebRTCInternalsHTMLSource() {
  WebUIDataSource* source =
      WebUIDataSource::Create(kChromeUIWebRTCInternalsHost);

  source->SetJsonPath("strings.js");
  source->AddResourcePath("webrtc_internals.js", IDR_WEBRTC_INTERNALS_JS);
  source->SetDefaultResource(IDR_WEBRTC_INTERNALS_HTML);
  source->UseGzip();
  return source;
}

}  // namespace

////////////////////////////////////////////////////////////////////////////////
//
// WebRTCInternalsUI
//
////////////////////////////////////////////////////////////////////////////////

WebRTCInternalsUI::WebRTCInternalsUI(WebUI* web_ui)
    : WebUIController(web_ui) {
  web_ui->AddMessageHandler(std::make_unique<WebRTCInternalsMessageHandler>());

  BrowserContext* browser_context =
      web_ui->GetWebContents()->GetBrowserContext();
  WebUIDataSource::Add(browser_context, CreateWebRTCInternalsHTMLSource());
}

}  // namespace host
