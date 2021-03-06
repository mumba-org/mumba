// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/webrtc/webrtc_internals_message_handler.h"

#include "core/host/webrtc/webrtc_internals.h"
#include "core/shared/common/media/peer_connection_tracker_messages.h"
#include "core/host/host_thread.h"
#include "core/host/render_frame_host.h"
#include "core/host/render_process_host.h"
#include "core/host/web_contents.h"
#include "core/host/web_ui.h"
#include "core/shared/common/url_constants.h"

namespace host {

WebRTCInternalsMessageHandler::WebRTCInternalsMessageHandler()
    : WebRTCInternalsMessageHandler(WebRTCInternals::GetInstance()) {}

WebRTCInternalsMessageHandler::WebRTCInternalsMessageHandler(
    WebRTCInternals* webrtc_internals)
    : webrtc_internals_(webrtc_internals) {
  DCHECK(webrtc_internals);
  webrtc_internals_->AddObserver(this);
}

WebRTCInternalsMessageHandler::~WebRTCInternalsMessageHandler() {
  webrtc_internals_->RemoveObserver(this);
}

void WebRTCInternalsMessageHandler::RegisterMessages() {
  web_ui()->RegisterMessageCallback(
      "getAllStats",
      base::BindRepeating(&WebRTCInternalsMessageHandler::OnGetAllStats,
                          base::Unretained(this)));

  web_ui()->RegisterMessageCallback(
      "enableAudioDebugRecordings",
      base::BindRepeating(
          &WebRTCInternalsMessageHandler::OnSetAudioDebugRecordingsEnabled,
          base::Unretained(this), true));

  web_ui()->RegisterMessageCallback(
      "disableAudioDebugRecordings",
      base::BindRepeating(
          &WebRTCInternalsMessageHandler::OnSetAudioDebugRecordingsEnabled,
          base::Unretained(this), false));

  web_ui()->RegisterMessageCallback(
      "enableEventLogRecordings",
      base::BindRepeating(
          &WebRTCInternalsMessageHandler::OnSetEventLogRecordingsEnabled,
          base::Unretained(this), true));

  web_ui()->RegisterMessageCallback(
      "disableEventLogRecordings",
      base::BindRepeating(
          &WebRTCInternalsMessageHandler::OnSetEventLogRecordingsEnabled,
          base::Unretained(this), false));

  web_ui()->RegisterMessageCallback(
      "finishedDOMLoad",
      base::BindRepeating(&WebRTCInternalsMessageHandler::OnDOMLoadDone,
                          base::Unretained(this)));
}

RenderFrameHost* WebRTCInternalsMessageHandler::GetWebRTCInternalsHost() const {
  RenderFrameHost* host = web_ui()->GetWebContents()->GetMainFrame();
  if (host) {
    // Make sure we only ever execute the script in the webrtc-internals page.
    const GURL url(host->GetLastCommittedURL());
    if (!url.SchemeIs(kChromeUIScheme) ||
        url.host() != kChromeUIWebRTCInternalsHost) {
      // Some other page is currently loaded even though we might be in the
      // process of loading webrtc-internals.  So, the current RFH is not the
      // one we're waiting for.
      host = nullptr;
    }
  }

  return host;
}

void WebRTCInternalsMessageHandler::OnGetAllStats(
    const base::ListValue* /* unused_list */) {
  for (RenderProcessHost::iterator i(
       content::RenderProcessHost::AllHostsIterator());
       !i.IsAtEnd(); i.Advance()) {
    i.GetCurrentValue()->Send(new PeerConnectionTracker_GetAllStats());
  }
}

void WebRTCInternalsMessageHandler::OnSetAudioDebugRecordingsEnabled(
    bool enable, const base::ListValue* /* unused_list */) {
  if (enable) {
    webrtc_internals_->EnableAudioDebugRecordings(web_ui()->GetWebContents());
  } else {
    webrtc_internals_->DisableAudioDebugRecordings();
  }
}

void WebRTCInternalsMessageHandler::OnSetEventLogRecordingsEnabled(
    bool enable,
    const base::ListValue* /* unused_list */) {
  if (!webrtc_internals_->CanToggleEventLogRecordings()) {
    LOG(WARNING) << "Cannot toggle WebRTC event logging.";
    return;
  }

  if (enable) {
    webrtc_internals_->EnableLocalEventLogRecordings(
        web_ui()->GetWebContents());
  } else {
    webrtc_internals_->DisableLocalEventLogRecordings();
  }
}

void WebRTCInternalsMessageHandler::OnDOMLoadDone(
    const base::ListValue* /* unused_list */) {
  webrtc_internals_->UpdateObserver(this);

  if (webrtc_internals_->IsAudioDebugRecordingsEnabled())
    ExecuteJavascriptCommand("setAudioDebugRecordingsEnabled", nullptr);

  if (webrtc_internals_->IsEventLogRecordingsEnabled())
    ExecuteJavascriptCommand("setEventLogRecordingsEnabled", nullptr);

  const base::Value can_toggle(
      webrtc_internals_->CanToggleEventLogRecordings());
  ExecuteJavascriptCommand("setEventLogRecordingsToggleability", &can_toggle);
}

void WebRTCInternalsMessageHandler::OnUpdate(const char* command,
                                             const base::Value* args) {
  ExecuteJavascriptCommand(command, args);
}

// TODO(eladalon): Make this function accept a vector of base::Values.
// https://crbug.com/817384
void WebRTCInternalsMessageHandler::ExecuteJavascriptCommand(
    const char* command,
    const base::Value* args) {
  DCHECK_CURRENTLY_ON(HostThread::UI);

  RenderFrameHost* host = GetWebRTCInternalsHost();
  if (!host)
    return;

  std::vector<const base::Value*> args_vector;
  if (args)
    args_vector.push_back(args);

  base::string16 script = WebUI::GetJavascriptCall(command, args_vector);
  host->ExecuteJavaScript(script);
}

}  // namespace host
