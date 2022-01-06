// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/application/media/peer_connection_tracker_host.h"

#include "base/power_monitor/power_monitor.h"
#include "core/host/application/application_process_host.h"
#include "core/host/webrtc/webrtc_internals.h"
#include "core/shared/common/media/peer_connection_tracker_messages.h"
#include "core/host/webrtc_event_logger.h"

namespace host {

PeerConnectionTrackerHost::PeerConnectionTrackerHost(int render_process_id)
    : HostMessageFilter(PeerConnectionTrackerMsgStart),
      HostAssociatedInterface<common::mojom::PeerConnectionTrackerHost>(this, this),
      render_process_id_(render_process_id) {}

bool PeerConnectionTrackerHost::OnMessageReceived(const IPC::Message& message) {
  bool handled = true;

  IPC_BEGIN_MESSAGE_MAP(PeerConnectionTrackerHost, message)
    IPC_MESSAGE_HANDLER(PeerConnectionTrackerHost_AddPeerConnection,
                        OnAddPeerConnection)
    IPC_MESSAGE_HANDLER(PeerConnectionTrackerHost_AddStats, OnAddStats)
    IPC_MESSAGE_UNHANDLED(handled = false)
  IPC_END_MESSAGE_MAP()
  return handled;
}

void PeerConnectionTrackerHost::OverrideThreadForMessage(
    const IPC::Message& message, HostThread::ID* thread) {
  if (IPC_MESSAGE_CLASS(message) == PeerConnectionTrackerMsgStart)
    *thread = HostThread::UI;
}

PeerConnectionTrackerHost::~PeerConnectionTrackerHost() {
}

void PeerConnectionTrackerHost::OnChannelConnected(int32_t peer_pid) {
  DCHECK_CURRENTLY_ON(HostThread::IO);
  // Add PowerMonitor when connected to channel rather than in constructor due
  // to thread safety concerns. Observers of PowerMonitor must be added and
  // removed on the same thread. BrowserMessageFilter is created on the UI
  // thread but can be destructed on the UI or IO thread because they are
  // referenced by RenderProcessHostImpl on the UI thread and ChannelProxy on
  // the IO thread. Using OnChannelConnected and OnChannelClosing guarantees
  // execution on the IO thread.
  base::PowerMonitor* power_monitor = base::PowerMonitor::Get();
  if (power_monitor)
    power_monitor->AddObserver(this);
}

void PeerConnectionTrackerHost::OnChannelClosing() {
  DCHECK_CURRENTLY_ON(HostThread::IO);
  base::PowerMonitor* power_monitor = base::PowerMonitor::Get();
  if (power_monitor)
    power_monitor->RemoveObserver(this);
}

void PeerConnectionTrackerHost::OnAddPeerConnection(
    const PeerConnectionInfo& info) {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  WebRTCInternals* webrtc_internals = WebRTCInternals::GetInstance();
  if (webrtc_internals) {
    webrtc_internals->OnAddPeerConnection(
        render_process_id_, peer_pid(), info.lid, info.url,
        info.rtc_configuration, info.constraints);
  }
  WebRtcEventLogger* const logger = WebRtcEventLogger::Get();
  if (logger) {
    logger->PeerConnectionAdded(render_process_id_, info.lid,
                                info.peer_connection_id);
  }
}

void PeerConnectionTrackerHost::RemovePeerConnection(int lid) {
  if (!HostThread::CurrentlyOn(HostThread::UI)) {
    HostThread::PostTask(
        HostThread::UI, FROM_HERE,
        base::BindOnce(&PeerConnectionTrackerHost::RemovePeerConnection, this,
                       lid));
    return;
  }
  WebRTCInternals* webrtc_internals = WebRTCInternals::GetInstance();
  if (webrtc_internals) {
    webrtc_internals->OnRemovePeerConnection(peer_pid(), lid);
  }
  WebRtcEventLogger* const logger = WebRtcEventLogger::Get();
  if (logger) {
    logger->PeerConnectionRemoved(render_process_id_, lid);
  }
}

void PeerConnectionTrackerHost::UpdatePeerConnection(int lid,
                                                     const std::string& type,
                                                     const std::string& value) {
  if (!HostThread::CurrentlyOn(HostThread::UI)) {
    HostThread::PostTask(
        HostThread::UI, FROM_HERE,
        base::BindOnce(&PeerConnectionTrackerHost::UpdatePeerConnection, this,
                       lid, type, value));
    return;
  }
  // TODO(eladalon): Get rid of magic value. https://crbug.com/810383
  if (type == "stop") {
    WebRtcEventLogger* const logger = WebRtcEventLogger::Get();
    if (logger) {
      logger->PeerConnectionStopped(render_process_id_, lid);
    }
  }

  WebRTCInternals* webrtc_internals = WebRTCInternals::GetInstance();
  if (webrtc_internals) {
    webrtc_internals->OnUpdatePeerConnection(peer_pid(), lid, type, value);
  }
}

void PeerConnectionTrackerHost::OnAddStats(int lid,
                                           const base::ListValue& value) {
  WebRTCInternals* webrtc_internals = WebRTCInternals::GetInstance();
  if (webrtc_internals) {
    webrtc_internals->OnAddStats(peer_pid(), lid, value);
  }
}

void PeerConnectionTrackerHost::GetUserMedia(
    const std::string& origin,
    bool audio,
    bool video,
    const std::string& audio_constraints,
    const std::string& video_constraints) {
  if (!HostThread::CurrentlyOn(HostThread::UI)) {
    HostThread::PostTask(
        HostThread::UI, FROM_HERE,
        base::BindOnce(&PeerConnectionTrackerHost::GetUserMedia, this, origin,
                       audio, video, audio_constraints, video_constraints));
    return;
  }
  WebRTCInternals* webrtc_internals = WebRTCInternals::GetInstance();
  if (webrtc_internals) {
    webrtc_internals->OnGetUserMedia(render_process_id_, peer_pid(), origin,
                                     audio, video, audio_constraints,
                                     video_constraints);
  }
}

void PeerConnectionTrackerHost::WebRtcEventLogWrite(int lid,
                                                    const std::string& output) {
  if (!HostThread::CurrentlyOn(HostThread::UI)) {
    HostThread::PostTask(
        HostThread::UI, FROM_HERE,
        base::BindOnce(&PeerConnectionTrackerHost::WebRtcEventLogWrite, this,
                       lid, output));
    return;
  }
  WebRtcEventLogger* const logger = WebRtcEventLogger::Get();
  if (logger) {
    logger->OnWebRtcEventLogWrite(render_process_id_, lid, output);
  }
}

void PeerConnectionTrackerHost::OnSuspend() {
  HostThread::PostTask(
      HostThread::UI, FROM_HERE,
      base::BindOnce(&PeerConnectionTrackerHost::SendOnSuspendOnUIThread,
                     this));
}

void PeerConnectionTrackerHost::SendOnSuspendOnUIThread() {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  ApplicationProcessHost* host =
      ApplicationProcessHost::FromID(render_process_id_);
  if (host)
    host->Send(new PeerConnectionTracker_OnSuspend());
}

}  // namespace host
