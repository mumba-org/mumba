// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/media/audio_stream_monitor.h"

#include "base/bind.h"
#include "base/bind_helpers.h"
#include "base/stl_util.h"
//#include "core/host/frame_host/render_frame_host_impl.h"
#include "core/host/application/application_window_host.h"
#include "core/host/application/application_contents.h"
#include "core/host/application/invalidate_type.h"
#include "core/host/host_thread.h"

namespace host {

namespace {

AudioStreamMonitor* GetMonitorForApplicationWindow(int app_process_id,
                                                  int app_window_id) {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  // ApplicationContents* const web_contents =
  //     static_cast<ApplicationContents*>(ApplicationContents::FromRenderFrameHost(
  //         RenderFrameHost::FromID(app_process_id,, app_window_id)));
  ApplicationContents* const app_contents =
      static_cast<ApplicationContents*>(ApplicationContents::FromApplicationWindowHost(
          ApplicationWindowHost::FromID(app_process_id, app_window_id)));
  return app_contents ? app_contents->audio_stream_monitor() : nullptr;
}

}  // namespace

bool AudioStreamMonitor::StreamID::operator<(const StreamID& other) const {
  return std::tie(app_process_id, app_window_id, stream_id) <
         std::tie(other.app_process_id, other.app_window_id,
                  other.stream_id);
}

bool AudioStreamMonitor::StreamID::operator==(const StreamID& other) const {
  return std::tie(app_process_id, app_window_id, stream_id) ==
         std::tie(other.app_process_id, other.app_window_id,
                  other.stream_id);
}

AudioStreamMonitor::AudioStreamMonitor(ApplicationContents* contents)
    : ApplicationContentsObserver(contents),
      application_contents_(contents),
      clock_(base::DefaultTickClock::GetInstance()),
      indicator_is_on_(false),
      is_audible_(false) {
  DCHECK(application_contents_);

}

AudioStreamMonitor::~AudioStreamMonitor() {
  //DLOG(INFO) << "~AudioStreamMonitor: " << this;
}

bool AudioStreamMonitor::WasRecentlyAudible() const {
  DCHECK(thread_checker_.CalledOnValidThread());
  return indicator_is_on_;
}

bool AudioStreamMonitor::IsCurrentlyAudible() const {
  DCHECK(thread_checker_.CalledOnValidThread());
  return is_audible_;
}

void AudioStreamMonitor::ApplicationProcessGone(int app_process_id) {
  DCHECK(thread_checker_.CalledOnValidThread());

  // Note: It's possible for the RenderProcessHost and ApplicationContents (and thus
  // this class) to survive the death of the render process and subsequently be
  // reused. During this period GetMonitorForRenderFrame() will be unable to
  // lookup the ApplicationContents using the now-dead |app_window_id|. We must thus
  // have this secondary mechanism for clearing stale streams.
  // Streams must be removed locally before calling UpdateStreams() in order to
  // avoid removing streams from the process twice, since RenderProcessHost
  // removes the streams on its own when the renderer process is gone.
  base::EraseIf(streams_,
                [app_process_id](const std::pair<StreamID, bool>& entry) {
                  return entry.first.app_process_id == app_process_id;
                });
  UpdateStreams();
}

// static
void AudioStreamMonitor::StartMonitoringStream(int app_process_id,
                                               int app_window_id,
                                               int stream_id) {
  HostThread::PostTask(
      HostThread::UI, FROM_HERE,
      base::BindOnce(
          [](const StreamID& sid) {
            if (AudioStreamMonitor* monitor = GetMonitorForApplicationWindow(//GetMonitorForRenderFrame(
                    sid.app_process_id, sid.app_window_id)) {
              monitor->StartMonitoringStreamOnUIThread(sid);
            }
          },
          StreamID{app_process_id, app_window_id, stream_id}));
}

// static
void AudioStreamMonitor::StopMonitoringStream(int app_process_id,
                                              int app_window_id,
                                              int stream_id) {
  HostThread::PostTask(
      HostThread::UI, FROM_HERE,
      base::BindOnce(
          [](const StreamID& sid) {
            if (AudioStreamMonitor* monitor = GetMonitorForApplicationWindow(
                    sid.app_process_id, sid.app_window_id)) {
              monitor->StopMonitoringStreamOnUIThread(sid);
            }
          },
          StreamID{app_process_id, app_window_id, stream_id}));
}

// static
void AudioStreamMonitor::UpdateStreamAudibleState(int app_process_id,
                                                  int app_window_id,
                                                  int stream_id,
                                                  bool is_audible) {
  HostThread::PostTask(
      HostThread::UI, FROM_HERE,
      base::BindOnce(
          [](const StreamID& sid, bool is_audible) {
            if (AudioStreamMonitor* monitor = GetMonitorForApplicationWindow(
                    sid.app_process_id, sid.app_window_id)) {
              monitor->UpdateStreamAudibleStateOnUIThread(sid, is_audible);
            }
          },
          StreamID{app_process_id, app_window_id, stream_id}, is_audible));
}

void AudioStreamMonitor::StartMonitoringStreamOnUIThread(const StreamID& sid) {
  DCHECK(thread_checker_.CalledOnValidThread());
  DCHECK(streams_.find(sid) == streams_.end());
  streams_[sid] = false;
}

void AudioStreamMonitor::StopMonitoringStreamOnUIThread(const StreamID& sid) {
  DCHECK(thread_checker_.CalledOnValidThread());
  auto it = streams_.find(sid);
  if (it == streams_.end())
    return;

  // First set the state of stream to silent in order to correctly update the
  // frame state.
  streams_[sid] = false;
  UpdateStreams();
  streams_.erase(it);
}

void AudioStreamMonitor::UpdateStreamAudibleStateOnUIThread(const StreamID& sid,
                                                            bool is_audible) {
  DCHECK(thread_checker_.CalledOnValidThread());
  auto it = streams_.find(sid);
  if (it == streams_.end())
    return;

  it->second = is_audible;
  UpdateStreams();
}

void AudioStreamMonitor::UpdateStreams() {
  bool was_audible = is_audible_;
  is_audible_ = false;

  // Record whether or not a RenderFrameHost is audible.
  base::flat_map<ApplicationWindowHost*, bool> audible_frame_map;
  audible_frame_map.reserve(streams_.size());
  for (auto& kv : streams_) {
    const bool is_stream_audible = kv.second;
    is_audible_ |= is_stream_audible;

    // Record whether or not the RenderFrame is audible. A RenderFrame is
    // audible when it has at least one audio stream that is audible.
    auto* app_window_host = ApplicationWindowHost::FromID(//RenderFrameHost::FromID(
            kv.first.app_process_id, kv.first.app_window_id);
    // This may be nullptr in tests.
    if (!app_window_host)
      continue;
    audible_frame_map[app_window_host] |= is_stream_audible;
  }

  if (was_audible && !is_audible_)
    last_became_silent_time_ = clock_->NowTicks();

  // Update RenderFrameHost audible state only when state changed.
  for (auto& kv : audible_frame_map) {
    auto* app_window_host = kv.first;
    bool is_frame_audible = kv.second;
    if (is_frame_audible != app_window_host->is_audible())
      app_window_host->OnAudibleStateChanged(is_frame_audible);
  }

  if (is_audible_ != was_audible) {
    MaybeToggle();
    application_contents_->OnAudioStateChanged(is_audible_);
  }
}

void AudioStreamMonitor::MaybeToggle() {
  const base::TimeTicks off_time =
      last_became_silent_time_ +
      base::TimeDelta::FromMilliseconds(kHoldOnMilliseconds);
  const base::TimeTicks now = clock_->NowTicks();
  const bool should_stop_timer = is_audible_ || now >= off_time;
  const bool should_indicator_be_on = is_audible_ || !should_stop_timer;

  if (should_indicator_be_on != indicator_is_on_) {
    indicator_is_on_ = should_indicator_be_on;
    //application_contents_->NotifyNavigationStateChanged(INVALIDATE_TYPE_TAB);
  }

  if (should_stop_timer) {
    off_timer_.Stop();
  } else if (!off_timer_.IsRunning()) {
    off_timer_.Start(
        FROM_HERE,
        off_time - now,
        base::Bind(&AudioStreamMonitor::MaybeToggle, base::Unretained(this)));
  }
}

void AudioStreamMonitor::ApplicationWindowDeleted(ApplicationWindowHost* application_window_host) {
  int app_process_id = application_window_host->GetProcess()->GetID();
  int app_window_id = application_window_host->GetRoutingID();

  // It is possible for a frame to be deleted before notifications about its
  // streams are received. Explicitly clear these streams.
  base::EraseIf(streams_, [app_process_id, app_window_id](
                              const std::pair<StreamID, bool>& entry) {
    return entry.first.app_process_id == app_process_id &&
           entry.first.app_window_id == app_window_id;
  });
  UpdateStreams();
}

}  // namespace host
