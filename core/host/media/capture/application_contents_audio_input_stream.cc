// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/media/capture/application_contents_audio_input_stream.h"

#include <memory>
#include <string>

#include "base/bind.h"
#include "base/bind_helpers.h"
#include "base/logging.h"
#include "base/macros.h"
#include "base/threading/thread_checker.h"
#include "core/host/media/capture/audio_mirroring_manager.h"
#include "core/host/media/capture/application_contents_tracker.h"
#include "core/host/host_thread.h"
#include "core/host/media/desktop_media_id.h"
#include "core/host/application/application_window_host.h"
#include "core/host/application/application_contents.h"
#include "core/host/application/application_contents_media_capture_id.h"
#include "media/audio/virtual_audio_input_stream.h"
#include "media/audio/virtual_audio_output_stream.h"
#include "media/audio/virtual_audio_sink.h"
#include "media/base/bind_to_current_loop.h"

namespace host {

class ApplicationContentsAudioInputStream::Impl
    : public base::RefCountedThreadSafe<ApplicationContentsAudioInputStream::Impl>,
      public AudioMirroringManager::MirroringDestination {
 public:
  // Takes ownership of |mixer_stream|.  The rest outlive this instance.
  Impl(int render_process_id,
       int main_render_frame_id,
       AudioMirroringManager* mirroring_manager,
       const scoped_refptr<ApplicationContentsTracker>& tracker,
       media::VirtualAudioInputStream* mixer_stream,
       bool is_duplication);

  // Open underlying VirtualAudioInputStream and start tracker.
  bool Open();

  // Start the underlying VirtualAudioInputStream and instruct
  // AudioMirroringManager to begin a mirroring session.
  void Start(AudioInputCallback* callback);

  // Stop the underlying VirtualAudioInputStream and instruct
  // AudioMirroringManager to shutdown a mirroring session.
  void Stop();

  // Close the underlying VirtualAudioInputStream and stop the tracker.
  void Close();

  // Accessor to underlying VirtualAudioInputStream.
  media::VirtualAudioInputStream* mixer_stream() const {
    return mixer_stream_.get();
  }

 private:
  friend class base::RefCountedThreadSafe<ApplicationContentsAudioInputStream::Impl>;

  typedef AudioMirroringManager::SourceFrameRef SourceFrameRef;

  enum State {
    CONSTRUCTED,
    OPENED,
    MIRRORING,
    CLOSED
  };

  ~Impl() override;

  // Notifies the consumer callback that the stream is now dead.
  void ReportError();

  // (Re-)Start/Stop mirroring by posting a call to AudioMirroringManager on the
  // IO HostThread.
  void StartMirroring();
  void StopMirroring();

  // Increment/decrement the capturer count on the UI HostThread.
  void IncrementCapturerCount();
  void DecrementCapturerCount();

  // Invoked on the UI thread to make sure ApplicationContents muting is turned off for
  // successful audio capture.
  void UnmuteApplicationContentsAudio();

  // AudioMirroringManager::MirroringDestination implementation
  void QueryForMatches(const std::set<SourceFrameRef>& candidates,
                       const MatchesCallback& results_callback) override;
  void QueryForMatchesOnUIThread(const std::set<SourceFrameRef>& candidates,
                                 const MatchesCallback& results_callback);
  media::AudioOutputStream* AddInput(
      const media::AudioParameters& params) override;
  media::AudioPushSink* AddPushInput(
      const media::AudioParameters& params) override;

  // Callback which is run when |stream| is closed.  Deletes |stream|.
  void ReleaseInput(media::VirtualAudioOutputStream* stream);
  void ReleasePushInput(media::VirtualAudioSink* sink);

  // Called by ApplicationContentsTracker when the target of the audio mirroring has
  // changed.
  void OnTargetChanged(bool had_target);

  // Injected dependencies.
  const int initial_render_process_id_;
  const int initial_main_render_frame_id_;
  AudioMirroringManager* const mirroring_manager_;
  const scoped_refptr<ApplicationContentsTracker> tracker_;
  // The AudioInputStream implementation that handles the audio conversion and
  // mixing details.
  const std::unique_ptr<media::VirtualAudioInputStream> mixer_stream_;

  State state_;

  // Set to true if |tracker_| reports a NULL target, which indicates the target
  // is permanently lost.
  bool is_target_lost_;

  // Current callback used to consume the resulting mixed audio data.
  AudioInputCallback* callback_;

  // If true, this ApplicationContentsAudioInputStream will request a duplication of
  // audio data, instead of exclusive access to pull the audio data.
  bool is_duplication_;

  base::ThreadChecker thread_checker_;

  DISALLOW_COPY_AND_ASSIGN(Impl);
};

ApplicationContentsAudioInputStream::Impl::Impl(
    int render_process_id,
    int main_render_frame_id,
    AudioMirroringManager* mirroring_manager,
    const scoped_refptr<ApplicationContentsTracker>& tracker,
    media::VirtualAudioInputStream* mixer_stream,
    bool is_duplication)
    : initial_render_process_id_(render_process_id),
      initial_main_render_frame_id_(main_render_frame_id),
      mirroring_manager_(mirroring_manager),
      tracker_(tracker),
      mixer_stream_(mixer_stream),
      state_(CONSTRUCTED),
      is_target_lost_(false),
      callback_(nullptr),
      is_duplication_(is_duplication) {
  DCHECK(mirroring_manager_);
  DCHECK(tracker_);
  DCHECK(mixer_stream_);

  // WAIS::Impl can be constructed on any thread, but will DCHECK that all
  // its methods from here on are called from the same thread.
  thread_checker_.DetachFromThread();
}

ApplicationContentsAudioInputStream::Impl::~Impl() {
  DCHECK(state_ == CONSTRUCTED || state_ == CLOSED);
}

bool ApplicationContentsAudioInputStream::Impl::Open() {
  DCHECK(thread_checker_.CalledOnValidThread());
  DCHECK_EQ(CONSTRUCTED, state_) << "Illegal to Open more than once.";

  // For browser tests, not to start audio track to a fake tab.
  if (initial_render_process_id_ == DesktopMediaID::kFakeId &&
      initial_main_render_frame_id_ == DesktopMediaID::kFakeId)
    return true;

  if (!mixer_stream_->Open())
    return false;

  state_ = OPENED;
  tracker_->Start(
      initial_render_process_id_, initial_main_render_frame_id_,
      base::Bind(&Impl::OnTargetChanged, this));
  HostThread::PostTask(HostThread::UI, FROM_HERE,
                          base::BindOnce(&Impl::IncrementCapturerCount, this));

  return true;
}

void ApplicationContentsAudioInputStream::Impl::IncrementCapturerCount() {
  DCHECK_CURRENTLY_ON(HostThread::UI);

  if (ApplicationContents* contents = tracker_->application_contents())
    contents->IncrementCapturerCount(gfx::Size());
}

void ApplicationContentsAudioInputStream::Impl::Start(AudioInputCallback* callback) {
  DCHECK(thread_checker_.CalledOnValidThread());
  DCHECK(callback);

  if (state_ != OPENED)
    return;

  callback_ = callback;
  if (is_target_lost_) {
    ReportError();
    callback_ = nullptr;
    return;
  }

  state_ = MIRRORING;
  mixer_stream_->Start(callback);

  StartMirroring();

  // ApplicationContents audio muting is implemented as audio capture to nowhere.
  // Unmuting will stop that audio capture, allowing AudioMirroringManager to
  // divert audio capture to here.
  HostThread::PostTask(HostThread::UI, FROM_HERE,
                          base::BindOnce(&Impl::UnmuteApplicationContentsAudio, this));
}

void ApplicationContentsAudioInputStream::Impl::Stop() {
  DCHECK(thread_checker_.CalledOnValidThread());

  if (state_ != MIRRORING)
    return;

  state_ = OPENED;

  mixer_stream_->Stop();
  callback_ = nullptr;

  StopMirroring();
}

void ApplicationContentsAudioInputStream::Impl::Close() {
  DCHECK(thread_checker_.CalledOnValidThread());

  Stop();

  if (state_ == OPENED) {
    state_ = CONSTRUCTED;
    HostThread::PostTask(
        HostThread::UI, FROM_HERE,
        base::BindOnce(&Impl::DecrementCapturerCount, this));
    tracker_->Stop();
    mixer_stream_->Close();
  }

  DCHECK_EQ(CONSTRUCTED, state_);
  state_ = CLOSED;
}

void ApplicationContentsAudioInputStream::Impl::DecrementCapturerCount() {
  DCHECK_CURRENTLY_ON(HostThread::UI);

  if (ApplicationContents* contents = tracker_->application_contents())
    contents->DecrementCapturerCount();
}

void ApplicationContentsAudioInputStream::Impl::ReportError() {
  DCHECK(thread_checker_.CalledOnValidThread());

  callback_->OnError();
}

void ApplicationContentsAudioInputStream::Impl::StartMirroring() {
  DCHECK(thread_checker_.CalledOnValidThread());

  HostThread::PostTask(HostThread::IO, FROM_HERE,
                          base::BindOnce(&AudioMirroringManager::StartMirroring,
                                         base::Unretained(mirroring_manager_),
                                         base::RetainedRef(this)));
}

void ApplicationContentsAudioInputStream::Impl::StopMirroring() {
  DCHECK(thread_checker_.CalledOnValidThread());

  HostThread::PostTask(HostThread::IO, FROM_HERE,
                          base::BindOnce(&AudioMirroringManager::StopMirroring,
                                         base::Unretained(mirroring_manager_),
                                         base::RetainedRef(this)));
}

void ApplicationContentsAudioInputStream::Impl::UnmuteApplicationContentsAudio() {
  DCHECK_CURRENTLY_ON(HostThread::UI);

  ApplicationContents* const contents = tracker_->application_contents();
  if (contents)
    contents->SetAudioMuted(false);
}

void ApplicationContentsAudioInputStream::Impl::QueryForMatches(
    const std::set<SourceFrameRef>& candidates,
    const MatchesCallback& results_callback) {
  HostThread::PostTask(
      HostThread::UI, FROM_HERE,
      base::BindOnce(&Impl::QueryForMatchesOnUIThread, this, candidates,
                     media::BindToCurrentLoop(results_callback)));
}

void ApplicationContentsAudioInputStream::Impl::QueryForMatchesOnUIThread(
    const std::set<SourceFrameRef>& candidates,
    const MatchesCallback& results_callback) {
  DCHECK_CURRENTLY_ON(HostThread::UI);

  std::set<SourceFrameRef> matches;
  ApplicationContents* const contents = tracker_->application_contents();
  if (contents) {
    // Add each ID to |matches| if it maps to a RenderFrameHost that maps to the
    // currently-tracked ApplicationContents.
    for (std::set<SourceFrameRef>::const_iterator i = candidates.begin();
         i != candidates.end(); ++i) {
      ApplicationContents* const contents_containing_frame =
          //ApplicationContents::FromRenderFrameHost(
          //    RenderFrameHost::FromID(i->first, i->second));
       ApplicationContents::FromApplicationWindowHost(
        ApplicationWindowHost::FromID(i->first, i->second));
      if (contents_containing_frame == contents)
        matches.insert(*i);
    }
  }

  results_callback.Run(matches, is_duplication_);
}

media::AudioOutputStream* ApplicationContentsAudioInputStream::Impl::AddInput(
    const media::AudioParameters& params) {
  // Note: The closure created here holds a reference to "this," which will
  // guarantee the VirtualAudioInputStream (mixer_stream_) outlives the
  // VirtualAudioOutputStream.
  return new media::VirtualAudioOutputStream(
      params,
      mixer_stream_.get(),
      base::Bind(&Impl::ReleaseInput, this));
}

void ApplicationContentsAudioInputStream::Impl::ReleaseInput(
    media::VirtualAudioOutputStream* stream) {
  delete stream;
}

media::AudioPushSink* ApplicationContentsAudioInputStream::Impl::AddPushInput(
    const media::AudioParameters& params) {
  // Note: The closure created here holds a reference to "this," which will
  // guarantee the VirtualAudioInputStream (mixer_stream_) outlives the
  // VirtualAudioSink.
  return new media::VirtualAudioSink(params, mixer_stream_.get(),
                                     base::Bind(&Impl::ReleasePushInput, this));
}

void ApplicationContentsAudioInputStream::Impl::ReleasePushInput(
    media::VirtualAudioSink* stream) {
  delete stream;
}

void ApplicationContentsAudioInputStream::Impl::OnTargetChanged(bool had_target) {
  DCHECK(thread_checker_.CalledOnValidThread());

  is_target_lost_ = !had_target;

  if (state_ == MIRRORING) {
    if (is_target_lost_) {
      ReportError();
      Stop();
    } else {
      StartMirroring();
    }
  }
}

// static
ApplicationContentsAudioInputStream* ApplicationContentsAudioInputStream::Create(
    const std::string& device_id,
    const media::AudioParameters& params,
    const scoped_refptr<base::SingleThreadTaskRunner>& worker_task_runner,
    AudioMirroringManager* audio_mirroring_manager) {
  ApplicationContentsMediaCaptureId media_id;
  if (!ApplicationContentsMediaCaptureId::Parse(device_id, &media_id)) {
    return nullptr;
  }

  return new ApplicationContentsAudioInputStream(
      media_id.render_process_id, media_id.main_render_frame_id,
      audio_mirroring_manager, new ApplicationContentsTracker(false),
      new media::VirtualAudioInputStream(
          params, worker_task_runner,
          media::VirtualAudioInputStream::AfterCloseCallback()),
      !media_id.disable_local_echo);
}

ApplicationContentsAudioInputStream::ApplicationContentsAudioInputStream(
    int render_process_id,
    int main_render_frame_id,
    AudioMirroringManager* mirroring_manager,
    const scoped_refptr<ApplicationContentsTracker>& tracker,
    media::VirtualAudioInputStream* mixer_stream,
    bool is_duplication)
    : impl_(new Impl(render_process_id,
                     main_render_frame_id,
                     mirroring_manager,
                     tracker,
                     mixer_stream,
                     is_duplication)) {}

ApplicationContentsAudioInputStream::~ApplicationContentsAudioInputStream() {}

bool ApplicationContentsAudioInputStream::Open() {
  return impl_->Open();
}

void ApplicationContentsAudioInputStream::Start(AudioInputCallback* callback) {
  impl_->Start(callback);
}

void ApplicationContentsAudioInputStream::Stop() {
  impl_->Stop();
}

void ApplicationContentsAudioInputStream::Close() {
  impl_->Close();
  delete this;
}

double ApplicationContentsAudioInputStream::GetMaxVolume() {
  return impl_->mixer_stream()->GetMaxVolume();
}

void ApplicationContentsAudioInputStream::SetVolume(double volume) {
  impl_->mixer_stream()->SetVolume(volume);
}

double ApplicationContentsAudioInputStream::GetVolume() {
  return impl_->mixer_stream()->GetVolume();
}

bool ApplicationContentsAudioInputStream::SetAutomaticGainControl(bool enabled) {
  return impl_->mixer_stream()->SetAutomaticGainControl(enabled);
}

bool ApplicationContentsAudioInputStream::GetAutomaticGainControl() {
  return impl_->mixer_stream()->GetAutomaticGainControl();
}

bool ApplicationContentsAudioInputStream::IsMuted() {
  return false;
}

}  // namespace host
