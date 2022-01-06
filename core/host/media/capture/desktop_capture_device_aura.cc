// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/media/capture/desktop_capture_device_aura.h"

#include <utility>

#include "base/logging.h"
#include "base/memory/ptr_util.h"
#include "base/timer/timer.h"
#include "core/host/media/capture/aura_window_capture_machine.h"
#include "core/host/media/capture/desktop_capture_device_uma_types.h"
#include "core/host/host_thread.h"
#include "ui/aura/window.h"

namespace host {

namespace {

void SetCaptureSource(AuraWindowCaptureMachine* machine,
                      const DesktopMediaID& source) {
  DCHECK_CURRENTLY_ON(HostThread::UI);

  aura::Window* window = DesktopMediaID::GetAuraWindowById(source);
  if (window) {
    machine->SetWindow(window);
    if (source.type == DesktopMediaID::TYPE_SCREEN) {
      if (source.audio_share)
        IncrementDesktopCaptureCounter(SCREEN_CAPTURER_CREATED_WITH_AUDIO);
      else
        IncrementDesktopCaptureCounter(SCREEN_CAPTURER_CREATED_WITHOUT_AUDIO);
    }
  }
}

}  // namespace

DesktopCaptureDeviceAura::DesktopCaptureDeviceAura(
    const DesktopMediaID& source) {
  AuraWindowCaptureMachine* machine = new AuraWindowCaptureMachine();
  core_.reset(new media::ScreenCaptureDeviceCore(base::WrapUnique(machine)));
  // |core_| owns |machine| and deletes it on UI thread so passing the raw
  // pointer to the UI thread is safe here.
  HostThread::PostTask(HostThread::UI, FROM_HERE,
                          base::BindOnce(&SetCaptureSource, machine, source));
}

DesktopCaptureDeviceAura::~DesktopCaptureDeviceAura() {
  DVLOG(2) << "DesktopCaptureDeviceAura@" << this << " destroying.";
}

// static
std::unique_ptr<media::VideoCaptureDevice> DesktopCaptureDeviceAura::Create(
    const DesktopMediaID& source) {
  if (source.aura_id == DesktopMediaID::kNullId)
    return nullptr;
  return std::unique_ptr<media::VideoCaptureDevice>(
      new DesktopCaptureDeviceAura(source));
}

void DesktopCaptureDeviceAura::AllocateAndStart(
    const media::VideoCaptureParams& params,
    std::unique_ptr<Client> client) {
  DVLOG(1) << "Allocating " << params.requested_format.frame_size.ToString();
  core_->AllocateAndStart(params, std::move(client));
}

void DesktopCaptureDeviceAura::RequestRefreshFrame() {
  core_->RequestRefreshFrame();
}

void DesktopCaptureDeviceAura::StopAndDeAllocate() {
  core_->StopAndDeAllocate();
}

void DesktopCaptureDeviceAura::OnUtilizationReport(int frame_feedback_id,
                                                   double utilization) {
  core_->OnConsumerReportingUtilization(frame_feedback_id, utilization);
}

}  // namespace host
