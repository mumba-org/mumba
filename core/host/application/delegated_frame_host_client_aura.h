// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_APPLICATION_DELEGATED_FRAME_HOST_CLIENT_AURA_H_
#define MUMBA_HOST_APPLICATION_DELEGATED_FRAME_HOST_CLIENT_AURA_H_

#include "base/macros.h"
#include "core/host/application/compositor_resize_lock.h"
#include "core/host/application/delegated_frame_host.h"
#include "core/shared/common/content_export.h"

namespace host {

class ApplicationWindowHostViewAura;

// DelegatedFrameHostClient implementation for aura, not used in mus.
class CONTENT_EXPORT DelegatedFrameHostClientAura
    : public DelegatedFrameHostClient,
      public CompositorResizeLockClient {
 public:
  explicit DelegatedFrameHostClientAura(
      ApplicationWindowHostViewAura* application_window_host_view);
  ~DelegatedFrameHostClientAura() override;

 protected:
  ApplicationWindowHostViewAura* application_window_host_view() {
    return application_window_host_view_;
  }

  // DelegatedFrameHostClient implementation.
  ui::Layer* DelegatedFrameHostGetLayer() const override;
  bool DelegatedFrameHostIsVisible() const override;
  SkColor DelegatedFrameHostGetGutterColor() const override;
  bool DelegatedFrameCanCreateResizeLock() const override;
  std::unique_ptr<CompositorResizeLock> DelegatedFrameHostCreateResizeLock()
      override;
  void OnFirstSurfaceActivation(const viz::SurfaceInfo& surface_info) override;
  void OnBeginFrame(base::TimeTicks frame_time) override;
  bool IsAutoResizeEnabled() const override;
  void OnFrameTokenChanged(uint32_t frame_token) override;
  void DidReceiveFirstFrameAfterNavigation() override;

  // CompositorResizeLockClient implementation.
  std::unique_ptr<ui::CompositorLock> GetCompositorLock(
      ui::CompositorLockClient* client) override;
  void CompositorResizeLockEnded() override;

 private:
  ApplicationWindowHostViewAura* application_window_host_view_;

  DISALLOW_COPY_AND_ASSIGN(DelegatedFrameHostClientAura);
};

}  // namespace host

#endif  // MUMBA_HOST_APPLICATION_DELEGATED_FRAME_HOST_CLIENT_AURA_H_
