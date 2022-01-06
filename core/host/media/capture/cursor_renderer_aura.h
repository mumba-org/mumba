// Copyright (c) 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_MEDIA_CAPTURE_CURSOR_RENDERER_AURA_H_
#define MUMBA_HOST_MEDIA_CAPTURE_CURSOR_RENDERER_AURA_H_

#include "core/host/media/capture/cursor_renderer.h"
#include "ui/aura/window.h"
#include "ui/events/event_handler.h"

namespace host {

class CONTENT_EXPORT CursorRendererAura : public CursorRenderer,
                                          public ui::EventHandler,
                                          public aura::WindowObserver {
 public:
  explicit CursorRendererAura(CursorDisplaySetting cursor_display);
  ~CursorRendererAura() final;

  // CursorRenderer implementation.
  void SetTargetView(gfx::NativeView window) final;
  bool IsCapturedViewActive() final;
  gfx::Size GetCapturedViewSize() final;
  gfx::Point GetCursorPositionInView() final;
  gfx::NativeCursor GetLastKnownCursor() final;
  SkBitmap GetLastKnownCursorImage(gfx::Point* hot_point) final;

  // ui::EventHandler overrides.
  void OnMouseEvent(ui::MouseEvent* event) final;

  // aura::WindowObserver overrides.
  void OnWindowDestroying(aura::Window* window) final;

 private:
  aura::Window* window_ = nullptr;

  DISALLOW_COPY_AND_ASSIGN(CursorRendererAura);
};

}  // namespace host

#endif  // MUMBA_HOST_MEDIA_CAPTURE_CURSOR_RENDERER_AURA_H_
