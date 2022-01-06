// Copyright 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_APPLICATION_APPLICATION_INSTANCE_H_
#define MUMBA_DOMAIN_APPLICATION_APPLICATION_INSTANCE_H_

#include <string>

#include "base/macros.h"
#include "base/uuid.h"
#include "core/shared/common/content_export.h"
#include "core/shared/common/mojom/application.mojom.h"
#include "core/shared/domain/application/window_instance.h"

namespace domain {
class Application;
struct WindowInstance;

#if defined(OS_WIN)
enum class ApplicationState : int {
#else
enum CONTENT_EXPORT class ApplicationState : int {
#endif
  kNONE = 0,
  kRUNNING = 1,
  kKILLED = 2,
  kLAUNCH_ERROR = 3,
};

class CONTENT_EXPORT ApplicationInstance {
public:
  ApplicationInstance();
  ~ApplicationInstance();

  Application* application() const;
  void set_application(Application* application);
  WindowInstance* window() const;
  void set_window(WindowInstance* window);
  int id() const;
  void set_id(int id);
  const std::string& url() const;
  void set_url(const std::string& url);
  const base::UUID& uuid() const;
  void set_uuid(const base::UUID& uuid);
  ApplicationState state() const;
  void set_state(ApplicationState state);
  WindowMode window_mode() const { return window_mode_; }
  const gfx::Rect& initial_bounds() const { return initial_bounds_; }
  ui::mojom::WindowOpenDisposition window_open_disposition() const { return window_open_disposition_; }
  bool fullscreen() const { return fullscreen_; }
  bool headless() const { return headless_; }

  void set_window_mode(WindowMode mode) { window_mode_ = mode; }
  void set_initial_bounds(const gfx::Rect& bounds) { initial_bounds_ = bounds; }
  void set_window_open_disposition(ui::mojom::WindowOpenDisposition disposition) { window_open_disposition_ = disposition; }
  void set_fullscreen(bool fullscreen) { fullscreen_ = fullscreen; }
  void set_headless(bool headless) { headless_ = headless; }
  
private:

  Application* application_ = nullptr;
  WindowInstance* window_ = nullptr;
  int id_ = -1;
  std::string url_;
  base::UUID uuid_;
  ApplicationState state_ = ApplicationState::kNONE;
  WindowMode window_mode_;
  gfx::Rect initial_bounds_;
  ui::mojom::WindowOpenDisposition window_open_disposition_;
  bool fullscreen_;
  bool headless_;

 DISALLOW_COPY_AND_ASSIGN(ApplicationInstance);
};

}

#endif