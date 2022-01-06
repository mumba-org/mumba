// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_APPLICATION_APPLICATION_FRAME_STATE_H_
#define MUMBA_HOST_APPLICATION_APPLICATION_FRAME_STATE_H_

#include "base/memory/weak_ptr.h"
#include "ui/gfx/geometry/size.h"

namespace host {
class ApplicationWindowHost;
class ApplicationWindowHostView;
class ApplicationProcessHost;
/*
 * Very simple structs just to keep the state about frames
 * loaded on the application process
 *
 * TODO: have a ApplicationState for ever instantiated application
 * and keep ApplicationContents, ApplicationWindowHost and
 * the tree of ApplicationFrameStates on the same instance
 *
 */

class ApplicationFrame {
public:
  ApplicationFrame(
  	base::WeakPtr<ApplicationWindowHost> application_window_host,
    int routing_id,
  	bool proxy,
  	bool live,
  	bool main_frame);

  ~ApplicationFrame() = default;

  int routing_id() const { return routing_id_; }
  gfx::Size size() const { return size_; }
  bool is_proxy() const { return proxy_; }
  bool is_live() const { return live_; }
  bool is_main_frame() const { return main_frame_; }
  ApplicationWindowHost* GetWindow() const;
  ApplicationWindowHostView* GetView() const;
  ApplicationProcessHost* GetProcess() const;

 private:
  int routing_id_;
  gfx::Size size_;
  bool proxy_;
  bool live_;
  bool main_frame_;
  base::WeakPtr<ApplicationWindowHost> application_window_host_;

  DISALLOW_COPY_AND_ASSIGN(ApplicationFrame);
};

}

#endif