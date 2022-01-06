// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/application/application_frame.h"

#include "core/host/application/application_window_host.h"
#include "core/host/application/application_window_host_view.h"
#include "core/host/application/application_process_host.h"

namespace host {

ApplicationFrame::ApplicationFrame(
  	base::WeakPtr<ApplicationWindowHost> application_window_host,
    int routing_id,
  	bool proxy,
  	bool live,
  	bool main_frame):
   routing_id_(routing_id),
   proxy_(proxy),
   live_(live),
   main_frame_(main_frame),
   application_window_host_(std::move(application_window_host)) {}

 ApplicationWindowHost* ApplicationFrame::GetWindow() const {
   return application_window_host_.get();
 }

 ApplicationWindowHostView* ApplicationFrame::GetView() const {
   return application_window_host_->GetView();
 }

 ApplicationProcessHost* ApplicationFrame::GetProcess() const {
   return application_window_host_->GetProcess();
 }

}