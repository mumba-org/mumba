// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/application/application.h"

#include "core/host/application/domain.h"
#include "core/host/application/application_contents.h"
#include "core/host/ui/dock.h"
#include "core/common/protocol/message_serialization.h"
#include "core/host/application/domain_automation_host.h"
#include "core/host/application/runnable_manager.h"

namespace host {

// static 
std::unique_ptr<Application> Application::New(
  RunnableManager* manager,
  Domain* domain, 
  int id, 
  const std::string& name, 
  const std::string& url, 
  const base::UUID& uuid,
  Dock::Type window_mode,
  gfx::Rect initial_bounds,
  WindowOpenDisposition window_open_disposition,
  bool fullscreen,
  bool headless) {
  return std::unique_ptr<Application>(new Application(
    manager,
    domain, 
    id, 
    name, 
    url, 
    uuid,
    window_mode,
    initial_bounds,
    window_open_disposition,
    fullscreen,
    headless));
}

// static 
std::unique_ptr<Application> Application::Deserialize(RunnableManager* manager, Domain* domain, net::IOBuffer* buffer, int size) {
  protocol::Application application_proto;
  protocol::CompoundBuffer cbuffer;
  cbuffer.Append(buffer, size);
  cbuffer.Lock();
  protocol::CompoundBufferInputStream stream(&cbuffer);
  
  if (!application_proto.ParseFromZeroCopyStream(&stream)) {
    return {};
  }
  return std::unique_ptr<Application>(new Application(manager, domain, std::move(application_proto)));
}

Application::Application(
  RunnableManager* manager,
  Domain* domain, 
  int id, 
  const std::string& name, 
  const std::string& url, 
  const base::UUID& uuid, 
  Dock::Type window_mode,
  gfx::Rect initial_bounds,
  WindowOpenDisposition window_open_disposition,
  bool fullscreen,
  bool headless):
   Runnable(
    manager, 
    domain, 
    id,
    name,
    url,
    uuid), 
 process_(nullptr),
 contents_(nullptr),
 dock_(nullptr),
 window_mode_(window_mode),
 initial_bounds_(initial_bounds),
 window_open_disposition_(window_open_disposition),
 fullscreen_(fullscreen),
 headless_(headless),
 weak_factory_(this) {

 application_client_ = new ApplicationDriver(this);

 proto()->set_fullscreen(fullscreen);
 proto()->set_headless(headless);
 proto()->set_window_mode(static_cast<protocol::WindowMode>(window_mode));
 proto()->set_window_open_disposition(static_cast<protocol::WindowOpenDisposition>(window_open_disposition));
 proto()->set_initial_bounds_x(initial_bounds.x());
 proto()->set_initial_bounds_y(initial_bounds.y());
 proto()->set_initial_bounds_width(initial_bounds.width());
 proto()->set_initial_bounds_height(initial_bounds.height());
}

Application::Application(
  RunnableManager* manager,
  Domain* domain, 
  int id, 
  const std::string& name, 
  const GURL& url, 
  const base::UUID& uuid, 
  Dock::Type window_mode,
  gfx::Rect initial_bounds,
  WindowOpenDisposition window_open_disposition,
  bool fullscreen,
  bool headless):
 Runnable(
  manager, 
  domain, 
  id,
  name,
  url.spec(),
  uuid), 
 process_(nullptr),
 contents_(nullptr),
 dock_(nullptr),
 window_mode_(window_mode),
 initial_bounds_(initial_bounds),
 window_open_disposition_(window_open_disposition),
 fullscreen_(fullscreen),
 headless_(headless),
 weak_factory_(this) {

 application_client_ = new ApplicationDriver(this);

 proto()->set_fullscreen(fullscreen);
 proto()->set_headless(headless);
 proto()->set_window_mode(static_cast<protocol::WindowMode>(window_mode));
 proto()->set_window_open_disposition(static_cast<protocol::WindowOpenDisposition>(window_open_disposition));
 proto()->set_initial_bounds_x(initial_bounds.x());
 proto()->set_initial_bounds_y(initial_bounds.y());
 proto()->set_initial_bounds_width(initial_bounds.width());
 proto()->set_initial_bounds_height(initial_bounds.height()); 
}

Application::Application(RunnableManager* manager, Domain* domain, protocol::Application application_proto):
 Runnable(manager, domain, std::move(application_proto)),
 process_(nullptr),
 headless_(false),
 weak_factory_(this) {
  application_client_ = new ApplicationDriver(this);
}

Application::~Application() {
  if (process_) {
    process_->RemoveObserver(this);
  }
}

void Application::set_contents(ApplicationContents* contents) {
  contents_ = contents;
  if (contents_) {
    contents_->AddObserver(GetWeakPtr());
  } //else {
    //contents_->RemoveObserver(this);
  //}
}

RunnableProcess* Application::process() const {
  return process_; 
}

void Application::OnRenderFrameMetadataChanged(const viz::CompositorFrameMetadata& last_frame_metadata) {
  SkColor background_color = last_frame_metadata.root_background_color;
  last_background_color_ = background_color;
  if (dock()) {
    int index = tab_index();
    dock()->tablist_model()->SetTablistThemeColor(background_color, index);
  }
}

int Application::tab_index() const {
  if (dock()) {
    return dock()->tablist_model()->GetIndexOfApplicationContents(contents());
  }
  return -1;
}

bool Application::is_ui_application() const {
  return dock() && contents();
}

void Application::TerminateNow() {
  if (!contents_) {
    return;
  }
  contents_->CloseNow();
}

void Application::ApplicationProcessReady(ApplicationProcessHost* process) {
  DCHECK(domain_);
  // bind clients

  domain_->automation_host()->BindClientInterfaces(rid(), domain_->process()->GetChannelProxy());
  
  application_driver()->BindInterfaces();
  domain_->OnApplicationLaunched(this);
}

void Application::ApplicationProcessShutdownRequested(ApplicationProcessHost* process) {
  DCHECK(domain_);
  domain_->OnApplicationShutdownRequested(this);
}

void Application::ApplicationProcessWillExit(ApplicationProcessHost* process) {
  DCHECK(domain_);
  domain_->OnApplicationWillExit(this);
}

void Application::ApplicationProcessExited(
  ApplicationProcessHost* process,
  const ChildProcessTerminationInfo& info) {
  domain_->OnApplicationProcessExited(this, process, info);
}

void Application::ApplicationProcessHostDestroyed(ApplicationProcessHost* process) {
  if (process) {
    process->RemoveObserver(this);
  }
  process_ = nullptr;
  domain_->OnApplicationProcessDestroyed(this, process);
}

void Application::DidInitializeApplicationContents() {
  domain_->OnApplicationInitialized(this);
}


}