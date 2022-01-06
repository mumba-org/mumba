// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_APPLICATION_APPLICATION_H_
#define MUMBA_HOST_APPLICATION_APPLICATION_H_

#include <string>

#include "base/macros.h"
#include "base/memory/weak_ptr.h"
#include "base/uuid.h"
#include "core/host/application/runnable.h"
#include "core/host/application/application_process_host.h"
#include "core/host/application/application_contents_observer.h"
#include "core/host/application/application_process_host_observer.h"
#include "core/host/application/automation/application_driver.h"
#include "core/host/ui/dock.h"
#include "core/host/host_thread.h"
#include "core/common/proto/objects.pb.h"
#include "ui/base/window_open_disposition.h"

namespace host {
class Domain;
class ApplicationContents;
class ApplicationDriver;
class Dock;
class RunnableManager;

class Application : public Runnable,
                    public ApplicationProcessHostObserver,
                    public ApplicationContentsObserver {
public:
  static std::unique_ptr<Application> New(
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
    bool headless);

  static std::unique_ptr<Application> Deserialize(
    RunnableManager* manager, 
    Domain* domain, 
    net::IOBuffer* buffer, 
    int size);

  Application(
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
    bool headless);
  
  Application(
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
    bool headless);

  ~Application() override;

  // Runnable
  RunnableType type() const override {
    return RunnableType::APPLICATION;
  }

  RunnableProcess* process() const override;
  void TerminateNow() override;

  // a client mostly for the automation api
  const scoped_refptr<ApplicationDriver>& application_driver() const {
    return application_client_;
  }

  const GURL& initial_url() const {
    return initial_url_;
  }

  void set_initial_url(const GURL& initial_url) {
    initial_url_ = initial_url;
  }

  // it may have associated contents if its a 'ui' application
  ApplicationContents* contents() const {
    return contents_;
  }

  void set_contents(ApplicationContents* contents);

  Dock* dock() const {
    return dock_;
  }

  void set_dock(Dock* dock) {
    dock_ = dock;
  }

  SkColor last_background_color() const {
    return last_background_color_;
  }

  bool headless() const {
    return headless_;
  }

  Dock::Type window_mode() {
    return window_mode_;
  }
  
  gfx::Rect initial_bounds() {
    return initial_bounds_;
  }
  
  WindowOpenDisposition window_open_disposition() const {
    return window_open_disposition_;
  }
  
  // FIXME: this should follow on/off state machine of fullscreen
  //        and not just keep the initial fullscreen state
  bool fullscreen() const {
    return fullscreen_;
  }

  void AttachProcess(ApplicationProcessHost* process) {
    process_ = process;
    process_->AddObserver(this);
  }

  void DetachProcess(ApplicationProcessHost* process) {
    process->RemoveObserver(this);
    process_ = nullptr;
  }

  int tab_index() const;

  bool is_ui_application() const;

  base::WeakPtr<Application> GetWeakPtr() {
    return weak_factory_.GetWeakPtr();
  }

  void OnRenderFrameMetadataChanged(const viz::CompositorFrameMetadata& last_frame_metadata);
  
private:
  friend class Domain;

  Application(RunnableManager* manager, Domain* domain, protocol::Application application_proto);
  
  // Observer
  void ApplicationProcessReady(ApplicationProcessHost* process) override;
  void ApplicationProcessShutdownRequested(ApplicationProcessHost* process) override;
  void ApplicationProcessWillExit(ApplicationProcessHost* process) override;
  void ApplicationProcessExited(ApplicationProcessHost* process,
                                const ChildProcessTerminationInfo& info) override;
  void ApplicationProcessHostDestroyed(ApplicationProcessHost* process) override;

  // ContentsObserver

  void DidInitializeApplicationContents() override;

  scoped_refptr<ApplicationDriver> application_client_;
  //std::unique_ptr<ApplicationDriver, HostThread::DeleteOnIOThread> application_client_;
  //std::string name_;
  ApplicationProcessHost* process_;
  ApplicationContents* contents_;
  Dock* dock_;
  SkColor last_background_color_;

  GURL initial_url_;
  
  // carefull: once theres a public setter for those
  //           the equivalent proto variable must be set
  Dock::Type window_mode_;
  gfx::Rect initial_bounds_;
  WindowOpenDisposition window_open_disposition_;
  bool fullscreen_;
  bool headless_;

  base::WeakPtrFactory<Application> weak_factory_;
  
  DISALLOW_COPY_AND_ASSIGN(Application);
};

}

#endif
