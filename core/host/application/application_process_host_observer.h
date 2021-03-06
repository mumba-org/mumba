// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_APPLICATION_APPLICATION_PROCESS_HOST_OBSERVER_H_
#define MUMBA_HOST_APPLICATION_APPLICATION_PROCESS_HOST_OBSERVER_H_

#include "base/process/kill.h"
#include "base/process/process_handle.h"
#include "core/shared/common/content_export.h"

namespace host {

class ApplicationProcessHost;
struct ChildProcessTerminationInfo;

// An observer API implemented by classes which are interested
// in RenderProcessHost lifecycle events.
class CONTENT_EXPORT ApplicationProcessHostObserver {
 public:
  // This method is invoked when the process was launched and the channel was
  // connected. This is the earliest time it is safe to call Shutdown on the
  // RenderProcessHost.
  virtual void ApplicationProcessReady(ApplicationProcessHost* host) {}

  // This method is invoked when the process when the process could shut down
  // but may or may not be allowed.
  virtual void ApplicationProcessShutdownRequested(ApplicationProcessHost* host) {}

  // This method is invoked when the process is going to exit and should not be
  // used for further navigations. Note that this is a COURTESY callback, not
  // guaranteed to be called for any particular process. Because this is the
  // first step in an orderly shutdown of a render process, do not expect that
  // a new render process will be hosted with this RenderProcessHost.
  virtual void ApplicationProcessWillExit(ApplicationProcessHost* host) {}

  // This method is invoked when the process of the observed RenderProcessHost
  // exits (either normally or with a crash). To determine if the process closed
  // normally or crashed, examine the |status| parameter.
  //
  // A new render process may be spawned for this RenderProcessHost, but there
  // are no guarantees (e.g. if shutdown is occurring, the HostDestroyed
  // callback will happen soon and that will be it, but if the renderer crashed
  // and the user clicks 'reload', a new render process will be spawned).
  //
  // This will cause a call to WebContentsObserver::RenderProcessGone() for the
  // active renderer process for the top-level frame; for code that needs to be
  // a WebContentsObserver anyway, consider whether that API might be a better
  // choice.
  virtual void ApplicationProcessExited(ApplicationProcessHost* host,
                                        const ChildProcessTerminationInfo& info) {}

  // This method is invoked when the observed RenderProcessHost itself is
  // destroyed. This is guaranteed to be the last call made to the observer, so
  // if the observer is tied to the observed RenderProcessHost, it is safe to
  // delete it.
  virtual void ApplicationProcessHostDestroyed(ApplicationProcessHost* host) {}

 protected:
  virtual ~ApplicationProcessHostObserver() {}
};

}  // namespace host

#endif  // CONTENT_PUBLIC_BROWSER_RENDER_PROCESS_HOST_OBSERVER_H_
