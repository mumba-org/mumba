// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_PUBLIC_BROWSER_BROWSER_CHILD_PROCESS_OBSERVER_H_
#define CONTENT_PUBLIC_BROWSER_BROWSER_CHILD_PROCESS_OBSERVER_H_

#include "core/shared/common/content_export.h"

namespace host {

struct ChildProcessData;
struct ChildProcessTerminationInfo;

// An observer API implemented by classes which are interested in host child
// process events. Note that render processes cannot be observed through this
// interface; use RenderProcessHostObserver instead.
class CONTENT_EXPORT HostChildProcessObserver {
 public:
  // Called when a child process host has connected to a child process.
  // Note that |data.handle| may be invalid, if the child process connects to
  // the pipe before the process launcher's reply arrives.
  virtual void HostChildProcessHostConnected(const ChildProcessData& data) {}

  // Called when a child process has successfully launched and has connected to
  // it child process host. The |data.handle| is guaranteed to be valid.
  virtual void HostChildProcessLaunchedAndConnected(
      const ChildProcessData& data) {}

  // Called after a ChildProcessHost is disconnected from the child process.
  virtual void HostChildProcessHostDisconnected(
      const ChildProcessData& data) {}

  // Called when a child process disappears unexpectedly as a result of a crash.
  virtual void HostChildProcessCrashed(
      const ChildProcessData& data,
      const ChildProcessTerminationInfo& info) {}

  // Called when a child process disappears unexpectedly as a result of being
  // killed.
  virtual void HostChildProcessKilled(
      const ChildProcessData& data,
      const ChildProcessTerminationInfo& info) {}

 protected:
  // The observer can be destroyed on any thread.
  virtual ~HostChildProcessObserver() {}

  static void Add(HostChildProcessObserver* observer);
  static void Remove(HostChildProcessObserver* observer);
};

}  // namespace host

#endif  // CONTENT_PUBLIC_BROWSER_BROWSER_CHILD_PROCESS_OBSERVER_H_
