// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_DOMAIN_THREAD_IMPL_H_
#define MUMBA_DOMAIN_DOMAIN_THREAD_IMPL_H_

#include "base/memory/scoped_refptr.h"
#include "base/single_thread_task_runner.h"
#include "core/shared/common/content_export.h"
#include "core/domain/domain_thread.h"

namespace domain {
class DomainMainThread;
//class DomainMainLoop;
//class DomainProcessSubThread;
//class TestDomainThread;

// DomainThreadImpl is a scoped object which maps a SingleThreadTaskRunner to a
// DomainThread::ID. On ~DomainThreadImpl() that ID enters a SHUTDOWN state
// (in which DomainThread::IsThreadInitialized() returns false) but the mapping
// isn't undone to avoid shutdown races (the task runner is free to stop
// accepting tasks by then however).
//
// Very few users should use this directly. To mock DomainThreads, tests should
// use TestDomainThreadBundle instead.
class CONTENT_EXPORT DomainThreadImpl : public DomainThread {
 public:
  ~DomainThreadImpl();

  // Returns the thread name for |identifier|.
  static const char* GetThreadName(DomainThread::ID identifier);

  // Resets globals for |identifier|. Used in tests to clear global state that
  // would otherwise leak to the next test. Globals are not otherwise fully
  // cleaned up in ~DomainThreadImpl() as there are subtle differences between
  // UNINITIALIZED and SHUTDOWN state (e.g. globals.task_runners are kept around
  // on shutdown). Must be called after ~DomainThreadImpl() for the given
  // |identifier|.
  static void ResetGlobalsForTesting(DomainThread::ID identifier);

 private:
  // Restrict instantiation to DomainProcessSubThread as it performs important
  // initialization that shouldn't be bypassed (except by DomainMainLoop for
  // the main thread).
  //friend class DomainProcessSubThread;
  friend class DomainMainThread;
  // TestDomainThread is also allowed to construct this when instantiating fake
  // threads.
  //friend class TestDomainThread;

  // Binds |identifier| to |task_runner| for the browser_thread.h API. This
  // needs to happen on the main thread before //content and embedders are
  // kicked off and enabled to invoke the DomainThread API from other threads.
  DomainThreadImpl(DomainThread::ID identifier,
                    scoped_refptr<base::SingleThreadTaskRunner> task_runner);

  // The identifier of this thread.  Only one thread can exist with a given
  // identifier at a given time.
  ID identifier_;
};

}  // namespace domain

#endif  // MUMBA_DOMAIN_DOMAIN_THREAD_IMPL_H_
