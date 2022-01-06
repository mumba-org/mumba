// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/domain/domain_thread_impl.h"

#include <string>
#include <utility>

#include "base/atomicops.h"
#include "base/bind.h"
#include "base/callback.h"
#include "base/compiler_specific.h"
#include "base/lazy_instance.h"
#include "base/logging.h"
#include "base/macros.h"
#include "base/sequence_checker.h"
#include "base/threading/platform_thread.h"
#include "base/threading/thread_checker.h"
#include "base/time/time.h"
#include "build/build_config.h"

namespace domain {

namespace {

// An implementation of SingleThreadTaskRunner to be used in conjunction
// with DomainThread.
// TODO(gab): Consider replacing this with |g_globals->task_runners| -- only
// works if none are requested before starting the threads.
class DomainThreadTaskRunner : public base::SingleThreadTaskRunner {
 public:
  explicit DomainThreadTaskRunner(DomainThread::ID identifier)
      : id_(identifier) {}

  // SingleThreadTaskRunner implementation.
  bool PostDelayedTask(const base::Location& from_here,
                       base::OnceClosure task,
                       base::TimeDelta delay) override {
    return DomainThread::PostDelayedTask(id_, from_here, std::move(task),
                                          delay);
  }

  bool PostNonNestableDelayedTask(const base::Location& from_here,
                                  base::OnceClosure task,
                                  base::TimeDelta delay) override {
    return DomainThread::PostNonNestableDelayedTask(id_, from_here,
                                                     std::move(task), delay);
  }

  bool RunsTasksInCurrentSequence() const override {
    return DomainThread::CurrentlyOn(id_);
  }

 protected:
  ~DomainThreadTaskRunner() override {}

 private:
  DomainThread::ID id_;
  DISALLOW_COPY_AND_ASSIGN(DomainThreadTaskRunner);
};

// A separate helper is used just for the task runners, in order to avoid
// needing to initialize the globals to create a task runner.
struct DomainThreadTaskRunners {
  DomainThreadTaskRunners() {
    for (int i = 0; i < DomainThread::ID_COUNT; ++i) {
      proxies[i] =
          new DomainThreadTaskRunner(static_cast<DomainThread::ID>(i));
    }
  }

  scoped_refptr<base::SingleThreadTaskRunner> proxies[DomainThread::ID_COUNT];
};

base::LazyInstance<DomainThreadTaskRunners>::Leaky g_task_runners =
    LAZY_INSTANCE_INITIALIZER;

// State of a given DomainThread::ID in chronological order throughout the
// browser process' lifetime.
enum DomainThreadState {
  // DomainThread::ID isn't associated with anything yet.
  UNINITIALIZED = 0,
  // DomainThread::ID is associated to a TaskRunner and is accepting tasks.
  RUNNING,
  // DomainThread::ID no longer accepts tasks (it's still associated to a
  // TaskRunner but that TaskRunner doesn't have to accept tasks).
  SHUTDOWN
};

struct DomainThreadGlobals {
  DomainThreadGlobals() {
    // A few unit tests which do not use a TestDomainThreadBundle still invoke
    // code that reaches into CurrentlyOn()/IsThreadInitialized(). This can
    // result in instantiating DomainThreadGlobals off the main thread.
    // |main_thread_checker_| being bound incorrectly would then result in a
    // flake in the next test that instantiates a TestDomainThreadBundle in the
    // same process. Detaching here postpones binding |main_thread_checker_| to
    // the first invocation of DomainThreadImpl::DomainThreadImpl() and works
    // around this issue.
    DETACH_FROM_THREAD(main_thread_checker_);
  }

  // DomainThreadGlobals must be initialized on main thread before it's used by
  // any other threads.
  THREAD_CHECKER(main_thread_checker_);

  // |task_runners[id]| is safe to access on |main_thread_checker_| as
  // well as on any thread once it's read-only after initialization
  // (i.e. while |states[id] >= RUNNING|).
  scoped_refptr<base::SingleThreadTaskRunner>
      task_runners[DomainThread::ID_COUNT];

  // Tracks the runtime state of DomainThreadImpls. Atomic because a few
  // methods below read this value outside |main_thread_checker_| to
  // confirm it's >= RUNNING and doing so requires an atomic read as it could be
  // in the middle of transitioning to SHUTDOWN (which the check is fine with
  // but reading a non-atomic value as it's written to by another thread can
  // result in undefined behaviour on some platforms).
  // Only NoBarrier atomic operations should be used on |states| as it shouldn't
  // be used to establish happens-after relationships but rather checking the
  // runtime state of various threads (once again: it's only atomic to support
  // reading while transitioning from RUNNING=>SHUTDOWN).
  base::subtle::Atomic32 states[DomainThread::ID_COUNT] = {};
};

base::LazyInstance<DomainThreadGlobals>::Leaky
    g_globals = LAZY_INSTANCE_INITIALIZER;

bool PostTaskHelper(DomainThread::ID identifier,
                    const base::Location& from_here,
                    base::OnceClosure task,
                    base::TimeDelta delay,
                    bool nestable) {
  DCHECK_GE(identifier, 0);
  DCHECK_LT(identifier, DomainThread::ID_COUNT);

  DomainThreadGlobals& globals = g_globals.Get();

  // Tasks should always be posted while the DomainThread is in a RUNNING or
  // SHUTDOWN state (will return false if SHUTDOWN).
  //
  // Posting tasks before DomainThreads are initialized is incorrect as it
  // would silently no-op. If you need to support posting early, gate it on
  // DomainThread::IsThreadInitialized(). If you hit this check in unittests,
  // you most likely posted a task outside the scope of a
  // TestDomainThreadBundle (which also completely resets the state after
  // shutdown in ~TestDomainThreadBundle(), ref. ResetGlobalsForTesting(),
  // making sure TestDomainThreadBundle is the first member of your test
  // fixture and thus outlives everything is usually the right solution).
  DCHECK_GE(base::subtle::NoBarrier_Load(&globals.states[identifier]),
            DomainThreadState::RUNNING);
  DCHECK(globals.task_runners[identifier]);

  if (nestable) {
    return globals.task_runners[identifier]->PostDelayedTask(
        from_here, std::move(task), delay);
  } else {
    return globals.task_runners[identifier]->PostNonNestableDelayedTask(
        from_here, std::move(task), delay);
  }
}

}  // namespace

DomainThreadImpl::DomainThreadImpl(
    ID identifier,
    scoped_refptr<base::SingleThreadTaskRunner> task_runner)
    : identifier_(identifier) {
  DCHECK_GE(identifier_, 0);
  DCHECK_LT(identifier_, ID_COUNT);
  DCHECK(task_runner);

  DomainThreadGlobals& globals = g_globals.Get();

  DCHECK_CALLED_ON_VALID_THREAD(globals.main_thread_checker_);

  DCHECK_EQ(base::subtle::NoBarrier_Load(&globals.states[identifier_]),
            DomainThreadState::UNINITIALIZED);
  base::subtle::NoBarrier_Store(&globals.states[identifier_],
                                DomainThreadState::RUNNING);

  DCHECK(!globals.task_runners[identifier_]);
  globals.task_runners[identifier_] = std::move(task_runner);
}

DomainThreadImpl::~DomainThreadImpl() {
  DomainThreadGlobals& globals = g_globals.Get();
  DCHECK_CALLED_ON_VALID_THREAD(globals.main_thread_checker_);

  DCHECK_EQ(base::subtle::NoBarrier_Load(&globals.states[identifier_]),
            DomainThreadState::RUNNING);
  base::subtle::NoBarrier_Store(&globals.states[identifier_],
                                DomainThreadState::SHUTDOWN);

  // The mapping is kept alive after shutdown to avoid requiring a lock only for
  // shutdown (the SingleThreadTaskRunner itself may stop accepting tasks at any
  // point -- usually soon before/after destroying the DomainThreadImpl).
  DCHECK(globals.task_runners[identifier_]);
}

// static
void DomainThreadImpl::ResetGlobalsForTesting(DomainThread::ID identifier) {
  DomainThreadGlobals& globals = g_globals.Get();
  DCHECK_CALLED_ON_VALID_THREAD(globals.main_thread_checker_);

  DCHECK_EQ(base::subtle::NoBarrier_Load(&globals.states[identifier]),
            DomainThreadState::SHUTDOWN);
  base::subtle::NoBarrier_Store(&globals.states[identifier],
                                DomainThreadState::UNINITIALIZED);

  globals.task_runners[identifier] = nullptr;
}

// static
const char* DomainThreadImpl::GetThreadName(DomainThread::ID thread) {
  static const char* const kDomainThreadNames[DomainThread::ID_COUNT] = {
      "",                 // UI (name assembled in browser_main_loop.cc).
      //"Mumba_IOThread",  // IO
  };

  //if (DomainThread::UI < thread && thread < DomainThread::ID_COUNT)
  //  return kDomainThreadNames[thread];
  if (thread == DomainThread::UI)
    return "Mumba_UIThread";
  return "Unknown Thread";
}

// static
void DomainThread::PostAfterStartupTask(
    const base::Location& from_here,
    const scoped_refptr<base::TaskRunner>& task_runner,
    base::OnceClosure task) {
  // GetContentClient()->browser()->PostAfterStartupTask(from_here, task_runner,
  //                                                     std::move(task));
}

// static
bool DomainThread::IsThreadInitialized(ID identifier) {
  DCHECK_GE(identifier, 0);
  DCHECK_LT(identifier, ID_COUNT);

  DomainThreadGlobals& globals = g_globals.Get();
  return base::subtle::NoBarrier_Load(&globals.states[identifier]) ==
         DomainThreadState::RUNNING;
}

// static
bool DomainThread::CurrentlyOn(ID identifier) {
  DCHECK_GE(identifier, 0);
  DCHECK_LT(identifier, ID_COUNT);

  DomainThreadGlobals& globals = g_globals.Get();

  // Thread-safe since |globals.task_runners| is read-only after being
  // initialized from main thread (which happens before //content and embedders
  // are kicked off and enabled to call the DomainThread API from other
  // threads).
  return globals.task_runners[identifier] &&
         globals.task_runners[identifier]->RunsTasksInCurrentSequence();
}

// static
std::string DomainThread::GetDCheckCurrentlyOnErrorMessage(ID expected) {
  std::string actual_name = base::PlatformThread::GetName();
  if (actual_name.empty())
    actual_name = "Unknown Thread";

  std::string result = "Must be called on ";
  result += DomainThreadImpl::GetThreadName(expected);
  result += "; actually called on ";
  result += actual_name;
  result += ".";
  return result;
}

bool DomainThread::PostTask(ID identifier,
                             const base::Location& from_here,
                             base::OnceClosure task) {
  return PostTaskHelper(identifier, from_here, std::move(task),
                        base::TimeDelta(), true);
}

// static
bool DomainThread::PostDelayedTask(ID identifier,
                                    const base::Location& from_here,
                                    base::OnceClosure task,
                                    base::TimeDelta delay) {
  return PostTaskHelper(identifier, from_here, std::move(task), delay, true);
}

// static
bool DomainThread::PostNonNestableTask(ID identifier,
                                        const base::Location& from_here,
                                        base::OnceClosure task) {
  return PostTaskHelper(identifier, from_here, std::move(task),
                        base::TimeDelta(), false);
}

// static
bool DomainThread::PostNonNestableDelayedTask(ID identifier,
                                               const base::Location& from_here,
                                               base::OnceClosure task,
                                               base::TimeDelta delay) {
  return PostTaskHelper(identifier, from_here, std::move(task), delay, false);
}

// static
bool DomainThread::PostTaskAndReply(ID identifier,
                                     const base::Location& from_here,
                                     base::OnceClosure task,
                                     base::OnceClosure reply) {
  return GetTaskRunnerForThread(identifier)
      ->PostTaskAndReply(from_here, std::move(task), std::move(reply));
}

// static
bool DomainThread::GetCurrentThreadIdentifier(ID* identifier) {
  DomainThreadGlobals& globals = g_globals.Get();

  // Thread-safe since |globals.task_runners| is read-only after being
  // initialized from main thread (which happens before //content and embedders
  // are kicked off and enabled to call the DomainThread API from other
  // threads).
  for (int i = 0; i < ID_COUNT; ++i) {
    if (globals.task_runners[i] &&
        globals.task_runners[i]->RunsTasksInCurrentSequence()) {
      *identifier = static_cast<ID>(i);
      return true;
    }
  }

  return false;
}

// static
scoped_refptr<base::SingleThreadTaskRunner>
DomainThread::GetTaskRunnerForThread(ID identifier) {
  return g_task_runners.Get().proxies[identifier];
}

}  // namespace domain
