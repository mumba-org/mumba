// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/domain/domain_thread.h"

#include <string>
#include "base/atomicops.h"
#include "base/bind.h"
#include "base/compiler_specific.h"
#include "base/lazy_instance.h"
#include "base/single_thread_task_runner.h"
#include "base/threading/thread_restrictions.h"
#include "core/shared/common/client.h"
#include "core/domain/domain_thread_delegate.h"
#include "net/disk_cache/simple/simple_backend_impl.h"
#if defined(OS_ANDROID)
#include "base/android/jni_android.h"
#endif

namespace domain {
 
namespace {
 // Friendly names for the well-known threads.
 static const char* g_engine_thread_names[DomainThread::MAX] = {
   "",  // UI (name assembled in engine_main.cc).
   //"Host_DBThread",  // DB
   //"Host_FileThread",  // FILE
  };

 // An implementation of SingleThreadTaskRunner to be used in conjunction
 // with DomainThread.
 class DomainThreadTaskRunner : public base::SingleThreadTaskRunner {
 public:
  explicit DomainThreadTaskRunner(DomainThread::ID identifier)
    : id_(identifier) {}
  
  // SingleThreadTaskRunner implementation.
  bool PostDelayedTask(
   const base::Location& from_here,
   base::OnceClosure task,
   base::TimeDelta delay) override {
  
   return DomainThread::PostDelayedTask(id_, from_here, std::move(task), delay);
  
  }

  bool PostNonNestableDelayedTask(
   const base::Location& from_here,
   base::OnceClosure task,
   base::TimeDelta delay) override {
   
   return DomainThread::PostNonNestableDelayedTask(id_, from_here, std::move(task),
     delay);
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
   for (int i = 0; i < DomainThread::MAX; ++i) {
     proxies[i] =
      new DomainThreadTaskRunner(static_cast<DomainThread::ID>(i));
   }
  }
  
  scoped_refptr<base::SingleThreadTaskRunner> proxies[DomainThread::MAX];
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
     DETACH_FROM_THREAD(main_thread_checker_);
     memset(thread_delegates, 0,
     DomainThread::MAX * sizeof(thread_delegates[0]));
  }
  // DomainThreadGlobals must be initialized on main thread before it's used by
  // any other threads.
  THREAD_CHECKER(main_thread_checker_);
  // This lock protects |threads|. Do not read or modify that array
  // without holding this lock. Do not block while holding this lock.
  base::Lock lock;
   
  // |task_runners[id]| is safe to access on |main_thread_checker_| as
  // well as on any thread once it's read-only after initialization
  // (i.e. while |states[id] >= RUNNING|).
  scoped_refptr<base::SingleThreadTaskRunner>
      task_runners[DomainThread::MAX];

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
  base::subtle::Atomic32 states[DomainThread::MAX] = {};
  // Only atomic operations are used on this array. The delegates are not owned
  // by this array, rather by whoever calls DomainThread::SetDelegate.
  DomainThreadDelegate* thread_delegates[DomainThread::MAX];
 };

 base::LazyInstance<DomainThreadGlobals>::Leaky
   g_globals = LAZY_INSTANCE_INITIALIZER;

bool PostTaskHelper(DomainThread::ID identifier,
                    const base::Location& from_here,
                    base::OnceClosure task,
                    base::TimeDelta delay,
                    bool nestable) {
  DCHECK_GE(identifier, 0);
  DCHECK_LT(identifier, DomainThread::MAX);

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

DomainThread::DomainThread(ID identifier,
                         scoped_refptr<base::SingleThreadTaskRunner> task_runner)
 : Thread(DomainThread::GetThreadName(identifier)),
   identifier_(identifier),
   initialized_(false) {
 
  Initialize(std::move(task_runner));
}

// DomainThread::DomainThread(ID identifier): 
//     Thread(DomainThread::GetThreadName(identifier)),
//     identifier_(identifier),
//     initialized_(false) {
//   //Initialize(task_runner());
// }

// static
// void DomainThread::ShutdownThreadNamespace() {
//  // The goal is to make it impossible for switch to 'infinite loop' during
//  // shutdown, but to reasonably expect that all BLOCKING_SHUTDOWN tasks queued
//  // during shutdown get run. There's nothing particularly scientific about the
//  // number chosen.
//  const int kMaxNewShutdownBlockingTasks = 1000;
//  DomainThreadGlobals& globals = g_globals.Get();
//  globals.blocking_namespace->Shutdown(kMaxNewShutdownBlockingTasks);
// }

// void DomainThread::Initialize() {
//   DomainThreadGlobals& globals = g_globals.Get();

//   DCHECK_CALLED_ON_VALID_THREAD(globals.main_thread_checker_);

//   DCHECK_EQ(base::subtle::NoBarrier_Load(&globals.states[identifier_]),
//             DomainThreadState::UNINITIALIZED);
//   base::subtle::NoBarrier_Store(&globals.states[identifier_],
//                                 DomainThreadState::RUNNING);

//   DCHECK(!globals.task_runners[identifier_]);
//   globals.task_runners[identifier_] = task_runner();
//   initialized_ = true;
// }

void DomainThread::Initialize(scoped_refptr<base::SingleThreadTaskRunner> task_runner) {
  DCHECK_GE(identifier_, 0);
  DCHECK_LT(identifier_, MAX);
  DCHECK(task_runner);

  DomainThreadGlobals& globals = g_globals.Get();

  DCHECK_CALLED_ON_VALID_THREAD(globals.main_thread_checker_);

  DCHECK_EQ(base::subtle::NoBarrier_Load(&globals.states[identifier_]),
            DomainThreadState::UNINITIALIZED);
  base::subtle::NoBarrier_Store(&globals.states[identifier_],
                                DomainThreadState::RUNNING);

  DCHECK(!globals.task_runners[identifier_]);
  globals.task_runners[identifier_] = std::move(task_runner);
  initialized_ = true;
}

void DomainThread::Init() {
 DomainThreadGlobals& globals = g_globals.Get();
 using base::subtle::AtomicWord;
 AtomicWord* storage =
  reinterpret_cast<AtomicWord*>(&globals.thread_delegates[identifier_]);
 AtomicWord stored_pointer = base::subtle::NoBarrier_Load(storage);
 DomainThreadDelegate* delegate =
  reinterpret_cast<DomainThreadDelegate*>(stored_pointer);
 if (delegate)
  delegate->Init();
}
// We disable optimizations for this block of functions so the compiler doesn't
// merge them all together.
MSVC_DISABLE_OPTIMIZE()
MSVC_PUSH_DISABLE_WARNING(4748)

NOINLINE void DomainThread::UIThreadRun(base::RunLoop* run_loop) {
 volatile int line_number = __LINE__;
 Thread::Run(run_loop);
 CHECK_GT(line_number, 0);
}

// NOINLINE void DomainThread::DBThreadRun(base::RunLoop* run_loop) {
//  volatile int line_number = __LINE__;
//  Thread::Run(run_loop);
//  CHECK_GT(line_number, 0);
// }

// NOINLINE void DomainThread::FileThreadRun(base::RunLoop* run_loop) {
//  volatile int line_number = __LINE__;
//  Thread::Run(run_loop);
//  CHECK_GT(line_number, 0);
// }

MSVC_POP_WARNING()
MSVC_ENABLE_OPTIMIZE();

void DomainThread::Run(base::RunLoop* run_loop) {
#if defined(OS_ANDROID)
 // Not to reset thread name to "Thread-???" by VM, attach VM with thread name.
 // Though it may create unnecessary VM thread objects, keeping thread name
 // gives more benefit in debugging in the platform.
 if (!thread_name().empty()) {
  base::android::AttachCurrentThreadWithName(thread_name());
 }
#endif
 DomainThread::ID thread_id = MAX;
 if (!GetCurrentThreadIdentifier(&thread_id))
  return Thread::Run(run_loop);
 switch (thread_id) {
 case DomainThread::UI:
  return UIThreadRun(run_loop);
 // case DomainThread::DB:
 //  return DBThreadRun(run_loop);
 // case DomainThread::FILE:
 //  return FileThreadRun(run_loop); 
 case DomainThread::MAX:
  CHECK(false);  // This shouldn't actually be reached!
  break;
 }
 Thread::Run(run_loop);
}

void DomainThread::CleanUp() {
 DomainThreadGlobals& globals = g_globals.Get();
 using base::subtle::AtomicWord;
 AtomicWord* storage =
  reinterpret_cast<AtomicWord*>(&globals.thread_delegates[identifier_]);
 AtomicWord stored_pointer = base::subtle::NoBarrier_Load(storage);
 DomainThreadDelegate* delegate =
  reinterpret_cast<DomainThreadDelegate*>(stored_pointer);
 if (delegate)
  delegate->CleanUp();
}

bool DomainThread::StartWithOptions(const Options& options) {
 // The global thread table needs to be locked while a new thread is
 // starting, as the new thread can asynchronously start touching the
 // table (and other thread's message_loop).
 DomainThreadGlobals& globals = g_globals.Get();
 base::AutoLock lock(globals.lock);
 bool started = Thread::StartWithOptions(options);
 if (started && !initialized_) {
  Initialize();
 }
 return started;
}

DomainThread::~DomainThread() {
  Stop();
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

// bool DomainThread::StartWithOptions(const Options& options) {
//  // The global thread table needs to be locked while a new thread is
//  // starting, as the new thread can asynchronously start touching the
//  // table (and other thread's message_loop).
//  DomainThreadGlobals& globals = g_globals.Get();
//  base::AutoLock lock(globals.lock);
//  return Thread::StartWithOptions(options);
// }

// static
// bool DomainThread::PostTaskHelper(
//  DomainThread::ID identifier,
//  const base::Location& from_here,
//  base::OnceClosure task,
//  base::TimeDelta delay,
//  bool nestable) {
//  DCHECK(identifier >= 0 && identifier < MAX);
//  // Optimization: to avoid unnecessary locks, we listed the ID enumeration in
//  // order of lifetime.  So no need to lock if we know that the target thread
//  // outlives current thread.
//  // Note: since the array is so small, ok to loop instead of creating a map,
//  // which would require a lock because std::map isn't thread safe, defeating
//  // the whole purpose of this optimization.
//  DomainThread::ID current_thread = MAX;
//  bool target_thread_outlives_current =
//   GetCurrentThreadIdentifier(&current_thread) &&
//   current_thread >= identifier;
//  DomainThreadGlobals& globals = g_globals.Get();
//  if (!target_thread_outlives_current)
//   globals.lock.Acquire();
//  base::MessageLoop* message_loop =
//   globals.threads[identifier] ? globals.threads[identifier]->message_loop()
//   : NULL;
//  if (message_loop) {
//   if (nestable) {
//    message_loop->task_runner()->PostDelayedTask(from_here, std::move(task), delay);
//   }
//   else {
//    message_loop->task_runner()->PostNonNestableDelayedTask(from_here, std::move(task),
//     delay);
//   }
//  }
//  if (!target_thread_outlives_current)
//   globals.lock.Release();
//  return !!message_loop;
// }

// static
// bool DomainThread::PostBlockingNamespaceTask(
//  const base::Location& from_here,
//  const base::Closure& task) {
//  return g_globals.Get().blocking_namespace->PostWorkerTask(from_here, task);
// }

// // static
// bool DomainThread::PostBlockingNamespaceTaskAndReply(
//  const base::Location& from_here,
//  const base::Closure& task,
//  const base::Closure& reply) {
//  return g_globals.Get().blocking_namespace->PostTaskAndReply(
//   from_here, task, reply);
// }

// // static
// bool DomainThread::PostBlockingNamespaceSequencedTask(
//  const std::string& sequence_token_name,
//  const base::Location& from_here,
//  const base::Closure& task) {
//  return g_globals.Get().blocking_namespace->PostNamedSequencedWorkerTask(
//   sequence_token_name, from_here, task);
// }

// static
void DomainThread::PostAfterStartupTask(
 const base::Location& from_here,
 const scoped_refptr<base::TaskRunner>& task_runner,
 base::OnceClosure task) {
 
 printf(not implemented";
//  common::GetClient()->shell()->PostAfterStartupTask(from_here, task_runner,
//   std::move(task));
}

// static
// base::SequencedWorkerNamespace* DomainThread::GetBlockingNamespace() {
//  return g_globals.Get().blocking_namespace.get();
// }

// static
bool DomainThread::IsThreadInitialized(ID identifier) {
 DCHECK_GE(identifier, 0);
 DCHECK_LT(identifier, MAX);

 DomainThreadGlobals& globals = g_globals.Get();
  return base::subtle::NoBarrier_Load(&globals.states[identifier]) ==
         DomainThreadState::RUNNING;
}

// static
bool DomainThread::CurrentlyOn(ID identifier) {
  DCHECK_GE(identifier, 0);
  DCHECK_LT(identifier, MAX);

  DomainThreadGlobals& globals = g_globals.Get();

  // Thread-safe since |globals.task_runners| is read-only after being
  // initialized from main thread (which happens before //content and embedders
  // are kicked off and enabled to call the DomainThread API from other
  // threads).
  return globals.task_runners[identifier] &&
         globals.task_runners[identifier]->RunsTasksInCurrentSequence();
}

const char* DomainThread::GetThreadName(DomainThread::ID thread) {
 if (DomainThread::UI < thread && thread < DomainThread::MAX)
  return g_engine_thread_names[thread];
 if (thread == DomainThread::UI)
  return "Domain_UIThread";
 return "Unknown Thread";
}

// static
std::string DomainThread::GetDCheckCurrentlyOnErrorMessage(ID expected) {
std::string actual_name = base::PlatformThread::GetName();
  if (actual_name.empty())
    actual_name = "Unknown Thread";

  std::string result = "Must be called on ";
  result += DomainThread::GetThreadName(expected);
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
  for (int i = 0; i < MAX; ++i) {
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
DomainThread::GetMessageLoopProxyForThread(ID identifier) {
 return g_task_runners.Get().proxies[identifier];
}

// static
void DomainThread::SetDelegate(ID identifier,
 DomainThreadDelegate* delegate) {
 using base::subtle::AtomicWord;
 DomainThreadGlobals& globals = g_globals.Get();
 AtomicWord* storage = reinterpret_cast<AtomicWord*>(
  &globals.thread_delegates[identifier]);
 AtomicWord old_pointer = base::subtle::NoBarrier_AtomicExchange(
  storage, reinterpret_cast<AtomicWord>(delegate));
 // This catches registration when previously registered.
 DCHECK(!delegate || !old_pointer);
}

scoped_refptr<base::SingleThreadTaskRunner> DomainThread::GetTaskRunnerForThread(ID identifier) {
  return g_task_runners.Get().proxies[identifier];
}

}
