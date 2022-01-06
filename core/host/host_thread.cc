// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/host_thread.h"

#include <string>
#include "base/atomicops.h"
#include "base/bind.h"
#include "base/compiler_specific.h"
#include "base/lazy_instance.h"
#include "base/single_thread_task_runner.h"
#include "base/threading/thread_restrictions.h"
#include "core/shared/common/client.h"
#include "core/host/host_thread_delegate.h"
#include "core/host/host_client.h"
#include "net/disk_cache/simple/simple_backend_impl.h"
#if defined(OS_ANDROID)
#include "base/android/jni_android.h"
#endif

namespace host {
 
namespace {
 // Friendly names for the well-known threads.
 static const char* g_engine_thread_names[HostThread::MAX] = {
   "",  // UI (name assembled in engine_main.cc).
   "Host_ProcessLauncherThread",  // PROCESS LAUNCHER
   //"Host_FileThread",  // FILE
   //"Host_DBThread",  // DB
   //"Host_RpcThread",  // Rpc
   //"Host_DispatcherThread",  // DISPATCHER
   //"Host_NotificationThread",  // DAEMON
   "Host_IOThread",  // IO 
   //"Host_WatchdogThread",  // DHT
  };

 // An implementation of SingleThreadTaskRunner to be used in conjunction
 // with HostThread.
 class HostThreadTaskRunner : public base::SingleThreadTaskRunner {
 public:
  explicit HostThreadTaskRunner(HostThread::ID identifier)
    : id_(identifier) {}
  
  // SingleThreadTaskRunner implementation.
  bool PostDelayedTask(
   const base::Location& from_here,
   base::OnceClosure task,
   base::TimeDelta delay) override {
  
   return HostThread::PostDelayedTask(id_, from_here, std::move(task), delay);
  
  }

  bool PostNonNestableDelayedTask(
   const base::Location& from_here,
   base::OnceClosure task,
   base::TimeDelta delay) override {
   
   return HostThread::PostNonNestableDelayedTask(id_, from_here, std::move(task),
     delay);
  }

  bool RunsTasksInCurrentSequence() const override {
    return HostThread::CurrentlyOn(id_);
  }

 protected:
  ~HostThreadTaskRunner() override {}
 private:
  HostThread::ID id_;
  
  DISALLOW_COPY_AND_ASSIGN(HostThreadTaskRunner);
 };

 // A separate helper is used just for the task runners, in order to avoid
 // needing to initialize the globals to create a task runner.
 struct HostThreadTaskRunners {
  HostThreadTaskRunners() {
   for (int i = 0; i < HostThread::MAX; ++i) {
     proxies[i] =
      new HostThreadTaskRunner(static_cast<HostThread::ID>(i));
   }
  }
  
  scoped_refptr<base::SingleThreadTaskRunner> proxies[HostThread::MAX];
 };

 base::LazyInstance<HostThreadTaskRunners>::Leaky g_task_runners =
   LAZY_INSTANCE_INITIALIZER;

// State of a given HostThread::ID in chronological order throughout the
// browser process' lifetime.
enum HostThreadState {
  // HostThread::ID isn't associated with anything yet.
  UNINITIALIZED = 0,
  // HostThread::ID is associated to a TaskRunner and is accepting tasks.
  RUNNING,
  // HostThread::ID no longer accepts tasks (it's still associated to a
  // TaskRunner but that TaskRunner doesn't have to accept tasks).
  SHUTDOWN
};

 struct HostThreadGlobals {
  HostThreadGlobals() {
     DETACH_FROM_THREAD(main_thread_checker_);
     memset(thread_delegates, 0,
     HostThread::MAX * sizeof(thread_delegates[0]));
  }
  // HostThreadGlobals must be initialized on main thread before it's used by
  // any other threads.
  THREAD_CHECKER(main_thread_checker_);
  // This lock protects |threads|. Do not read or modify that array
  // without holding this lock. Do not block while holding this lock.
  base::Lock lock;
   
  // |task_runners[id]| is safe to access on |main_thread_checker_| as
  // well as on any thread once it's read-only after initialization
  // (i.e. while |states[id] >= RUNNING|).
  scoped_refptr<base::SingleThreadTaskRunner>
      task_runners[HostThread::MAX];

  // Tracks the runtime state of HostThreadImpls. Atomic because a few
  // methods below read this value outside |main_thread_checker_| to
  // confirm it's >= RUNNING and doing so requires an atomic read as it could be
  // in the middle of transitioning to SHUTDOWN (which the check is fine with
  // but reading a non-atomic value as it's written to by another thread can
  // result in undefined behaviour on some platforms).
  // Only NoBarrier atomic operations should be used on |states| as it shouldn't
  // be used to establish happens-after relationships but rather checking the
  // runtime state of various threads (once again: it's only atomic to support
  // reading while transitioning from RUNNING=>SHUTDOWN).
  base::subtle::Atomic32 states[HostThread::MAX] = {};
  // Only atomic operations are used on this array. The delegates are not owned
  // by this array, rather by whoever calls HostThread::SetDelegate.
  HostThreadDelegate* thread_delegates[HostThread::MAX];
 };

 base::LazyInstance<HostThreadGlobals>::Leaky
   g_globals = LAZY_INSTANCE_INITIALIZER;

bool PostTaskHelper(HostThread::ID identifier,
                    const base::Location& from_here,
                    base::OnceClosure task,
                    base::TimeDelta delay,
                    bool nestable) {
  DCHECK_GE(identifier, 0);
  DCHECK_LT(identifier, HostThread::MAX);

  HostThreadGlobals& globals = g_globals.Get();

  // Tasks should always be posted while the HostThread is in a RUNNING or
  // SHUTDOWN state (will return false if SHUTDOWN).
  //
  // Posting tasks before HostThreads are initialized is incorrect as it
  // would silently no-op. If you need to support posting early, gate it on
  // HostThread::IsThreadInitialized(). If you hit this check in unittests,
  // you most likely posted a task outside the scope of a
  // TestHostThreadBundle (which also completely resets the state after
  // shutdown in ~TestHostThreadBundle(), ref. ResetGlobalsForTesting(),
  // making sure TestHostThreadBundle is the first member of your test
  // fixture and thus outlives everything is usually the right solution).
  DCHECK_GE(base::subtle::NoBarrier_Load(&globals.states[identifier]),
            HostThreadState::RUNNING);
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

HostThread::HostThread(ID identifier,
                         scoped_refptr<base::SingleThreadTaskRunner> task_runner)
 : Thread(HostThread::GetThreadName(identifier)),
   identifier_(identifier),
   initialized_(false) {
 
  Initialize(std::move(task_runner));
}

HostThread::HostThread(ID identifier): 
    Thread(HostThread::GetThreadName(identifier)),
    identifier_(identifier),
    initialized_(false) {
  //Initialize(task_runner());
}

// static
// void HostThread::ShutdownThreadPool() {
//  // The goal is to make it impossible for switch to 'infinite loop' during
//  // shutdown, but to reasonably expect that all BLOCKING_SHUTDOWN tasks queued
//  // during shutdown get run. There's nothing particularly scientific about the
//  // number chosen.
//  const int kMaxNewShutdownBlockingTasks = 1000;
//  HostThreadGlobals& globals = g_globals.Get();
//  globals.blocking_pool->Shutdown(kMaxNewShutdownBlockingTasks);
// }

void HostThread::Initialize() {
  HostThreadGlobals& globals = g_globals.Get();

  DCHECK_CALLED_ON_VALID_THREAD(globals.main_thread_checker_);

  DCHECK_EQ(base::subtle::NoBarrier_Load(&globals.states[identifier_]),
            HostThreadState::UNINITIALIZED);
  base::subtle::NoBarrier_Store(&globals.states[identifier_],
                                HostThreadState::RUNNING);

  DCHECK(!globals.task_runners[identifier_]);
  globals.task_runners[identifier_] = task_runner();
  initialized_ = true;
}

void HostThread::Initialize(scoped_refptr<base::SingleThreadTaskRunner> task_runner) {
  DCHECK_GE(identifier_, 0);
  DCHECK_LT(identifier_, MAX);
  DCHECK(task_runner);

  HostThreadGlobals& globals = g_globals.Get();

  DCHECK_CALLED_ON_VALID_THREAD(globals.main_thread_checker_);

  DCHECK_EQ(base::subtle::NoBarrier_Load(&globals.states[identifier_]),
            HostThreadState::UNINITIALIZED);
  base::subtle::NoBarrier_Store(&globals.states[identifier_],
                                HostThreadState::RUNNING);

  DCHECK(!globals.task_runners[identifier_]);
  globals.task_runners[identifier_] = std::move(task_runner);
  initialized_ = true;
}

void HostThread::Init() {
 HostThreadGlobals& globals = g_globals.Get();
 using base::subtle::AtomicWord;
 AtomicWord* storage =
  reinterpret_cast<AtomicWord*>(&globals.thread_delegates[identifier_]);
 AtomicWord stored_pointer = base::subtle::NoBarrier_Load(storage);
 HostThreadDelegate* delegate =
  reinterpret_cast<HostThreadDelegate*>(stored_pointer);
 if (delegate)
  delegate->Init();
}
// We disable optimizations for this block of functions so the compiler doesn't
// merge them all together.
MSVC_DISABLE_OPTIMIZE()
MSVC_PUSH_DISABLE_WARNING(4748)

NOINLINE void HostThread::UIThreadRun(base::RunLoop* run_loop) {
 volatile int line_number = __LINE__;
 Thread::Run(run_loop);
 CHECK_GT(line_number, 0);
}

// NOINLINE void HostThread::FileThreadRun(
//  base::RunLoop* run_loop) {
//  volatile int line_number = __LINE__;
//  Thread::Run(run_loop);
//  CHECK_GT(line_number, 0);
// }

// NOINLINE void HostThread::DBThreadRun(
//  base::RunLoop* run_loop) {
//  volatile int line_number = __LINE__;
//  Thread::Run(run_loop);
//  CHECK_GT(line_number, 0);
// }

// NOINLINE void HostThread::RpcThreadRun(
//  base::RunLoop* run_loop) {
//  volatile int line_number = __LINE__;
//  Thread::Run(run_loop);
//  CHECK_GT(line_number, 0);
// }

// NOINLINE void HostThread::DispatcherThreadRun(
//  base::RunLoop* run_loop) {
//  volatile int line_number = __LINE__;
//  Thread::Run(run_loop);
//  CHECK_GT(line_number, 0);
// }

// NOINLINE void HostThread::NotificationThreadRun(
//  base::RunLoop* run_loop) {
//  volatile int line_number = __LINE__;
//  Thread::Run(run_loop);
//  CHECK_GT(line_number, 0);
// }

NOINLINE void HostThread::IOThreadRun(base::RunLoop* run_loop) {
 volatile int line_number = __LINE__;
 Thread::Run(run_loop);
 CHECK_GT(line_number, 0);
}

NOINLINE void HostThread::ProcessLauncherThreadRun(base::RunLoop* run_loop) {
 volatile int line_number = __LINE__;
 Thread::Run(run_loop);
 CHECK_GT(line_number, 0);
}

// NOINLINE void HostThread::WatchdogThreadRun(base::RunLoop* run_loop) {
//  volatile int line_number = __LINE__;
//  Thread::Run(run_loop);
//  CHECK_GT(line_number, 0);
// }

MSVC_POP_WARNING()
MSVC_ENABLE_OPTIMIZE();

void HostThread::Run(base::RunLoop* run_loop) {
#if defined(OS_ANDROID)
 // Not to reset thread name to "Thread-???" by VM, attach VM with thread name.
 // Though it may create unnecessary VM thread objects, keeping thread name
 // gives more benefit in debugging in the platform.
 if (!thread_name().empty()) {
  base::android::AttachCurrentThreadWithName(thread_name());
 }
#endif
 HostThread::ID thread_id = MAX;
 if (!GetCurrentThreadIdentifier(&thread_id))
  return Thread::Run(run_loop);
 switch (thread_id) {
 case HostThread::UI:
  return UIThreadRun(run_loop);
 case HostThread::IO:
  return IOThreadRun(run_loop);
 // case HostThread::FILE:
 //  return FileThreadRun(run_loop);
 // case HostThread::DB:
 //  return DBThreadRun(run_loop);
 // case HostThread::Rpc:
 //  return RpcThreadRun(run_loop); 
 // case HostThread::DISPATCHER:
 //  return DispatcherThreadRun(run_loop);
 // case HostThread::NOTIFICATION:
 //  return NotificationThreadRun(run_loop);
 case HostThread::PROCESS_LAUNCHER:
  return ProcessLauncherThreadRun(run_loop);
 // case HostThread::WATCHDOG:
 //  return WatchdogThreadRun(run_loop); 
 case HostThread::MAX:
  CHECK(false);  // This shouldn't actually be reached!
  break;
 }
 Thread::Run(run_loop);
}

void HostThread::CleanUp() {
 HostThreadGlobals& globals = g_globals.Get();
 using base::subtle::AtomicWord;
 AtomicWord* storage =
  reinterpret_cast<AtomicWord*>(&globals.thread_delegates[identifier_]);
 AtomicWord stored_pointer = base::subtle::NoBarrier_Load(storage);
 HostThreadDelegate* delegate =
  reinterpret_cast<HostThreadDelegate*>(stored_pointer);
 if (delegate)
  delegate->CleanUp();
}

bool HostThread::StartWithOptions(const Options& options) {
 // The global thread table needs to be locked while a new thread is
 // starting, as the new thread can asynchronously start touching the
 // table (and other thread's message_loop).
 HostThreadGlobals& globals = g_globals.Get();
 base::AutoLock lock(globals.lock);
 bool started = Thread::StartWithOptions(options);
 if (started && !initialized_) {
  Initialize();
 }
 return started;
}

HostThread::~HostThread() {
  Stop();
  HostThreadGlobals& globals = g_globals.Get();
  DCHECK_CALLED_ON_VALID_THREAD(globals.main_thread_checker_);

  DCHECK_EQ(base::subtle::NoBarrier_Load(&globals.states[identifier_]),
            HostThreadState::RUNNING);
  base::subtle::NoBarrier_Store(&globals.states[identifier_],
                                HostThreadState::SHUTDOWN);

  // The mapping is kept alive after shutdown to avoid requiring a lock only for
  // shutdown (the SingleThreadTaskRunner itself may stop accepting tasks at any
  // point -- usually soon before/after destroying the HostThreadImpl).
  DCHECK(globals.task_runners[identifier_]);
}

// bool HostThread::StartWithOptions(const Options& options) {
//  // The global thread table needs to be locked while a new thread is
//  // starting, as the new thread can asynchronously start touching the
//  // table (and other thread's message_loop).
//  HostThreadGlobals& globals = g_globals.Get();
//  base::AutoLock lock(globals.lock);
//  return Thread::StartWithOptions(options);
// }

// static
// bool HostThread::PostTaskHelper(
//  HostThread::ID identifier,
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
//  HostThread::ID current_thread = MAX;
//  bool target_thread_outlives_current =
//   GetCurrentThreadIdentifier(&current_thread) &&
//   current_thread >= identifier;
//  HostThreadGlobals& globals = g_globals.Get();
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
// bool HostThread::PostBlockingPoolTask(
//  const base::Location& from_here,
//  const base::Closure& task) {
//  return g_globals.Get().blocking_pool->PostWorkerTask(from_here, task);
// }

// // static
// bool HostThread::PostBlockingPoolTaskAndReply(
//  const base::Location& from_here,
//  const base::Closure& task,
//  const base::Closure& reply) {
//  return g_globals.Get().blocking_pool->PostTaskAndReply(
//   from_here, task, reply);
// }

// // static
// bool HostThread::PostBlockingPoolSequencedTask(
//  const std::string& sequence_token_name,
//  const base::Location& from_here,
//  const base::Closure& task) {
//  return g_globals.Get().blocking_pool->PostNamedSequencedWorkerTask(
//   sequence_token_name, from_here, task);
// }

// static
void HostThread::PostAfterStartupTask(
 const base::Location& from_here,
 const scoped_refptr<base::TaskRunner>& task_runner,
 base::OnceClosure task) {

 common::GetClient()->host()->PostAfterStartupTask(from_here, task_runner,
  std::move(task));
}

// static
// base::SequencedWorkerPool* HostThread::GetBlockingPool() {
//  return g_globals.Get().blocking_pool.get();
// }

// static
bool HostThread::IsThreadInitialized(ID identifier) {
 DCHECK_GE(identifier, 0);
 DCHECK_LT(identifier, MAX);

 HostThreadGlobals& globals = g_globals.Get();
  return base::subtle::NoBarrier_Load(&globals.states[identifier]) ==
         HostThreadState::RUNNING;
}

// static
bool HostThread::CurrentlyOn(ID identifier) {
  DCHECK_GE(identifier, 0);
  DCHECK_LT(identifier, MAX);

  HostThreadGlobals& globals = g_globals.Get();

  // Thread-safe since |globals.task_runners| is read-only after being
  // initialized from main thread (which happens before //content and embedders
  // are kicked off and enabled to call the HostThread API from other
  // threads).
  return globals.task_runners[identifier] &&
         globals.task_runners[identifier]->RunsTasksInCurrentSequence();
}

const char* HostThread::GetThreadName(HostThread::ID thread) {
 if (HostThread::UI < thread && thread < HostThread::MAX)
  return g_engine_thread_names[thread];
 if (thread == HostThread::UI)
  return "Host_UIThread";
 return "Unknown Thread";
}

// static
std::string HostThread::GetDCheckCurrentlyOnErrorMessage(ID expected) {
std::string actual_name = base::PlatformThread::GetName();
  if (actual_name.empty())
    actual_name = "Unknown Thread";

  std::string result = "Must be called on ";
  result += HostThread::GetThreadName(expected);
  result += "; actually called on ";
  result += actual_name;
  result += ".";
  return result;
}

// // static
// bool HostThread::IsMessageLoopValid(ID identifier) {
//  if (g_globals == NULL)
//   return false;
//  HostThreadGlobals& globals = g_globals.Get();
//  base::AutoLock lock(globals.lock);
//  DCHECK(identifier >= 0 && identifier < MAX);
//  return globals.threads[identifier] &&
//   globals.threads[identifier]->message_loop();
// }

// static
// bool HostThread::PostTask(ID identifier,
//  const base::Location& from_here,
//  const base::Closure& task) {
//  return HostThread::PostTaskHelper(
//   identifier, from_here, task, base::TimeDelta(), true);
// }

// // static
// bool HostThread::PostDelayedTask(ID identifier,
//  const base::Location& from_here,
//  const base::Closure& task,
//  base::TimeDelta delay) {
//  return HostThread::PostTaskHelper(
//   identifier, from_here, task, delay, true);
// }

// // static
// bool HostThread::PostNonNestableTask(
//  ID identifier,
//  const base::Location& from_here,
//  const base::Closure& task) {
//  return HostThread::PostTaskHelper(
//   identifier, from_here, task, base::TimeDelta(), false);
// }

// // static
// bool HostThread::PostNonNestableDelayedTask(
//  ID identifier,
//  const base::Location& from_here,
//  const base::Closure& task,
//  base::TimeDelta delay) {
//  return HostThread::PostTaskHelper(
//   identifier, from_here, task, delay, false);
// }

// // static
// bool HostThread::PostTaskAndReply(
//  ID identifier,
//  const base::Location& from_here,
//  const base::Closure& task,
//  const base::Closure& reply) {
//  return GetMessageLoopProxyForThread(identifier)->PostTaskAndReply(from_here,
//   task,
//   reply);
// }

bool HostThread::PostTask(ID identifier,
                             const base::Location& from_here,
                             base::OnceClosure task) {
  return PostTaskHelper(identifier, from_here, std::move(task),
                        base::TimeDelta(), true);
}

// static
bool HostThread::PostDelayedTask(ID identifier,
                                  const base::Location& from_here,
                                  base::OnceClosure task,
                                  base::TimeDelta delay) {
  return PostTaskHelper(identifier, from_here, std::move(task), delay, true);
}

// static
bool HostThread::PostNonNestableTask(ID identifier,
                                      const base::Location& from_here,
                                      base::OnceClosure task) {
  return PostTaskHelper(identifier, from_here, std::move(task),
                        base::TimeDelta(), false);
}

// static
bool HostThread::PostNonNestableDelayedTask(ID identifier,
                                             const base::Location& from_here,
                                             base::OnceClosure task,
                                             base::TimeDelta delay) {
  return PostTaskHelper(identifier, from_here, std::move(task), delay, false);
}

// static
bool HostThread::PostTaskAndReply(ID identifier,
                                     const base::Location& from_here,
                                     base::OnceClosure task,
                                     base::OnceClosure reply) {
  return GetTaskRunnerForThread(identifier)
      ->PostTaskAndReply(from_here, std::move(task), std::move(reply));
}


// static
bool HostThread::GetCurrentThreadIdentifier(ID* identifier) {
  HostThreadGlobals& globals = g_globals.Get();

  // Thread-safe since |globals.task_runners| is read-only after being
  // initialized from main thread (which happens before //content and embedders
  // are kicked off and enabled to call the HostThread API from other
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
HostThread::GetMessageLoopProxyForThread(ID identifier) {
 return g_task_runners.Get().proxies[identifier];
}

// // static
// base::MessageLoop* HostThread::UnsafeGetMessageLoopForThread(ID identifier) {
//  if (g_globals == NULL)
//   return NULL;
//  HostThreadGlobals& globals = g_globals.Get();
//  base::AutoLock lock(globals.lock);
//  base::Thread* thread = globals.threads[identifier];
//  DCHECK(thread);
//  base::MessageLoop* loop = thread->message_loop();
//  return loop;
// }

// static
void HostThread::SetDelegate(ID identifier,
 HostThreadDelegate* delegate) {
 using base::subtle::AtomicWord;
 HostThreadGlobals& globals = g_globals.Get();
 AtomicWord* storage = reinterpret_cast<AtomicWord*>(
  &globals.thread_delegates[identifier]);
 AtomicWord old_pointer = base::subtle::NoBarrier_AtomicExchange(
  storage, reinterpret_cast<AtomicWord>(delegate));
 // This catches registration when previously registered.
 DCHECK(!delegate || !old_pointer);
}

scoped_refptr<base::SingleThreadTaskRunner> HostThread::GetTaskRunnerForThread(ID identifier) {
  return g_task_runners.Get().proxies[identifier];
}


}
