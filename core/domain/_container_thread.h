// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_DOMAIN_THREAD_H_
#define MUMBA_DOMAIN_DOMAIN_THREAD_H_

#include <string>

#include "base/macros.h"
#include "base/callback.h"
#include "base/location.h"
#include "base/logging.h"
#include "base/single_thread_task_runner.h"
#include "base/task_runner_util.h"
#include "base/time/time.h"
#include "base/threading/thread.h"

namespace base {
class MessageLoop;
class SequencedWorkerNamespace;
class Thread;
}

namespace domain {
class DomainThreadDelegate;

// Use DCHECK_CURRENTLY_ON(DomainThread::ID) to assert that a function can only
// be called on the named DomainThread.
#define DCHECK_CURRENTLY_ON(thread_identifier)                          \
  (DCHECK(::shell::DomainThread::CurrentlyOn(thread_identifier)) \
   << ::shell::DomainThread::GetDCheckCurrentlyOnErrorMessage(   \
          thread_identifier))

///////////////////////////////////////////////////////////////////////////////
// DomainThread
//
// Utility functions for threads that are known by a browser-wide
// name.  For example, there is one IO thread for the entire browser
// process, and various pieces of code find it useful to retrieve a
// pointer to the IO thread's message loop.
//
// Invoke a task by thread ID:
//
//   DomainThread::PostTask(DomainThread::IO, FROM_HERE, task);
//
// The return value is false if the task couldn't be posted because the target
// thread doesn't exist.  If this could lead to data loss, you need to check the
// result and restructure the code to ensure it doesn't occur.
//
// This class automatically handles the lifetime of different threads.
// It's always safe to call PostTask on any thread.  If it's not yet created,
// the task is deleted.  There are no race conditions.  If the thread that the
// task is posted to is guaranteed to outlive the current thread, then no locks
// are used.  You should never need to cache pointers to MessageLoops, since
// they're not thread safe.

class DomainThread {//: public base::Thread {
public:
 
 enum ID {
  UI,
  //DB,
  //FILE,
  MAX
 };

 static const char* GetThreadName(DomainThread::ID identifier);

 // Construct a DomainThreadImpl with the supplied identifier.  It is an error
 // to construct a DomainThreadImpl that already exists.
 //explicit DomainThread(ID identifier);

 // Special constructor for the main thread and unittests. If a
 // |message_loop| is provied, we use a dummy thread here since the main
 // thread already exists.
 //DomainThread(ID identifier,
 // base::MessageLoop* message_loop);
 explicit DomainThread(ID identifier,
    scoped_refptr<base::SingleThreadTaskRunner> task_runner);

 ~DomainThread() override;
 

 bool StartWithOptions(const Options& options);


 static bool PostTask(ID identifier,
                       const base::Location& from_here,
                       base::OnceClosure task);
 static bool PostDelayedTask(ID identifier,
                              const base::Location& from_here,
                              base::OnceClosure task,
                              base::TimeDelta delay);
 static bool PostNonNestableTask(ID identifier,
                                  const base::Location& from_here,
                                  base::OnceClosure task);
 static bool PostNonNestableDelayedTask(ID identifier,
                                        const base::Location& from_here,
                                        base::OnceClosure task,
                                        base::TimeDelta delay);

 static bool PostTaskAndReply(ID identifier,
                              const base::Location& from_here,
                              base::OnceClosure task,
                              base::OnceClosure reply);

  template <typename ReturnType, typename ReplyArgType>
  static bool PostTaskAndReplyWithResult(
      ID identifier,
      const base::Location& from_here,
      base::OnceCallback<ReturnType()> task,
      base::OnceCallback<void(ReplyArgType)> reply) {
    scoped_refptr<base::SingleThreadTaskRunner> task_runner =
        GetTaskRunnerForThread(identifier);
    return base::PostTaskAndReplyWithResult(task_runner.get(), from_here,
                                            std::move(task), std::move(reply));
  }

  // Callback version of PostTaskAndReplyWithResult above.
  // Though RepeatingCallback is convertible to OnceCallback, we need this since
  // we cannot use template deduction and object conversion at once on the
  // overload resolution.
  // TODO(crbug.com/714018): Update all callers of the Callback version to use
  // OnceCallback.
  template <typename ReturnType, typename ReplyArgType>
  static bool PostTaskAndReplyWithResult(
      ID identifier,
      const base::Location& from_here,
      base::Callback<ReturnType()> task,
      base::Callback<void(ReplyArgType)> reply) {
    return PostTaskAndReplyWithResult(
        identifier, from_here,
        base::OnceCallback<ReturnType()>(std::move(task)),
        base::OnceCallback<void(ReplyArgType)>(std::move(reply)));
  }

  template <class T>
  static bool DeleteSoon(ID identifier,
                         const base::Location& from_here,
                         const T* object) {
    return GetTaskRunnerForThread(identifier)->DeleteSoon(from_here, object);
  }

  template <class T>
  static bool DeleteSoon(ID identifier,
                         const base::Location& from_here,
                         std::unique_ptr<T> object) {
    return DeleteSoon(identifier, from_here, object.release());
  }

  template <class T>
  static bool ReleaseSoon(ID identifier,
                          const base::Location& from_here,
                          const T* object) {
    return GetTaskRunnerForThread(identifier)->ReleaseSoon(from_here, object);
  }

 static void PostAfterStartupTask(
  const base::Location& from_here,
  const scoped_refptr<base::TaskRunner>& task_runner,
  base::OnceClosure);

 // Returns the thread namespace used for blocking file I/O. Use this object to
 // perform random blocking operations such as file writes or querying the
 // Windows registry.
 static base::SequencedWorkerNamespace* GetBlockingNamespace() WARN_UNUSED_RESULT;

 // Callable on any thread.  Returns whether the given well-known thread is
 // initialized.
 static bool IsThreadInitialized(ID identifier) WARN_UNUSED_RESULT;

 // Callable on any thread.  Returns whether you're currently on a particular
 // thread.  To DCHECK this, use the DCHECK_CURRENTLY_ON() macro above.
 static bool CurrentlyOn(ID identifier) WARN_UNUSED_RESULT;

 // Callable on any thread.  Returns whether the threads message loop is valid.
 // If this returns false it means the thread is in the process of shutting
 // down.
// static bool IsMessageLoopValid(ID identifier) WARN_UNUSED_RESULT;

 // If the current message loop is one of the known threads, returns true and
 // sets identifier to its ID.  Otherwise returns false.
 static bool GetCurrentThreadIdentifier(ID* identifier) WARN_UNUSED_RESULT;


 static scoped_refptr<base::SingleThreadTaskRunner> GetTaskRunnerForThread(ID identifier);

 // Callers can hold on to a refcounted task runner beyond the lifetime
 // of the thread.
 static scoped_refptr<base::SingleThreadTaskRunner>
  GetMessageLoopProxyForThread(ID identifier);

 // Returns a pointer to the thread's message loop, which will become
 // invalid during shutdown, so you probably shouldn't hold onto it.
 //
 // This must not be called before the thread is started, or after
 // the thread is stopped, or it will DCHECK.
 //
 // Ownership remains with the DomainThread implementation, so you
 // must not delete the pointer.
 //static base::MessageLoop* UnsafeGetMessageLoopForThread(ID identifier);

 // Sets the delegate for the specified DomainThread.
 //
 // Only one delegate may be registered at a time.  Delegates may be
 // unregistered by providing a nullptr pointer.
 //
 // If the caller unregisters a delegate before CleanUp has been
 // called, it must perform its own locking to ensure the delegate is
 // not deleted while unregistering.
 static void SetDelegate(ID identifier, DomainThreadDelegate* delegate);

 // Use these templates in conjunction with RefCountedThreadSafe or scoped_ptr
 // when you want to ensure that an object is deleted on a specific thread.
 // This is needed when an object can hop between threads
 // (i.e. IO -> FILE -> IO), and thread switching delays can mean that the
 // final IO tasks executes before the FILE task's stack unwinds.
 // This would lead to the object destructing on the FILE thread, which often
 // is not what you want (i.e. to unregister from NotificationService, to
 // notify other objects on the creating thread etc).

 template<ID thread>
 struct DeleteOnThread {
  template<typename T>
  static void Destruct(const T* x) {
   if (CurrentlyOn(thread)) {
    delete x;
   }
   else {
    if (!DeleteSoon(thread, FROM_HERE, x)) {
#if defined(UNIT_TEST)
     // Only logged under unit testing because leaks at shutdown
     // are acceptable under normal circumstances.
     LOG(ERROR) << "DeleteSoon failed on thread " << thread;
#endif  // UNIT_TEST
    }
   }
  }
  template <typename T>
  inline void operator()(T* ptr) const {
   enum { type_must_be_complete = sizeof(T) };
   Destruct(ptr);
  }
 };

 // Sample usage with RefCountedThreadSafe:
 // class Foo
 //     : public base::RefCountedThreadSafe<
 //           Foo, DomainThread::DeleteOnIOThread> {
 //
 // ...
 //  private:
 //   friend struct DomainThread::DeleteOnThread<DomainThread::IO>;
 //   friend class base::DeleteHelper<Foo>;
 //
 //   ~Foo();
 //
 // Sample usage with scoped_ptr:
 // std::unique_ptr<Foo, DomainThread::DeleteOnIOThread> ptr;

 struct DeleteOnUIThread : public DeleteOnThread<UI> { };
 //struct DeleteOnDBThread : public DeleteOnThread<DB> { };
 //struct DeleteOnFileThread : public DeleteOnThread<FILE> { };
 // Returns an appropriate error message for when DCHECK_CURRENTLY_ON() fails.
 static std::string GetDCheckCurrentlyOnErrorMessage(ID expected);

protected:
 
 void Init() override;
 void Run(base::RunLoop* run_loop) override;
 void CleanUp() override;

private:
 // The following are unique function names that makes it possible to tell
 // the thread id from the callstack alone in crash dumps.
 void UIThreadRun(base::RunLoop* run_loop);
 //void DBThreadRun(base::RunLoop* run_loop);
 //void FileThreadRun(base::RunLoop* run_loop);
 //static bool PostTaskHelper(
 // DomainThread::ID identifier,
 // const base::Location& from_here,
 // base::OnceClosure task,
 // base::TimeDelta delay,
 // bool nestable);

 // Common initialization code for the constructors.
 void Initialize(scoped_refptr<base::SingleThreadTaskRunner> task_runner);
 //void Initialize();

 ID identifier_;
 bool initialized_;
 
 DISALLOW_COPY_AND_ASSIGN(DomainThread);
};

}

#endif
