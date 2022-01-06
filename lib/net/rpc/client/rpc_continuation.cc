// Copyright (c) 2017 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/rpc/client/rpc_continuation.h"
#include "net/rpc/client/rpc_call.h"
#include "base/threading/thread_task_runner_handle.h"
#include "base/task_scheduler/post_task.h"
#include "base/sequenced_task_runner.h"
#include "base/bind.h"
#include "base/threading/thread_restrictions.h"

namespace net {

namespace {

void* tag(intptr_t i) { return (void*)i; } 

gpr_timespec grpc_timeout_milliseconds_to_deadline(int64_t time_ms) {
   return gpr_time_add(
       gpr_now(GPR_CLOCK_MONOTONIC),
       gpr_time_from_micros((int64_t)1e3 * time_ms,
                            GPR_TIMESPAN));
}

// gpr_timespec grpc_timeout_seconds_to_deadline(int64_t time_s) {
//   return gpr_time_add(
//       gpr_now(GPR_CLOCK_MONOTONIC),
//       gpr_time_from_millis((int64_t)1e3 * time_s,
//                            GPR_TIMESPAN));
// }

gpr_timespec ms_from_now(int ms) {
   return grpc_timeout_milliseconds_to_deadline(ms);
}

}  

RpcPluckContinuation::RpcPluckContinuation(
  const scoped_refptr<base::SequencedTaskRunner>& io_task_runner):
  completion_queue_(grpc_completion_queue_create_for_pluck(nullptr)),
  shutting_down_(false),
  //shutdown_loop_(false),
  io_task_runner_(io_task_runner),
  shutdown_event_(
      base::WaitableEvent::ResetPolicy::MANUAL, 
      base::WaitableEvent::InitialState::NOT_SIGNALED),
  weak_factory_(new base::WeakPtrFactory<RpcContinuation>(this)) {

}

RpcPluckContinuation::~RpcPluckContinuation() {
  //weak_factory_.InvalidateWeakPtrs();
  DCHECK(shutting_down_);
  // if (!shutting_down_) {
  //   Shutdown();
  // }
  grpc_completion_queue_destroy(completion_queue_);
  io_task_runner_ = nullptr;
}

void RpcPluckContinuation::Shutdown() {
  base::ScopedAllowBaseSyncPrimitivesForTesting allow_wait;
  grpc_event ev;
  shutting_down_ = true;
  //shutdown_loop_ = true;
  //delegate_ = nullptr;
  //weak_factory_.InvalidateWeakPtrs();
  grpc_completion_queue_shutdown(completion_queue_);
  do {
     ev = grpc_completion_queue_pluck(completion_queue_, tag(1), ms_from_now(1000), nullptr);
  } while (ev.type != GRPC_QUEUE_SHUTDOWN);
  io_task_runner_->PostTask(
    FROM_HERE,
    base::BindOnce(&RpcPluckContinuation::ShutdownOnIO,
     base::Unretained(this)));
  shutdown_event_.Wait();
  //grpc_completion_queue_destroy(completion_queue_);
}

void RpcPluckContinuation::ShutdownOnIO() {
  //weak_factory_.InvalidateWeakPtrs();
  //delegate_ = nullptr;
  weak_factory_->InvalidateWeakPtrs();
  shutdown_event_.Signal();
}

grpc_completion_queue* RpcPluckContinuation::c_completion_queue() const { 
  return completion_queue_; 
}

// RpcContinuation::Delegate* RpcPluckContinuation::delegate() const { 
//   return delegate_.get();
// }

base::WeakPtr<RpcContinuation> RpcPluckContinuation::GetWeakPtr() {
  return weak_factory_->GetWeakPtr();
}

void RpcPluckContinuation::Schedule(base::WeakPtr<Delegate> delegate) {
  for (;;) {
    auto ev = grpc_completion_queue_pluck(completion_queue_, nullptr, ms_from_now(3 * 1000), nullptr);
    switch (ev.type) {
      case GRPC_OP_COMPLETE: {
        RpcCall* call = reinterpret_cast<RpcCall* >(ev.tag);
        if (delegate) {
          delegate->OnContinue(ev.success != 0, call);
        }
        // if (call && call->call_and_close) {
        //   shutdown = true;
        // }
        break;
      }
      case GRPC_QUEUE_TIMEOUT: {
        DLOG(INFO) << "RpcPluckContinuation::Schedule: TIMEOUT";
        //RpcCall* call = reinterpret_cast<RpcCall* >(ev.tag);
        // if (call && call->call_and_close) {
        //   shutdown = true;
        // }
        //call->set_timeout();
        
        // FIXME: Dispatch the Schedule() over a weak pointer
        //        the task keep running even after this object is gone
        if (shutting_down_) {
          return;
        }

        // if (shutting_down_) {// || call->timeouts() > 1) {
        //   shutdown_loop_ = true;
        //   //return;
        // }
        // if (delegate_ && !shutting_down_ && !shutdown_loop_) {
        //   delegate_->OnTimeout();
        // }
        break;
      }
      case GRPC_QUEUE_SHUTDOWN:
        DLOG(INFO) << "RpcPluckContinuation::Schedule: SHUTDOWN";
        // if (delegate_) {    
        //   delegate_->OnShutdown();
        // }
        //if (shutting_down_) {
        //  return;
        //}
        return;
    }
  }
  if (delegate) {    
    delegate->OnShutdown();
  }
}

RpcNextContinuation::RpcNextContinuation(
  const scoped_refptr<base::SequencedTaskRunner>& io_task_runner):
  completion_queue_(grpc_completion_queue_create_for_next(nullptr)),
  shutting_down_(false),
  //shutdown_loop_(false),
  io_task_runner_(io_task_runner),
  shutdown_event_(
      base::WaitableEvent::ResetPolicy::MANUAL, 
      base::WaitableEvent::InitialState::NOT_SIGNALED),
  weak_factory_(new base::WeakPtrFactory<RpcContinuation>(this)) {

}

RpcNextContinuation::~RpcNextContinuation() {
  //DLOG(INFO) << "~RpcNextContinuation";
  DCHECK(shutting_down_);
  io_task_runner_->DeleteSoon(FROM_HERE, weak_factory_.release());
  //grpc_completion_queue_destroy(completion_queue_);
  //weak_factory_.InvalidateWeakPtrs();
  //grpc_completion_queue_destroy(completion_queue_);
  //grpc_completion_queue_destroy(completion_queue_);
  // if (!shutting_down_) {
  //   Shutdown();
  // }
  // grpc_completion_queue_destroy(completion_queue_);
  // io_task_runner_ = nullptr;
  //DLOG(INFO) << "~RpcNextContinuation END";
}

grpc_completion_queue* RpcNextContinuation::c_completion_queue() const { 
  return completion_queue_; 
}

// RpcContinuation::Delegate* RpcNextContinuation::delegate() const { 
//   return delegate_.get(); 
// }

void RpcNextContinuation::Schedule(base::WeakPtr<Delegate> delegate) {
  //DLOG(INFO) << "RpcNextContinuation::Schedule";
  int last_event = GRPC_OP_COMPLETE;
  //bool shutdown_loop = false;
  for (;;) {
    if (last_event != GRPC_QUEUE_TIMEOUT) {
      //DLOG(INFO) << "\nRpcNextContinuation::Schedule: waiting for completion ..\n";
    }
    //auto ev = grpc_completion_queue_next(completion_queue_, gpr_inf_future(GPR_CLOCK_REALTIME), nullptr);
    auto ev = grpc_completion_queue_next(completion_queue_, ms_from_now(3 * 1000), nullptr);
//if (ev.type != GRPC_QUEUE_TIMEOUT)
      //DLOG(INFO) << "\nRpcNextContinuation::Schedule: new event!\n";
    //if (shutting_down_) {
    //  return;
    //}
    switch (ev.type) {
      case GRPC_OP_COMPLETE: {
        //DLOG(INFO) << "\nRpcNextContinuation (client): COMPLETE: ev.success = " << ev.success << "\n";
        RpcCall* call = reinterpret_cast<RpcCall* >(ev.tag);
        if (delegate) {
          delegate->OnContinue(ev.success != 0, call);
          // io_task_runner_->PostTask(
          //   FROM_HERE,
          //   base::BindOnce(&Delegate::OnContinue,
          //     delegate_,
          //     ev.success != 0, 
          //     call));
        }
        // if (call && call->call_and_close) {
        //   shutdown = true;
        // }
        break;
      }
      case GRPC_QUEUE_TIMEOUT: {
        //DLOG(INFO) << "RpcNextContinuation: TIMEOUT";
        // FIXME: Dispatch the Schedule() over a weak pointer
        //        the task keep running even after this object is gone
        
        //if (delegate) {
        //  delegate->OnTimeout();
        //}
        
        //RpcCall* call = reinterpret_cast<RpcCall* >(ev.tag);
        //call->set_timeout();
        // if theres more than 2 timeouts on a single call
        // its likely that the remote service loop is gone 
        // if (shutting_down_) {// || call->timeouts() > 1) {
        //    //return;
        //    shutdown_loop_ = true;
        // }
        // // if (call && call->call_and_close) {
        // //   shutdown = true;
        // // }
        // if (delegate_ && !shutting_down_ && !shutdown_loop_) {
        //   delegate_->OnTimeout();
        //   // io_task_runner_->PostTask(
        //   //   FROM_HERE,
        //   //   base::BindOnce(&Delegate::OnTimeout,
        //   //     delegate_));
        // }

        //if (shutting_down_) {// || call->timeouts() > 1) {
           //return;
        //   shutdown_loop_ = true;
        //}
        //shutdown_loop_ = true;
        //return;
        //shutdown_loop = true;
        if (shutting_down_) {
          //DLOG(INFO) << "RpcNextContinuation: shutting_down_ => exiting";
          shutdown_event_.Signal();
          return;
        }
        break;
      }
      case GRPC_QUEUE_SHUTDOWN:
        //DLOG(INFO) << "RpcNextContinuation: SHUTDOWN";
        //if (delegate_) {    
        //  delegate_->OnShutdown();
        //}
        //if (shutting_down_) {// || call->timeouts() > 1) {
        //  return;
        //}
        //shutdown_loop = true;
        shutdown_event_.Signal();
        return;
    }
    last_event = ev.type;
  }
  // DLOG(INFO) << "RpcNextContinuation::Schedule: if (delegate && shutdown_loop)";
  // if (delegate) {
  //   DLOG(INFO) << "RpcNextContinuation::Schedule: delegate->OnShutdown()";
  //   delegate->OnShutdown();
  //   // io_task_runner_->PostTask(
  //   //   FROM_HERE,
  //   //   base::BindOnce(&Delegate::OnShutdown,
  //   //     delegate_));
  // }

  //DLOG(INFO) << "RpcNextContinuation::Schedule END";
}

void RpcNextContinuation::Shutdown() {
  //DLOG(INFO) << "RpcNextContinuation::Shutdown";
  base::ScopedAllowBaseSyncPrimitivesForTesting allow_wait;
  //grpc_event ev;
  shutting_down_ = true;
  //shutdown_loop_ = true;
  //delegate_ = nullptr;
  //grpc_completion_queue_shutdown(completion_queue_);
  //do {
  //  ev = grpc_completion_queue_next(completion_queue_, ms_from_now(3000), nullptr);
  //  DLOG(INFO) << "ev.type = " << ev.type;
  //} while (ev.type != GRPC_QUEUE_SHUTDOWN);
  //weak_factory_.InvalidateWeakPtrs();
  //grpc_completion_queue_destroy(completion_queue_);
  //io_task_runner_->DeleteSoon(FROM_HERE, weak_factory_.release());
  //io_task_runner_->PostTask(
  //  FROM_HERE,
  //  base::BindOnce(&RpcNextContinuation::ShutdownOnIO,
  //   base::Unretained(this)));
  //shutdown_event_.Wait();
  //grpc_completion_queue_shutdown(completion_queue_);
  grpc_completion_queue_destroy(completion_queue_);
  //io_task_runner_->DeleteSoon(FROM_HERE, weak_factory_.release());
  //io_task_runner_ = nullptr;
  
  //DLOG(INFO) << "RpcNextContinuation::Shutdown: weak_factory_.InvalidateWeakPtrs()";
  //weak_factory_.InvalidateWeakPtrs();
  //DLOG(INFO) << "RpcNextContinuation::Shutdown: weak_factory_.InvalidateWeakPtrs() DONE";
  shutdown_event_.Wait();
  //DLOG(INFO) << "RpcNextContinuation::Shutdown END";
}

void RpcNextContinuation::ShutdownOnIO() {
  //grpc_event ev;
  //DLOG(INFO) << "RpcNextContinuation::ShutdownOnIO";
  weak_factory_->InvalidateWeakPtrs();
  //grpc_completion_queue_shutdown(completion_queue_);
  // do {
  //   ev = grpc_completion_queue_next(completion_queue_, ms_from_now(5000), nullptr);
  //   DLOG(INFO) << "ev.type = " << ev.type;
  // } while (ev.type != GRPC_QUEUE_SHUTDOWN);
  //DLOG(INFO) << "RpcNextContinuation::ShutdownOnIO: DONE";
  //shutdown_event_.Signal();
}

base::WeakPtr<RpcContinuation> RpcNextContinuation::GetWeakPtr() {
  return weak_factory_->GetWeakPtr();
}

}