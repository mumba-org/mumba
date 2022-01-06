// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/domain/execution/event_queue.h"

#include "base/threading/thread_task_runner_handle.h"

namespace domain {

Operation::Operation(OperationType type): type_(type) {

}

Operation::~Operation() {

}

Event::Event(EventType type): type_(type) {

}

Event::~Event() {

}

EventQueue::EventQueue(scoped_refptr<base::SingleThreadTaskRunner> task_runner):
  task_runner_(task_runner),
  wait_event_(base::WaitableEvent::ResetPolicy::AUTOMATIC,
              base::WaitableEvent::InitialState::NOT_SIGNALED),
  shutting_down_(false) {

}

EventQueue::~EventQueue() {
  queue_.clear();
}

Event* EventQueue::Next() {
  //DLOG(INFO) << "EventQueue::WaitEvent";
  
  base::AutoLock lock(next_mutex_);
  
  // block until we have something in the queue
  //DCHECK_EQ(base::SingleThreadTaskRunnerHandle::Get() ,task_runner_);

  if (queue_.empty() && !shutting_down_) {
    //DLOG(INFO) << "EventLoop::WaitEvent: queue is empty. waiting ...";
    wait_event_.Wait();
  }

  while (!queue_.empty()) {
    //DLOG(INFO) << "EventLoop::WaitEvent: queue has " << queue_.size() << " objects. consuming ...";
    Event* event = queue_.front();
    queue_.pop_front();
    return event;
  }
  
  return nullptr;
}

void EventQueue::Push(Event* event) {
  //DLOG(INFO) << "EventQueue::Push";
  base::AutoLock lock(mutex_);
  
  queue_.emplace_back(event);
  
  wait_event_.Signal();
}

void EventQueue::Shutdown() {
  base::AutoLock lock(mutex_);
  
  shutting_down_ = true;
  queue_.clear();
  
  //grpc_completion_queue_destroy(completion_queue_);

  wait_event_.Signal();
}

}