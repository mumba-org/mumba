// Copyright (c) 2017 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_WAITABLE_TASK_H_
#define MUMBA_HOST_WAITABLE_TASK_H_

#include "base/macros.h"
//#include "base/move.h"
#include "base/synchronization/waitable_event.h"
#include "base/memory/ref_counted.h"

namespace host {

// enum class TaskState {
//  INIT,
//  WAITING,
//  DONE,
//  TIMEDOUT,
//  ERROR
// };

// A Waitable job of a T type of result
// this works like a Future would
template <typename T>
class WaitableTask {//: public base::RefCountedThreadSafe<WaitableTask<T>> {
public:
 class Delegate {
 public:	
  virtual ~Delegate() {}
  virtual void OnTaskTimeout() = 0;
  virtual void OnTaskDispose() = 0;
 };

 WaitableTask():
  delegate_(nullptr),
  result_(nullptr),
	ready_(new base::WaitableEvent(base::WaitableEvent::ResetPolicy::AUTOMATIC, base::WaitableEvent::InitialState::NOT_SIGNALED)),
	timedout_(false) {}//, 
	//state_(TaskState::INIT),
	//timedout_(false){}

 WaitableTask(T* result): 
	delegate_(nullptr),
  result_(result),
	ready_(new base::WaitableEvent(base::WaitableEvent::ResetPolicy::AUTOMATIC, base::WaitableEvent::InitialState::NOT_SIGNALED)), 
	timedout_(false) {}//, 
	//state_(TaskState::INIT),
	//timedout_(false){}

 ~WaitableTask() {
 		if (delegate_) {
 			delegate_->OnTaskDispose();
 		}
 	}	

 //TaskState state() const { return state_; }

 T* get() const { return result_.get(); }
 void set(T* result) { result_.reset(result); }

 bool expired() const { return timedout_; }

 Delegate* delegate() const { return delegate_; }
 void set_delegate(Delegate* delegate) { delegate_ = delegate; }

 base::WaitableEvent* GetDoneEvent() { return ready_.get(); }

 T* own() {
	 return result_.release();
 }

 //bool should_wait() const {
 //	return state_ == TaskState::INIT;
 //}

 //bool is_error() const {
 //	return state_ == TaskState::ERROR;
 //}

 //void set_error(T result) { 
 //	state_ = TaskState::ERROR;
 //	result_ = result;
 //}

 void Wait() {
 	//if (state_ == TaskState::ERROR || state_ == TaskState::DONE)
 	//	return result_;
 	
 	//state_ = TaskState::WAITING;
 	timedout_ = !ready_->TimedWait(base::TimeDelta::FromMilliseconds(10000));
 	if (timedout_) {
 		//state_ = TaskState::TIMEDOUT;
 		if (delegate_){
 			delegate_->OnTaskTimeout();
 		}
 	}
 	//return result_;
 }

 void Done() {
 	ready_->Signal();
 	//state_ = TaskState::DONE;
 }

private:
 
 Delegate* delegate_;

 //TaskState state_;

 std::unique_ptr<T> result_;
 
 std::unique_ptr<base::WaitableEvent> ready_;

 bool timedout_;
};

}

#endif