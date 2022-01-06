// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "storage/io_completion_callback.h"

#include "base/bind.h"
#include "base/bind_helpers.h"
#include "base/compiler_specific.h"
#include "base/run_loop.h"
#include "net/base/io_buffer.h"

namespace storage {

namespace internal {

void IOCompletionCallbackBaseInternal::DidSetResult() {
  //D//LOG(INFO) << "IOCompletionCallbackBaseInternal::DidSetResult";
  have_result_ = true;
  if (event_)//run_loop_)
    event_->Signal();
    //run_loop_->Quit();
  //D//LOG(INFO) << "IOCompletionCallbackBaseInternal::DidSetResult end";
}

void IOCompletionCallbackBaseInternal::WaitForResult() {
  //DCHECK(!run_loop_);
  //D//LOG(INFO) << "IOCompletionCallbackBaseInternal::WaitForResult";
  DCHECK(!event_);
  if (!have_result_) {
    //run_loop_.reset(new base::RunLoop());
    //run_loop_->Run();
    //run_loop_.reset();
    //DCHECK(have_result_);
    event_.reset(new base::WaitableEvent(
      base::WaitableEvent::ResetPolicy::MANUAL, 
      base::WaitableEvent::InitialState::NOT_SIGNALED));
    event_->Wait();
    event_.reset();
    DCHECK(have_result_);
  }
  have_result_ = false;  // Auto-reset for next callback.
  //D//LOG(INFO) << "IOCompletionCallbackBaseInternal::WaitForResult end";
}

IOCompletionCallbackBaseInternal::IOCompletionCallbackBaseInternal()
    : have_result_(false) {
}

IOCompletionCallbackBaseInternal::~IOCompletionCallbackBaseInternal() =
    default;

}  // namespace internal

IOClosure::IOClosure()
    : closure_(base::Bind(&IOClosure::DidSetResult, base::Unretained(this))) {
}

IOClosure::~IOClosure() = default;

IOCompletionCallback::IOCompletionCallback()
    : callback_(base::Bind(&IOCompletionCallback::SetResult,
                           base::Unretained(this))) {
}

IOCompletionCallback::~IOCompletionCallback() = default;

IOReleaseBufferCompletionCallback::IOReleaseBufferCompletionCallback(net::IOBuffer* buffer) : buffer_(buffer) {
}

IOReleaseBufferCompletionCallback::~IOReleaseBufferCompletionCallback() = default;

void IOReleaseBufferCompletionCallback::SetResult(int result) {
  if (!buffer_->HasOneRef())
    result = net::ERR_FAILED;
  IOCompletionCallback::SetResult(result);
}

}  // namespace storage
