// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef STORAGE_IO_COMPLETION_CALLBACK_H_
#define STORAGE_IO_COMPLETION_CALLBACK_H_

#include <stdint.h>

#include <memory>

#include "base/callback.h"
#include "base/compiler_specific.h"
#include "base/macros.h"
#include "base/synchronization/waitable_event.h"
#include "storage/storage_export.h"
#include "storage/backend/storage_entry.h" // for the correct CompletionCallback alias
#include "net/base/net_errors.h"

//-----------------------------------------------------------------------------
// completion callback helper

// A helper class for completion callbacks, designed to make it easy to run
// tests involving asynchronous operations.  Just call WaitForResult to wait
// for the asynchronous operation to complete.  Uses a RunLoop to spin the
// current MessageLoop while waiting.  The callback must be invoked on the same
// thread WaitForResult is called on.
//
// NOTE: Since this runs a message loop to wait for the completion callback,
// there could be other side-effects resulting from WaitForResult.  For this
// reason, this class is probably not ideal for a general application.
//
namespace base {
class RunLoop;
}

namespace net {
class IOBuffer;
}

namespace storage {

namespace internal {

class STORAGE_EXPORT IOCompletionCallbackBaseInternal {
 public:
  bool have_result() const { return have_result_; }

 protected:
  IOCompletionCallbackBaseInternal();
  virtual ~IOCompletionCallbackBaseInternal();

  void DidSetResult();
  void WaitForResult();

 private:
  // RunLoop.  Only non-NULL during the call to WaitForResult, so the class is
  // reusable.
  //std::unique_ptr<base::RunLoop> run_loop_;
  std::unique_ptr<base::WaitableEvent> event_;
  bool have_result_;

  DISALLOW_COPY_AND_ASSIGN(IOCompletionCallbackBaseInternal);
};

template <typename R>
class IOCompletionCallbackTemplate
    : public IOCompletionCallbackBaseInternal {
 public:
  virtual ~IOCompletionCallbackTemplate() override {}

  R WaitForResult() {
    IOCompletionCallbackBaseInternal::WaitForResult();
    return result_;
  }

  R GetResult(R result) {
    if (net::ERR_IO_PENDING != result)
      return result;
    return WaitForResult();
  }

 protected:
  IOCompletionCallbackTemplate() : result_(R()) {}

  // Override this method to gain control as the callback is running.
  virtual void SetResult(R result) {
    result_ = result;
    DidSetResult();
  }

 private:
  R result_;

  DISALLOW_COPY_AND_ASSIGN(IOCompletionCallbackTemplate);
};

}  // namespace internal

class IOClosure : public internal::IOCompletionCallbackBaseInternal {
 public:
  using internal::IOCompletionCallbackBaseInternal::WaitForResult;

  IOClosure();
  ~IOClosure() override;

  const base::Closure& closure() const { return closure_; }

 private:
  const base::Closure closure_;

  DISALLOW_COPY_AND_ASSIGN(IOClosure);
};

// Base class overridden by custom implementations of TestCompletionCallback.
typedef internal::IOCompletionCallbackTemplate<int>
    IOCompletionCallbackBase;

class STORAGE_EXPORT IOCompletionCallback : public IOCompletionCallbackBase {
 public:
  IOCompletionCallback();
  ~IOCompletionCallback() override;

  const net::CompletionCallback& callback() const { return callback_; }

 private:
  const net::CompletionCallback callback_;

  DISALLOW_COPY_AND_ASSIGN(IOCompletionCallback);
};

// Makes sure that the buffer is not referenced when the callback runs.
class STORAGE_EXPORT IOReleaseBufferCompletionCallback: public IOCompletionCallback {
 public:
  explicit IOReleaseBufferCompletionCallback(net::IOBuffer* buffer);
  ~IOReleaseBufferCompletionCallback() override;

 private:
  void SetResult(int result) override;

  net::IOBuffer* buffer_;
  DISALLOW_COPY_AND_ASSIGN(IOReleaseBufferCompletionCallback);
};

}  // namespace storage

#endif  // STORAGE_COMPLETION_CALLBACK_H_
