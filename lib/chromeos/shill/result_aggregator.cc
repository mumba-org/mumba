// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/result_aggregator.h"

#include "shill/event_dispatcher.h"
#include "shill/logging.h"

//#include <base/check.h>
#include <base/logging.h>
#include <base/time/time.h>

namespace shill {

ResultAggregator::ResultAggregator(const ResultCallback& callback)
    : ResultAggregator(callback, nullptr, base::TimeDelta()) {}

ResultAggregator::ResultAggregator(const ResultCallback& callback,
                                   EventDispatcher* dispatcher,
                                   base::TimeDelta timeout)
    : weak_ptr_factory_(this),
      callback_(callback),
      timeout_callback_(base::Bind(&ResultAggregator::Timeout,
                                   weak_ptr_factory_.GetWeakPtr())),
      got_result_(false),
      timed_out_(false) {
  CHECK(!callback.is_null());
  if (dispatcher) {
    dispatcher->PostDelayedTask(FROM_HERE, timeout_callback_.callback(),
                                timeout);
  }
}

ResultAggregator::~ResultAggregator() {
  if (got_result_ && !timed_out_) {
    callback_.Run(error_);
  }
  // timeout_callback_ will automatically be canceled when its destructor
  // is invoked.
}

void ResultAggregator::ReportResult(const Error& error) {
  LOG(INFO) << "Error type " << error << " reported";
  CHECK(!error.IsOngoing());  // We want the final result.
  got_result_ = true;
  if (error_.IsSuccess()) {  // Only copy first |error|.
    error_.CopyFrom(error);
  } else {
    LOG(WARNING) << "Dropping error type " << error;
  }
}

void ResultAggregator::Timeout() {
  LOG(WARNING) << "Results aggregator timed out";
  timed_out_ = true;
  error_.Populate(Error::kOperationTimeout);
  callback_.Run(error_);
}

}  // namespace shill
