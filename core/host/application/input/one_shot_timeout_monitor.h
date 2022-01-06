// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_APPLICATION_INPUT_ONE_SHOT_TIMEOUT_MONITOR_H_
#define MUMBA_HOST_APPLICATION_INPUT_ONE_SHOT_TIMEOUT_MONITOR_H_

#include "base/callback.h"
#include "base/macros.h"
#include "base/time/time.h"
#include "base/timer/timer.h"
#include "core/shared/common/content_export.h"

namespace host {

// Utility class for handling a timeout callback that can only be used once.
// This is effectively a wrapper for base::OneShotTimer that allows use of a
// base::OnceClosure.
class CONTENT_EXPORT OneShotTimeoutMonitor {
 public:
  typedef base::OnceClosure TimeoutHandler;

  // The timer starts upon construction.
  explicit OneShotTimeoutMonitor(TimeoutHandler timeout_handler,
                                 base::TimeDelta delay);
  ~OneShotTimeoutMonitor();

 private:
  void Start();
  void TimedOut();

  TimeoutHandler timeout_handler_;
  base::TimeDelta delay_;

  // This timer runs to check if |time_when_considered_timed_out_| has past.
  base::OneShotTimer timeout_timer_;

  DISALLOW_COPY_AND_ASSIGN(OneShotTimeoutMonitor);
};

}  // namespace host

#endif  // MUMBA_HOST_APPLICATION_INPUT_ONE_SHOT_TIMEOUT_MONITOR_H_
