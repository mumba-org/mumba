/*
 *
 * Copyright 2016 gRPC authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#ifndef GRPC_CORE_LIB_TRANSPORT_BDP_ESTIMATOR_H
#define GRPC_CORE_LIB_TRANSPORT_BDP_ESTIMATOR_H

#include <rpc/support/port_platform.h>

#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>

#include <rpc/support/log.h>
#include <rpc/support/time.h>

#include "rpc/debug/trace.h"
#include "rpc/iomgr/exec_ctx.h"

extern grpc_core::TraceFlag grpc_bdp_estimator_trace;

namespace grpc_core {

class BdpEstimator {
 public:
  explicit BdpEstimator(const char* name);
  ~BdpEstimator() {}

  int64_t EstimateBdp() const { return estimate_; }
  double EstimateBandwidth() const { return bw_est_; }

  void AddIncomingBytes(int64_t num_bytes) { accumulator_ += num_bytes; }

  // Schedule a ping: call in response to receiving a true from
  // grpc_bdp_estimator_add_incoming_bytes once a ping has been scheduled by a
  // transport (but not necessarily started)
  void SchedulePing() {
    if (grpc_bdp_estimator_trace.enabled()) {
      gpr_log(GPR_DEBUG, "bdp[%s]:sched acc=%" PRId64 " est=%" PRId64, name_,
              accumulator_, estimate_);
    }
    GPR_ASSERT(ping_state_ == PingState::UNSCHEDULED);
    ping_state_ = PingState::SCHEDULED;
    accumulator_ = 0;
  }

  // Start a ping: call after calling grpc_bdp_estimator_schedule_ping and
  // once
  // the ping is on the wire
  void StartPing() {
    if (grpc_bdp_estimator_trace.enabled()) {
      gpr_log(GPR_DEBUG, "bdp[%s]:start acc=%" PRId64 " est=%" PRId64, name_,
              accumulator_, estimate_);
    }
    GPR_ASSERT(ping_state_ == PingState::SCHEDULED);
    ping_state_ = PingState::STARTED;
    accumulator_ = 0;
    ping_start_time_ = gpr_now(GPR_CLOCK_MONOTONIC);
  }

  // Completes a previously started ping, returns when to schedule the next one
  grpc_millis CompletePing(grpc_exec_ctx* exec_ctx);

 private:
  enum class PingState { UNSCHEDULED, SCHEDULED, STARTED };

  PingState ping_state_;
  int64_t accumulator_;
  int64_t estimate_;
  // when was the current ping started?
  gpr_timespec ping_start_time_;
  int inter_ping_delay_;
  int stable_estimate_count_;
  double bw_est_;
  const char* name_;
};

}  // namespace grpc_core

#endif /* GRPC_CORE_LIB_TRANSPORT_BDP_ESTIMATOR_H */
