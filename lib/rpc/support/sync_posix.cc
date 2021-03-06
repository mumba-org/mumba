/*
 *
 * Copyright 2015 gRPC authors.
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

#include <rpc/support/port_platform.h>

#ifdef GPR_POSIX_SYNC

#include <errno.h>
#include <rpc/support/log.h>
#include <rpc/support/sync.h>
#include <rpc/support/time.h>
#include <time.h>
#include "rpc/profiling/timers.h"

#ifdef GPR_LOW_LEVEL_COUNTERS
gpr_atm gpr_mu_locks = 0;
gpr_atm gpr_counter_atm_cas = 0;
gpr_atm gpr_counter_atm_add = 0;
#endif

void gpr_mu_init(gpr_mu* mu) {
  GPR_ASSERT(pthread_mutex_init(mu, nullptr) == 0);
}

void gpr_mu_destroy(gpr_mu* mu) { GPR_ASSERT(pthread_mutex_destroy(mu) == 0); }

void gpr_mu_lock(gpr_mu* mu) {
#ifdef GPR_LOW_LEVEL_COUNTERS
  GPR_ATM_INC_COUNTER(gpr_mu_locks);
#endif
  GPR_TIMER_BEGIN("gpr_mu_lock", 0);
  GPR_ASSERT(pthread_mutex_lock(mu) == 0);
  GPR_TIMER_END("gpr_mu_lock", 0);
}

void gpr_mu_unlock(gpr_mu* mu) {
  GPR_TIMER_BEGIN("gpr_mu_unlock", 0);
  GPR_ASSERT(pthread_mutex_unlock(mu) == 0);
  GPR_TIMER_END("gpr_mu_unlock", 0);
}

int gpr_mu_trylock(gpr_mu* mu) {
  int err;
  GPR_TIMER_BEGIN("gpr_mu_trylock", 0);
  err = pthread_mutex_trylock(mu);
  GPR_ASSERT(err == 0 || err == EBUSY);
  GPR_TIMER_END("gpr_mu_trylock", 0);
  return err == 0;
}

/*----------------------------------------*/

void gpr_cv_init(gpr_cv* cv) {
  GPR_ASSERT(pthread_cond_init(cv, nullptr) == 0);
}

void gpr_cv_destroy(gpr_cv* cv) { GPR_ASSERT(pthread_cond_destroy(cv) == 0); }

int gpr_cv_wait(gpr_cv* cv, gpr_mu* mu, gpr_timespec abs_deadline) {
  int err = 0;
  if (gpr_time_cmp(abs_deadline, gpr_inf_future(abs_deadline.clock_type)) ==
      0) {
    err = pthread_cond_wait(cv, mu);
  } else {
    struct timespec abs_deadline_ts;
    abs_deadline = gpr_convert_clock_type(abs_deadline, GPR_CLOCK_REALTIME);
    abs_deadline_ts.tv_sec = (time_t)abs_deadline.tv_sec;
    abs_deadline_ts.tv_nsec = abs_deadline.tv_nsec;
    err = pthread_cond_timedwait(cv, mu, &abs_deadline_ts);
  }
  GPR_ASSERT(err == 0 || err == ETIMEDOUT || err == EAGAIN);
  return err == ETIMEDOUT;
}

void gpr_cv_signal(gpr_cv* cv) { GPR_ASSERT(pthread_cond_signal(cv) == 0); }

void gpr_cv_broadcast(gpr_cv* cv) {
  GPR_ASSERT(pthread_cond_broadcast(cv) == 0);
}

/*----------------------------------------*/

void gpr_once_init(gpr_once* once, void (*init_function)(void)) {
  GPR_ASSERT(pthread_once(once, init_function) == 0);
}

#endif /* GRP_POSIX_SYNC */
