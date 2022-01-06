/*
 * Copyright (c) 2008-2013 Apple Inc. All rights reserved.
 *
 * @APPLE_APACHE_LICENSE_HEADER_START@
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
 * @APPLE_APACHE_LICENSE_HEADER_END@
 */

#include "internal.h"
#if HAVE_MACH
#include "protocol.h" // _dispatch_send_wakeup_runloop_thread
#endif

#if HAVE_PTHREAD_WORKQUEUES || DISPATCH_USE_INTERNAL_WORKQUEUE
#define DISPATCH_USE_WORKQUEUES 1
#endif
#if (!HAVE_PTHREAD_WORKQUEUES || DISPATCH_DEBUG) && \
		!defined(DISPATCH_ENABLE_THREAD_POOL)
#define DISPATCH_ENABLE_THREAD_POOL 1
#endif
#if DISPATCH_ENABLE_PTHREAD_ROOT_QUEUES || DISPATCH_ENABLE_THREAD_POOL
#define DISPATCH_USE_PTHREAD_POOL 1
#endif
#if HAVE_PTHREAD_WORKQUEUES && (!HAVE_PTHREAD_WORKQUEUE_QOS || \
		DISPATCH_DEBUG) && !HAVE_PTHREAD_WORKQUEUE_SETDISPATCH_NP && \
		!defined(DISPATCH_USE_LEGACY_WORKQUEUE_FALLBACK)
#define DISPATCH_USE_LEGACY_WORKQUEUE_FALLBACK 1
#endif
#if HAVE_PTHREAD_WORKQUEUE_SETDISPATCH_NP && (DISPATCH_DEBUG || \
		(!DISPATCH_USE_KEVENT_WORKQUEUE && !HAVE_PTHREAD_WORKQUEUE_QOS)) && \
		!defined(DISPATCH_USE_PTHREAD_WORKQUEUE_SETDISPATCH_NP)
#define DISPATCH_USE_PTHREAD_WORKQUEUE_SETDISPATCH_NP 1
#endif
#if DISPATCH_USE_PTHREAD_WORKQUEUE_SETDISPATCH_NP || \
		DISPATCH_USE_LEGACY_WORKQUEUE_FALLBACK || \
		DISPATCH_USE_INTERNAL_WORKQUEUE
#if !DISPATCH_USE_INTERNAL_WORKQUEUE
#define DISPATCH_USE_WORKQ_PRIORITY 1
#endif
#define DISPATCH_USE_WORKQ_OPTIONS 1
#endif

#if DISPATCH_USE_WORKQUEUES && DISPATCH_USE_PTHREAD_POOL && \
		!DISPATCH_USE_LEGACY_WORKQUEUE_FALLBACK
#define pthread_workqueue_t void*
#endif

static void _dispatch_sig_thread(void *ctxt);
static void DISPATCH_TSD_DTOR_CC _dispatch_cache_cleanup(void *value);
static void _dispatch_async_f2(dispatch_queue_t dq, dispatch_continuation_t dc);
static void DISPATCH_TSD_DTOR_CC _dispatch_queue_cleanup(void *ctxt);
static void DISPATCH_TSD_DTOR_CC _dispatch_wlh_cleanup(void *ctxt);
static void DISPATCH_TSD_DTOR_CC _dispatch_deferred_items_cleanup(void *ctxt);
static void DISPATCH_TSD_DTOR_CC _dispatch_frame_cleanup(void *ctxt);
static void DISPATCH_TSD_DTOR_CC _dispatch_context_cleanup(void *ctxt);
static void _dispatch_queue_barrier_complete(dispatch_queue_t dq,
		dispatch_qos_t qos, dispatch_wakeup_flags_t flags);
static void _dispatch_queue_non_barrier_complete(dispatch_queue_t dq);
static void _dispatch_queue_push_sync_waiter(dispatch_queue_t dq,
		dispatch_sync_context_t dsc, dispatch_qos_t qos);
#if HAVE_PTHREAD_WORKQUEUE_QOS
static void _dispatch_root_queue_push_override_stealer(dispatch_queue_t orig_rq,
		dispatch_queue_t dq, dispatch_qos_t qos);
static inline void _dispatch_queue_class_wakeup_with_override(dispatch_queue_t,
		uint64_t dq_state, dispatch_wakeup_flags_t flags);
#endif
#if HAVE_PTHREAD_WORKQUEUES
static void _dispatch_worker_thread4(void *context);
#if HAVE_PTHREAD_WORKQUEUE_QOS
static void _dispatch_worker_thread3(pthread_priority_t priority);
#endif
#if DISPATCH_USE_PTHREAD_WORKQUEUE_SETDISPATCH_NP
static void _dispatch_worker_thread2(int priority, int options, void *context);
#endif
#endif
#if DISPATCH_USE_PTHREAD_POOL
static void *_dispatch_worker_thread(void *context);
#if defined(_WIN32)
static unsigned WINAPI
_dispatch_worker_thread_thunk(LPVOID lpParameter);
#endif
#endif

#if DISPATCH_COCOA_COMPAT
static dispatch_once_t _dispatch_main_q_handle_pred;
static void _dispatch_runloop_queue_poke(dispatch_queue_t dq,
		dispatch_qos_t qos, dispatch_wakeup_flags_t flags);
static void _dispatch_runloop_queue_handle_init(void *ctxt);
static void _dispatch_runloop_queue_handle_dispose(dispatch_queue_t dq);
#endif

#pragma mark -
#pragma mark dispatch_root_queue

struct dispatch_pthread_root_queue_context_s {
#if !defined(_WIN32)
	pthread_attr_t dpq_thread_attr;
#endif
	dispatch_block_t dpq_thread_configure;
	struct dispatch_semaphore_s dpq_thread_mediator;
	dispatch_pthread_root_queue_observer_hooks_s dpq_observer_hooks;
};
typedef struct dispatch_pthread_root_queue_context_s *
		dispatch_pthread_root_queue_context_t;

#if DISPATCH_ENABLE_THREAD_POOL
static struct dispatch_pthread_root_queue_context_s
		_dispatch_pthread_root_queue_contexts[] = {
	[DISPATCH_ROOT_QUEUE_IDX_MAINTENANCE_QOS] = {
		.dpq_thread_mediator = {
			DISPATCH_GLOBAL_OBJECT_HEADER(semaphore),
	}},
	[DISPATCH_ROOT_QUEUE_IDX_MAINTENANCE_QOS_OVERCOMMIT] = {
		.dpq_thread_mediator = {
			DISPATCH_GLOBAL_OBJECT_HEADER(semaphore),
	}},
	[DISPATCH_ROOT_QUEUE_IDX_BACKGROUND_QOS] = {
		.dpq_thread_mediator = {
			DISPATCH_GLOBAL_OBJECT_HEADER(semaphore),
	}},
	[DISPATCH_ROOT_QUEUE_IDX_BACKGROUND_QOS_OVERCOMMIT] = {
		.dpq_thread_mediator = {
			DISPATCH_GLOBAL_OBJECT_HEADER(semaphore),
	}},
	[DISPATCH_ROOT_QUEUE_IDX_UTILITY_QOS] = {
		.dpq_thread_mediator = {
			DISPATCH_GLOBAL_OBJECT_HEADER(semaphore),
	}},
	[DISPATCH_ROOT_QUEUE_IDX_UTILITY_QOS_OVERCOMMIT] = {
		.dpq_thread_mediator = {
			DISPATCH_GLOBAL_OBJECT_HEADER(semaphore),
	}},
	[DISPATCH_ROOT_QUEUE_IDX_DEFAULT_QOS] = {
		.dpq_thread_mediator = {
			DISPATCH_GLOBAL_OBJECT_HEADER(semaphore),
	}},
	[DISPATCH_ROOT_QUEUE_IDX_DEFAULT_QOS_OVERCOMMIT] = {
		.dpq_thread_mediator = {
			DISPATCH_GLOBAL_OBJECT_HEADER(semaphore),
	}},
	[DISPATCH_ROOT_QUEUE_IDX_USER_INITIATED_QOS] = {
		.dpq_thread_mediator = {
			DISPATCH_GLOBAL_OBJECT_HEADER(semaphore),
	}},
	[DISPATCH_ROOT_QUEUE_IDX_USER_INITIATED_QOS_OVERCOMMIT] = {
		.dpq_thread_mediator = {
			DISPATCH_GLOBAL_OBJECT_HEADER(semaphore),
	}},
	[DISPATCH_ROOT_QUEUE_IDX_USER_INTERACTIVE_QOS] = {
		.dpq_thread_mediator = {
			DISPATCH_GLOBAL_OBJECT_HEADER(semaphore),
	}},
	[DISPATCH_ROOT_QUEUE_IDX_USER_INTERACTIVE_QOS_OVERCOMMIT] = {
		.dpq_thread_mediator = {
			DISPATCH_GLOBAL_OBJECT_HEADER(semaphore),
	}},
};
#endif

#ifndef DISPATCH_WORKQ_MAX_PTHREAD_COUNT
#define DISPATCH_WORKQ_MAX_PTHREAD_COUNT 255
#endif

struct dispatch_root_queue_context_s {
	union {
		struct {
			int volatile dgq_pending;
#if DISPATCH_USE_WORKQUEUES
			qos_class_t dgq_qos;
#if DISPATCH_USE_WORKQ_PRIORITY
			int dgq_wq_priority;
#endif
#if DISPATCH_USE_WORKQ_OPTIONS
			int dgq_wq_options;
#endif
#if DISPATCH_USE_LEGACY_WORKQUEUE_FALLBACK || DISPATCH_USE_PTHREAD_POOL
			pthread_workqueue_t dgq_kworkqueue;
#endif
#endif // DISPATCH_USE_WORKQUEUES
#if DISPATCH_USE_PTHREAD_POOL
			void *dgq_ctxt;
			int32_t volatile dgq_thread_pool_size;
#endif
		};
		char _dgq_pad[DISPATCH_CACHELINE_SIZE];
	};
};
typedef struct dispatch_root_queue_context_s *dispatch_root_queue_context_t;

#define WORKQ_PRIO_INVALID (-1)
#ifndef WORKQ_BG_PRIOQUEUE_CONDITIONAL
#define WORKQ_BG_PRIOQUEUE_CONDITIONAL WORKQ_PRIO_INVALID
#endif
#ifndef WORKQ_HIGH_PRIOQUEUE_CONDITIONAL
#define WORKQ_HIGH_PRIOQUEUE_CONDITIONAL WORKQ_PRIO_INVALID
#endif

DISPATCH_CACHELINE_ALIGN
static struct dispatch_root_queue_context_s _dispatch_root_queue_contexts[] = {
	[DISPATCH_ROOT_QUEUE_IDX_MAINTENANCE_QOS] = {{{
#if DISPATCH_USE_WORKQUEUES
		.dgq_qos = QOS_CLASS_MAINTENANCE,
#if DISPATCH_USE_WORKQ_PRIORITY
		.dgq_wq_priority = WORKQ_BG_PRIOQUEUE,
#endif
#if DISPATCH_USE_WORKQ_OPTIONS
		.dgq_wq_options = 0,
#endif
#endif
#if DISPATCH_ENABLE_THREAD_POOL
		.dgq_ctxt = &_dispatch_pthread_root_queue_contexts[
				DISPATCH_ROOT_QUEUE_IDX_MAINTENANCE_QOS],
#endif
	}}},
	[DISPATCH_ROOT_QUEUE_IDX_MAINTENANCE_QOS_OVERCOMMIT] = {{{
#if DISPATCH_USE_WORKQUEUES
		.dgq_qos = QOS_CLASS_MAINTENANCE,
#if DISPATCH_USE_WORKQ_PRIORITY
		.dgq_wq_priority = WORKQ_BG_PRIOQUEUE,
#endif
#if DISPATCH_USE_WORKQ_OPTIONS
		.dgq_wq_options = WORKQ_ADDTHREADS_OPTION_OVERCOMMIT,
#endif
#endif
#if DISPATCH_ENABLE_THREAD_POOL
		.dgq_ctxt = &_dispatch_pthread_root_queue_contexts[
				DISPATCH_ROOT_QUEUE_IDX_MAINTENANCE_QOS_OVERCOMMIT],
#endif
	}}},
	[DISPATCH_ROOT_QUEUE_IDX_BACKGROUND_QOS] = {{{
#if DISPATCH_USE_WORKQUEUES
		.dgq_qos = QOS_CLASS_BACKGROUND,
#if DISPATCH_USE_WORKQ_PRIORITY
		.dgq_wq_priority = WORKQ_BG_PRIOQUEUE_CONDITIONAL,
#endif
#if DISPATCH_USE_WORKQ_OPTIONS
		.dgq_wq_options = 0,
#endif
#endif
#if DISPATCH_ENABLE_THREAD_POOL
		.dgq_ctxt = &_dispatch_pthread_root_queue_contexts[
				DISPATCH_ROOT_QUEUE_IDX_BACKGROUND_QOS],
#endif
	}}},
	[DISPATCH_ROOT_QUEUE_IDX_BACKGROUND_QOS_OVERCOMMIT] = {{{
#if DISPATCH_USE_WORKQUEUES
		.dgq_qos = QOS_CLASS_BACKGROUND,
#if DISPATCH_USE_WORKQ_PRIORITY
		.dgq_wq_priority = WORKQ_BG_PRIOQUEUE_CONDITIONAL,
#endif
#if DISPATCH_USE_WORKQ_OPTIONS
		.dgq_wq_options = WORKQ_ADDTHREADS_OPTION_OVERCOMMIT,
#endif
#endif
#if DISPATCH_ENABLE_THREAD_POOL
		.dgq_ctxt = &_dispatch_pthread_root_queue_contexts[
				DISPATCH_ROOT_QUEUE_IDX_BACKGROUND_QOS_OVERCOMMIT],
#endif
	}}},
	[DISPATCH_ROOT_QUEUE_IDX_UTILITY_QOS] = {{{
#if DISPATCH_USE_WORKQUEUES
		.dgq_qos = QOS_CLASS_UTILITY,
#if DISPATCH_USE_WORKQ_PRIORITY
		.dgq_wq_priority = WORKQ_LOW_PRIOQUEUE,
#endif
#if DISPATCH_USE_WORKQ_OPTIONS
		.dgq_wq_options = 0,
#endif
#endif
#if DISPATCH_ENABLE_THREAD_POOL
		.dgq_ctxt = &_dispatch_pthread_root_queue_contexts[
				DISPATCH_ROOT_QUEUE_IDX_UTILITY_QOS],
#endif
	}}},
	[DISPATCH_ROOT_QUEUE_IDX_UTILITY_QOS_OVERCOMMIT] = {{{
#if DISPATCH_USE_WORKQUEUES
		.dgq_qos = QOS_CLASS_UTILITY,
#if DISPATCH_USE_WORKQ_PRIORITY
		.dgq_wq_priority = WORKQ_LOW_PRIOQUEUE,
#endif
#if DISPATCH_USE_WORKQ_OPTIONS
		.dgq_wq_options = WORKQ_ADDTHREADS_OPTION_OVERCOMMIT,
#endif
#endif
#if DISPATCH_ENABLE_THREAD_POOL
		.dgq_ctxt = &_dispatch_pthread_root_queue_contexts[
				DISPATCH_ROOT_QUEUE_IDX_UTILITY_QOS_OVERCOMMIT],
#endif
	}}},
	[DISPATCH_ROOT_QUEUE_IDX_DEFAULT_QOS] = {{{
#if DISPATCH_USE_WORKQUEUES
		.dgq_qos = QOS_CLASS_DEFAULT,
#if DISPATCH_USE_WORKQ_PRIORITY
		.dgq_wq_priority = WORKQ_DEFAULT_PRIOQUEUE,
#endif
#if DISPATCH_USE_WORKQ_OPTIONS
		.dgq_wq_options = 0,
#endif
#endif
#if DISPATCH_ENABLE_THREAD_POOL
		.dgq_ctxt = &_dispatch_pthread_root_queue_contexts[
				DISPATCH_ROOT_QUEUE_IDX_DEFAULT_QOS],
#endif
	}}},
	[DISPATCH_ROOT_QUEUE_IDX_DEFAULT_QOS_OVERCOMMIT] = {{{
#if DISPATCH_USE_WORKQUEUES
		.dgq_qos = QOS_CLASS_DEFAULT,
#if DISPATCH_USE_WORKQ_PRIORITY
		.dgq_wq_priority = WORKQ_DEFAULT_PRIOQUEUE,
#endif
#if DISPATCH_USE_WORKQ_OPTIONS
		.dgq_wq_options = WORKQ_ADDTHREADS_OPTION_OVERCOMMIT,
#endif
#endif
#if DISPATCH_ENABLE_THREAD_POOL
		.dgq_ctxt = &_dispatch_pthread_root_queue_contexts[
				DISPATCH_ROOT_QUEUE_IDX_DEFAULT_QOS_OVERCOMMIT],
#endif
	}}},
	[DISPATCH_ROOT_QUEUE_IDX_USER_INITIATED_QOS] = {{{
#if DISPATCH_USE_WORKQUEUES
		.dgq_qos = QOS_CLASS_USER_INITIATED,
#if DISPATCH_USE_WORKQ_PRIORITY
		.dgq_wq_priority = WORKQ_HIGH_PRIOQUEUE,
#endif
#if DISPATCH_USE_WORKQ_OPTIONS
		.dgq_wq_options = 0,
#endif
#endif
#if DISPATCH_ENABLE_THREAD_POOL
		.dgq_ctxt = &_dispatch_pthread_root_queue_contexts[
				DISPATCH_ROOT_QUEUE_IDX_USER_INITIATED_QOS],
#endif
	}}},
	[DISPATCH_ROOT_QUEUE_IDX_USER_INITIATED_QOS_OVERCOMMIT] = {{{
#if DISPATCH_USE_WORKQUEUES
		.dgq_qos = QOS_CLASS_USER_INITIATED,
#if DISPATCH_USE_WORKQ_PRIORITY
		.dgq_wq_priority = WORKQ_HIGH_PRIOQUEUE,
#endif
#if DISPATCH_USE_WORKQ_OPTIONS
		.dgq_wq_options = WORKQ_ADDTHREADS_OPTION_OVERCOMMIT,
#endif
#endif
#if DISPATCH_ENABLE_THREAD_POOL
		.dgq_ctxt = &_dispatch_pthread_root_queue_contexts[
				DISPATCH_ROOT_QUEUE_IDX_USER_INITIATED_QOS_OVERCOMMIT],
#endif
	}}},
	[DISPATCH_ROOT_QUEUE_IDX_USER_INTERACTIVE_QOS] = {{{
#if DISPATCH_USE_WORKQUEUES
		.dgq_qos = QOS_CLASS_USER_INTERACTIVE,
#if DISPATCH_USE_WORKQ_PRIORITY
		.dgq_wq_priority = WORKQ_HIGH_PRIOQUEUE_CONDITIONAL,
#endif
#if DISPATCH_USE_WORKQ_OPTIONS
		.dgq_wq_options = 0,
#endif
#endif
#if DISPATCH_ENABLE_THREAD_POOL
		.dgq_ctxt = &_dispatch_pthread_root_queue_contexts[
				DISPATCH_ROOT_QUEUE_IDX_USER_INTERACTIVE_QOS],
#endif
	}}},
	[DISPATCH_ROOT_QUEUE_IDX_USER_INTERACTIVE_QOS_OVERCOMMIT] = {{{
#if DISPATCH_USE_WORKQUEUES
		.dgq_qos = QOS_CLASS_USER_INTERACTIVE,
#if DISPATCH_USE_WORKQ_PRIORITY
		.dgq_wq_priority = WORKQ_HIGH_PRIOQUEUE_CONDITIONAL,
#endif
#if DISPATCH_USE_WORKQ_OPTIONS
		.dgq_wq_options = WORKQ_ADDTHREADS_OPTION_OVERCOMMIT,
#endif
#endif
#if DISPATCH_ENABLE_THREAD_POOL
		.dgq_ctxt = &_dispatch_pthread_root_queue_contexts[
				DISPATCH_ROOT_QUEUE_IDX_USER_INTERACTIVE_QOS_OVERCOMMIT],
#endif
	}}},
};

// 6618342 Contact the team that owns the Instrument DTrace probe before
//         renaming this symbol
DISPATCH_CACHELINE_ALIGN
struct dispatch_queue_s _dispatch_root_queues[] = {
#define _DISPATCH_ROOT_QUEUE_IDX(n, flags) \
	((flags & DISPATCH_PRIORITY_FLAG_OVERCOMMIT) ? \
		DISPATCH_ROOT_QUEUE_IDX_##n##_QOS_OVERCOMMIT : \
		DISPATCH_ROOT_QUEUE_IDX_##n##_QOS)
#define _DISPATCH_ROOT_QUEUE_ENTRY(n, flags, ...) \
	[_DISPATCH_ROOT_QUEUE_IDX(n, flags)] = { \
		DISPATCH_GLOBAL_OBJECT_HEADER(queue_root), \
		.dq_state = DISPATCH_ROOT_QUEUE_STATE_INIT_VALUE, \
		.do_ctxt = &_dispatch_root_queue_contexts[ \
				_DISPATCH_ROOT_QUEUE_IDX(n, flags)], \
		.dq_atomic_flags = DQF_WIDTH(DISPATCH_QUEUE_WIDTH_POOL), \
		.dq_priority = _dispatch_priority_make(DISPATCH_QOS_##n, 0) | flags | \
				DISPATCH_PRIORITY_FLAG_ROOTQUEUE | \
				((flags & DISPATCH_PRIORITY_FLAG_DEFAULTQUEUE) ? 0 : \
				DISPATCH_QOS_##n << DISPATCH_PRIORITY_OVERRIDE_SHIFT), \
		__VA_ARGS__ \
	}
	_DISPATCH_ROOT_QUEUE_ENTRY(MAINTENANCE, 0,
		.dq_label = "com.apple.root.maintenance-qos",
		.dq_serialnum = 4,
	),
	_DISPATCH_ROOT_QUEUE_ENTRY(MAINTENANCE, DISPATCH_PRIORITY_FLAG_OVERCOMMIT,
		.dq_label = "com.apple.root.maintenance-qos.overcommit",
		.dq_serialnum = 5,
	),
	_DISPATCH_ROOT_QUEUE_ENTRY(BACKGROUND, 0,
		.dq_label = "com.apple.root.background-qos",
		.dq_serialnum = 6,
	),
	_DISPATCH_ROOT_QUEUE_ENTRY(BACKGROUND, DISPATCH_PRIORITY_FLAG_OVERCOMMIT,
		.dq_label = "com.apple.root.background-qos.overcommit",
		.dq_serialnum = 7,
	),
	_DISPATCH_ROOT_QUEUE_ENTRY(UTILITY, 0,
		.dq_label = "com.apple.root.utility-qos",
		.dq_serialnum = 8,
	),
	_DISPATCH_ROOT_QUEUE_ENTRY(UTILITY, DISPATCH_PRIORITY_FLAG_OVERCOMMIT,
		.dq_label = "com.apple.root.utility-qos.overcommit",
		.dq_serialnum = 9,
	),
	_DISPATCH_ROOT_QUEUE_ENTRY(DEFAULT, DISPATCH_PRIORITY_FLAG_DEFAULTQUEUE,
		.dq_label = "com.apple.root.default-qos",
		.dq_serialnum = 10,
	),
	_DISPATCH_ROOT_QUEUE_ENTRY(DEFAULT,
			DISPATCH_PRIORITY_FLAG_DEFAULTQUEUE | DISPATCH_PRIORITY_FLAG_OVERCOMMIT,
		.dq_label = "com.apple.root.default-qos.overcommit",
		.dq_serialnum = 11,
	),
	_DISPATCH_ROOT_QUEUE_ENTRY(USER_INITIATED, 0,
		.dq_label = "com.apple.root.user-initiated-qos",
		.dq_serialnum = 12,
	),
	_DISPATCH_ROOT_QUEUE_ENTRY(USER_INITIATED, DISPATCH_PRIORITY_FLAG_OVERCOMMIT,
		.dq_label = "com.apple.root.user-initiated-qos.overcommit",
		.dq_serialnum = 13,
	),
	_DISPATCH_ROOT_QUEUE_ENTRY(USER_INTERACTIVE, 0,
		.dq_label = "com.apple.root.user-interactive-qos",
		.dq_serialnum = 14,
	),
	_DISPATCH_ROOT_QUEUE_ENTRY(USER_INTERACTIVE, DISPATCH_PRIORITY_FLAG_OVERCOMMIT,
		.dq_label = "com.apple.root.user-interactive-qos.overcommit",
		.dq_serialnum = 15,
	),
};

#if DISPATCH_USE_PTHREAD_WORKQUEUE_SETDISPATCH_NP
static const dispatch_queue_t _dispatch_wq2root_queues[][2] = {
	[WORKQ_BG_PRIOQUEUE][0] = &_dispatch_root_queues[
			DISPATCH_ROOT_QUEUE_IDX_BACKGROUND_QOS],
	[WORKQ_BG_PRIOQUEUE][WORKQ_ADDTHREADS_OPTION_OVERCOMMIT] =
			&_dispatch_root_queues[
			DISPATCH_ROOT_QUEUE_IDX_BACKGROUND_QOS_OVERCOMMIT],
	[WORKQ_LOW_PRIOQUEUE][0] = &_dispatch_root_queues[
			DISPATCH_ROOT_QUEUE_IDX_UTILITY_QOS],
	[WORKQ_LOW_PRIOQUEUE][WORKQ_ADDTHREADS_OPTION_OVERCOMMIT] =
			&_dispatch_root_queues[
			DISPATCH_ROOT_QUEUE_IDX_UTILITY_QOS_OVERCOMMIT],
	[WORKQ_DEFAULT_PRIOQUEUE][0] = &_dispatch_root_queues[
			DISPATCH_ROOT_QUEUE_IDX_DEFAULT_QOS],
	[WORKQ_DEFAULT_PRIOQUEUE][WORKQ_ADDTHREADS_OPTION_OVERCOMMIT] =
			&_dispatch_root_queues[
			DISPATCH_ROOT_QUEUE_IDX_DEFAULT_QOS_OVERCOMMIT],
	[WORKQ_HIGH_PRIOQUEUE][0] = &_dispatch_root_queues[
			DISPATCH_ROOT_QUEUE_IDX_USER_INITIATED_QOS],
	[WORKQ_HIGH_PRIOQUEUE][WORKQ_ADDTHREADS_OPTION_OVERCOMMIT] =
			&_dispatch_root_queues[
			DISPATCH_ROOT_QUEUE_IDX_USER_INITIATED_QOS_OVERCOMMIT],
};
#endif // DISPATCH_USE_PTHREAD_WORKQUEUE_SETDISPATCH_NP

#if DISPATCH_USE_MGR_THREAD && DISPATCH_ENABLE_PTHREAD_ROOT_QUEUES
static struct dispatch_queue_s _dispatch_mgr_root_queue;
#else
#define _dispatch_mgr_root_queue _dispatch_root_queues[\
		DISPATCH_ROOT_QUEUE_IDX_USER_INTERACTIVE_QOS_OVERCOMMIT]
#endif

// 6618342 Contact the team that owns the Instrument DTrace probe before
//         renaming this symbol
DISPATCH_CACHELINE_ALIGN
struct dispatch_queue_s _dispatch_mgr_q = {
	DISPATCH_GLOBAL_OBJECT_HEADER(queue_mgr),
	.dq_state = DISPATCH_QUEUE_STATE_INIT_VALUE(1) |
			DISPATCH_QUEUE_ROLE_BASE_ANON,
	.do_targetq = &_dispatch_mgr_root_queue,
	.dq_label = "com.apple.libdispatch-manager",
	.dq_atomic_flags = DQF_WIDTH(1),
	.dq_priority = DISPATCH_PRIORITY_FLAG_MANAGER |
			DISPATCH_PRIORITY_SATURATED_OVERRIDE,
	.dq_serialnum = 2,
};

dispatch_queue_t
dispatch_get_global_queue(long priority, unsigned long flags)
{
	if (flags & ~(unsigned long)DISPATCH_QUEUE_OVERCOMMIT) {
		return DISPATCH_BAD_INPUT;
	}
	dispatch_qos_t qos = _dispatch_qos_from_queue_priority(priority);
#if !HAVE_PTHREAD_WORKQUEUE_QOS
	if (qos == QOS_CLASS_MAINTENANCE) {
		qos = DISPATCH_QOS_BACKGROUND;
	} else if (qos == QOS_CLASS_USER_INTERACTIVE) {
		qos = DISPATCH_QOS_USER_INITIATED;
	}
#endif
	if (qos == DISPATCH_QOS_UNSPECIFIED) {
		return DISPATCH_BAD_INPUT;
	}
	return _dispatch_get_root_queue(qos, flags & DISPATCH_QUEUE_OVERCOMMIT);
}

DISPATCH_ALWAYS_INLINE
static inline dispatch_queue_t
_dispatch_get_current_queue(void)
{
	return _dispatch_queue_get_current() ?:
			_dispatch_get_root_queue(DISPATCH_QOS_DEFAULT, true);
}

dispatch_queue_t
dispatch_get_current_queue(void)
{
	return _dispatch_get_current_queue();
}

DISPATCH_NOINLINE DISPATCH_NORETURN
static void
_dispatch_assert_queue_fail(dispatch_queue_t dq, bool expected)
{
	_dispatch_client_assert_fail(
			"Block was %sexpected to execute on queue [%s]",
			expected ? "" : "not ", dq->dq_label ?: "");
}

DISPATCH_NOINLINE DISPATCH_NORETURN
static void
_dispatch_assert_queue_barrier_fail(dispatch_queue_t dq)
{
	_dispatch_client_assert_fail(
			"Block was expected to act as a barrier on queue [%s]",
			dq->dq_label ?: "");
}

void
dispatch_assert_queue(dispatch_queue_t dq)
{
	unsigned long metatype = dx_metatype(dq);
	if (unlikely(metatype != _DISPATCH_QUEUE_TYPE)) {
		DISPATCH_CLIENT_CRASH(metatype, "invalid queue passed to "
				"dispatch_assert_queue()");
	}
	uint64_t dq_state = os_atomic_load2o(dq, dq_state, relaxed);
	if (likely(_dq_state_drain_locked_by_self(dq_state))) {
		return;
	}
	// we can look at the width: if it is changing while we read it,
	// it means that a barrier is running on `dq` concurrently, which
	// proves that we're not on `dq`. Hence reading a stale '1' is ok.
	//
	// However if we can have thread bound queues, these mess with lock
	// ownership and we always have to take the slowpath
	if (likely(DISPATCH_COCOA_COMPAT || dq->dq_width > 1)) {
		if (likely(_dispatch_thread_frame_find_queue(dq))) {
			return;
		}
	}
	_dispatch_assert_queue_fail(dq, true);
}

void
dispatch_assert_queue_not(dispatch_queue_t dq)
{
	unsigned long metatype = dx_metatype(dq);
	if (unlikely(metatype != _DISPATCH_QUEUE_TYPE)) {
		DISPATCH_CLIENT_CRASH(metatype, "invalid queue passed to "
				"dispatch_assert_queue_not()");
	}
	uint64_t dq_state = os_atomic_load2o(dq, dq_state, relaxed);
	if (likely(!_dq_state_drain_locked_by_self(dq_state))) {
		// we can look at the width: if it is changing while we read it,
		// it means that a barrier is running on `dq` concurrently, which
		// proves that we're not on `dq`. Hence reading a stale '1' is ok.
		//
		// However if we can have thread bound queues, these mess with lock
		// ownership and we always have to take the slowpath
		if (likely(!DISPATCH_COCOA_COMPAT && dq->dq_width == 1)) {
			return;
		}
		if (likely(!_dispatch_thread_frame_find_queue(dq))) {
			return;
		}
	}
	_dispatch_assert_queue_fail(dq, false);
}

void
dispatch_assert_queue_barrier(dispatch_queue_t dq)
{
	dispatch_assert_queue(dq);

	if (likely(dq->dq_width == 1)) {
		return;
	}

	if (likely(dq->do_targetq)) {
		uint64_t dq_state = os_atomic_load2o(dq, dq_state, relaxed);
		if (likely(_dq_state_is_in_barrier(dq_state))) {
			return;
		}
	}

	_dispatch_assert_queue_barrier_fail(dq);
}

#if DISPATCH_DEBUG && DISPATCH_ROOT_QUEUE_DEBUG
#define _dispatch_root_queue_debug(...) _dispatch_debug(__VA_ARGS__)
#define _dispatch_debug_root_queue(...) dispatch_debug_queue(__VA_ARGS__)
#else
#define _dispatch_root_queue_debug(...)
#define _dispatch_debug_root_queue(...)
#endif

#pragma mark -
#pragma mark dispatch_init

static inline bool
_dispatch_root_queues_init_workq(int *wq_supported)
{
	int r; (void)r;
	bool result = false;
	*wq_supported = 0;
#if DISPATCH_USE_WORKQUEUES
	bool disable_wq = false; (void)disable_wq;
#if DISPATCH_ENABLE_THREAD_POOL && DISPATCH_DEBUG
	disable_wq = slowpath(getenv("LIBDISPATCH_DISABLE_KWQ"));
#endif
#if DISPATCH_USE_KEVENT_WORKQUEUE || HAVE_PTHREAD_WORKQUEUE_QOS
	bool disable_qos = false;
#if DISPATCH_DEBUG
	disable_qos = slowpath(getenv("LIBDISPATCH_DISABLE_QOS"));
#endif
#if DISPATCH_USE_KEVENT_WORKQUEUE
	bool disable_kevent_wq = false;
#if DISPATCH_DEBUG || DISPATCH_PROFILE
	disable_kevent_wq = slowpath(getenv("LIBDISPATCH_DISABLE_KEVENT_WQ"));
#endif
#endif

	if (!disable_wq && !disable_qos) {
		*wq_supported = _pthread_workqueue_supported();
#if DISPATCH_USE_KEVENT_WORKQUEUE
		if (!disable_kevent_wq && (*wq_supported & WORKQ_FEATURE_KEVENT)) {
			r = _pthread_workqueue_init_with_kevent(_dispatch_worker_thread3,
					(pthread_workqueue_function_kevent_t)
					_dispatch_kevent_worker_thread,
					offsetof(struct dispatch_queue_s, dq_serialnum), 0);
#if DISPATCH_USE_MGR_THREAD
			_dispatch_kevent_workqueue_enabled = !r;
#endif
			result = !r;
		} else
#endif // DISPATCH_USE_KEVENT_WORKQUEUE
		if (*wq_supported & WORKQ_FEATURE_FINEPRIO) {
#if DISPATCH_USE_MGR_THREAD
			r = _pthread_workqueue_init(_dispatch_worker_thread3,
					offsetof(struct dispatch_queue_s, dq_serialnum), 0);
			result = !r;
#endif
		}
		if (!(*wq_supported & WORKQ_FEATURE_MAINTENANCE)) {
			DISPATCH_INTERNAL_CRASH(*wq_supported,
					"QoS Maintenance support required");
		}
	}
#endif // DISPATCH_USE_KEVENT_WORKQUEUE || HAVE_PTHREAD_WORKQUEUE_QOS
#if DISPATCH_USE_PTHREAD_WORKQUEUE_SETDISPATCH_NP
	if (!result && !disable_wq) {
		pthread_workqueue_setdispatchoffset_np(
				offsetof(struct dispatch_queue_s, dq_serialnum));
		r = pthread_workqueue_setdispatch_np(_dispatch_worker_thread2);
#if !DISPATCH_USE_LEGACY_WORKQUEUE_FALLBACK
		(void)dispatch_assume_zero(r);
#endif
		result = !r;
	}
#endif // DISPATCH_USE_PTHREAD_WORKQUEUE_SETDISPATCH_NP
#if DISPATCH_USE_LEGACY_WORKQUEUE_FALLBACK || DISPATCH_USE_PTHREAD_POOL
	if (!result) {
#if DISPATCH_USE_LEGACY_WORKQUEUE_FALLBACK
		pthread_workqueue_attr_t pwq_attr;
		if (!disable_wq) {
			r = pthread_workqueue_attr_init_np(&pwq_attr);
			(void)dispatch_assume_zero(r);
		}
#endif
		size_t i;
		for (i = 0; i < DISPATCH_ROOT_QUEUE_COUNT; i++) {
			pthread_workqueue_t pwq = NULL;
			dispatch_root_queue_context_t qc;
			qc = &_dispatch_root_queue_contexts[i];
#if DISPATCH_USE_LEGACY_WORKQUEUE_FALLBACK
			if (!disable_wq && qc->dgq_wq_priority != WORKQ_PRIO_INVALID) {
				r = pthread_workqueue_attr_setqueuepriority_np(&pwq_attr,
						qc->dgq_wq_priority);
				(void)dispatch_assume_zero(r);
				r = pthread_workqueue_attr_setovercommit_np(&pwq_attr,
						qc->dgq_wq_options &
						WORKQ_ADDTHREADS_OPTION_OVERCOMMIT);
				(void)dispatch_assume_zero(r);
				r = pthread_workqueue_create_np(&pwq, &pwq_attr);
				(void)dispatch_assume_zero(r);
				result = result || dispatch_assume(pwq);
			}
#endif // DISPATCH_USE_LEGACY_WORKQUEUE_FALLBACK
			if (pwq) {
				qc->dgq_kworkqueue = pwq;
			} else {
				qc->dgq_kworkqueue = (void*)(~0ul);
				// because the fastpath of _dispatch_global_queue_poke didn't
				// know yet that we're using the internal pool implementation
				// we have to undo its setting of dgq_pending
				qc->dgq_pending = 0;
			}
		}
#if DISPATCH_USE_LEGACY_WORKQUEUE_FALLBACK
		if (!disable_wq) {
			r = pthread_workqueue_attr_destroy_np(&pwq_attr);
			(void)dispatch_assume_zero(r);
		}
#endif
	}
#endif // DISPATCH_USE_LEGACY_WORKQUEUE_FALLBACK || DISPATCH_ENABLE_THREAD_POOL
#endif // DISPATCH_USE_WORKQUEUES
	return result;
}

#if DISPATCH_USE_PTHREAD_POOL
static inline void
_dispatch_root_queue_init_pthread_pool(dispatch_root_queue_context_t qc,
		int32_t pool_size, bool overcommit)
{
	dispatch_pthread_root_queue_context_t pqc = qc->dgq_ctxt;
	int32_t thread_pool_size = overcommit ? DISPATCH_WORKQ_MAX_PTHREAD_COUNT :
			(int32_t)dispatch_hw_config(active_cpus);
	if (slowpath(pool_size) && pool_size < thread_pool_size) {
		thread_pool_size = pool_size;
	}
	qc->dgq_thread_pool_size = thread_pool_size;
#if DISPATCH_USE_WORKQUEUES
	if (qc->dgq_qos) {
#if !defined(_WIN32)
		(void)dispatch_assume_zero(pthread_attr_init(&pqc->dpq_thread_attr));
		(void)dispatch_assume_zero(pthread_attr_setdetachstate(
				&pqc->dpq_thread_attr, PTHREAD_CREATE_DETACHED));
#endif
#if HAVE_PTHREAD_WORKQUEUE_QOS
		(void)dispatch_assume_zero(pthread_attr_set_qos_class_np(
				&pqc->dpq_thread_attr, qc->dgq_qos, 0));
#endif
	}
#endif // HAVE_PTHREAD_WORKQUEUES
	_dispatch_sema4_t *sema = &pqc->dpq_thread_mediator.dsema_sema;
	_dispatch_sema4_init(sema, _DSEMA4_POLICY_LIFO);
	_dispatch_sema4_create(sema, _DSEMA4_POLICY_LIFO);
}
#endif // DISPATCH_USE_PTHREAD_POOL

static void
_dispatch_root_queues_init_once(void *context DISPATCH_UNUSED)
{
	int wq_supported;
	_dispatch_fork_becomes_unsafe();
	if (!_dispatch_root_queues_init_workq(&wq_supported)) {
#if DISPATCH_ENABLE_THREAD_POOL
		size_t i;
		for (i = 0; i < DISPATCH_ROOT_QUEUE_COUNT; i++) {
			bool overcommit = true;
#if TARGET_OS_EMBEDDED || (DISPATCH_USE_INTERNAL_WORKQUEUE && HAVE_DISPATCH_WORKQ_MONITORING)
			// some software hangs if the non-overcommitting queues do not
			// overcommit when threads block. Someday, this behavior should
			// apply to all platforms
			if (!(i & 1)) {
				overcommit = false;
			}
#endif
			_dispatch_root_queue_init_pthread_pool(
					&_dispatch_root_queue_contexts[i], 0, overcommit);
		}
#else
		DISPATCH_INTERNAL_CRASH((errno << 16) | wq_supported,
				"Root queue initialization failed");
#endif // DISPATCH_ENABLE_THREAD_POOL
	}
}

void
_dispatch_root_queues_init(void)
{
	static dispatch_once_t _dispatch_root_queues_pred;
	dispatch_once_f(&_dispatch_root_queues_pred, NULL,
			_dispatch_root_queues_init_once);
}

DISPATCH_EXPORT DISPATCH_NOTHROW
void
libdispatch_init(void)
{
	dispatch_assert(DISPATCH_ROOT_QUEUE_COUNT == 2 * DISPATCH_QOS_MAX);

	dispatch_assert(DISPATCH_QUEUE_PRIORITY_LOW ==
			-DISPATCH_QUEUE_PRIORITY_HIGH);
	dispatch_assert(countof(_dispatch_root_queues) ==
			DISPATCH_ROOT_QUEUE_COUNT);
	dispatch_assert(countof(_dispatch_root_queue_contexts) ==
			DISPATCH_ROOT_QUEUE_COUNT);
#if DISPATCH_USE_PTHREAD_WORKQUEUE_SETDISPATCH_NP
	dispatch_assert(sizeof(_dispatch_wq2root_queues) /
			sizeof(_dispatch_wq2root_queues[0][0]) ==
			WORKQ_NUM_PRIOQUEUE * 2);
#endif
#if DISPATCH_ENABLE_THREAD_POOL
	dispatch_assert(countof(_dispatch_pthread_root_queue_contexts) ==
			DISPATCH_ROOT_QUEUE_COUNT);
#endif

	dispatch_assert(offsetof(struct dispatch_continuation_s, do_next) ==
			offsetof(struct dispatch_object_s, do_next));
	dispatch_assert(offsetof(struct dispatch_continuation_s, do_vtable) ==
			offsetof(struct dispatch_object_s, do_vtable));
	dispatch_assert(sizeof(struct dispatch_apply_s) <=
			DISPATCH_CONTINUATION_SIZE);
	dispatch_assert(sizeof(struct dispatch_queue_s) % DISPATCH_CACHELINE_SIZE
			== 0);
	dispatch_assert(offsetof(struct dispatch_queue_s, dq_state) % _Alignof(uint64_t) == 0);
	dispatch_assert(sizeof(struct dispatch_root_queue_context_s) %
			DISPATCH_CACHELINE_SIZE == 0);

#if HAVE_PTHREAD_WORKQUEUE_QOS
	dispatch_qos_t qos = _dispatch_qos_from_qos_class(qos_class_main());
	dispatch_priority_t pri = _dispatch_priority_make(qos, 0);
	_dispatch_main_q.dq_priority = _dispatch_priority_with_override_qos(pri, qos);
#if DISPATCH_DEBUG
	if (!slowpath(getenv("LIBDISPATCH_DISABLE_SET_QOS"))) {
		_dispatch_set_qos_class_enabled = 1;
	}
#endif
#endif

#if DISPATCH_USE_THREAD_LOCAL_STORAGE
	_dispatch_thread_key_create(&__dispatch_tsd_key, _libdispatch_tsd_cleanup);
#else
	_dispatch_thread_key_create(&dispatch_priority_key, NULL);
	_dispatch_thread_key_create(&dispatch_r2k_key, NULL);
	_dispatch_thread_key_create(&dispatch_queue_key, _dispatch_queue_cleanup);
	_dispatch_thread_key_create(&dispatch_frame_key, _dispatch_frame_cleanup);
	_dispatch_thread_key_create(&dispatch_cache_key, _dispatch_cache_cleanup);
	_dispatch_thread_key_create(&dispatch_context_key, _dispatch_context_cleanup);
	_dispatch_thread_key_create(&dispatch_pthread_root_queue_observer_hooks_key,
			NULL);
	_dispatch_thread_key_create(&dispatch_basepri_key, NULL);
#if DISPATCH_INTROSPECTION
	_dispatch_thread_key_create(&dispatch_introspection_key , NULL);
#elif DISPATCH_PERF_MON
	_dispatch_thread_key_create(&dispatch_bcounter_key, NULL);
#endif
	_dispatch_thread_key_create(&dispatch_wlh_key, _dispatch_wlh_cleanup);
	_dispatch_thread_key_create(&dispatch_voucher_key, _voucher_thread_cleanup);
	_dispatch_thread_key_create(&dispatch_deferred_items_key,
			_dispatch_deferred_items_cleanup);
#endif

#if DISPATCH_USE_RESOLVERS // rdar://problem/8541707
	_dispatch_main_q.do_targetq = &_dispatch_root_queues[
			DISPATCH_ROOT_QUEUE_IDX_DEFAULT_QOS_OVERCOMMIT];
#endif

	_dispatch_queue_set_current(&_dispatch_main_q);
	_dispatch_queue_set_bound_thread(&_dispatch_main_q);

#if DISPATCH_USE_PTHREAD_ATFORK
	(void)dispatch_assume_zero(pthread_atfork(dispatch_atfork_prepare,
			dispatch_atfork_parent, dispatch_atfork_child));
#endif
	_dispatch_hw_config_init();
	_dispatch_time_init();
	_dispatch_vtable_init();
	_os_object_init();
	_voucher_init();
	_dispatch_introspection_init();
}

#if DISPATCH_USE_THREAD_LOCAL_STORAGE
#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
#include <unistd.h>
#endif
#if !defined(_WIN32)
#include <sys/syscall.h>
#endif

#ifndef __ANDROID__
#ifdef SYS_gettid
DISPATCH_ALWAYS_INLINE
static inline pid_t
gettid(void)
{
	return (pid_t)syscall(SYS_gettid);
}
#elif defined(__FreeBSD__)
DISPATCH_ALWAYS_INLINE
static inline pid_t
gettid(void)
{
	return (pid_t)pthread_getthreadid_np();
}
#elif defined(_WIN32)
DISPATCH_ALWAYS_INLINE
static inline DWORD
gettid(void)
{
	return GetCurrentThreadId();
}
#else
#error "SYS_gettid unavailable on this system"
#endif /* SYS_gettid */
#endif /* ! __ANDROID__ */

#define _tsd_call_cleanup(k, f)  do { \
		if ((f) && tsd->k) ((void(*)(void*))(f))(tsd->k); \
	} while (0)

#ifdef __ANDROID__
static void (*_dispatch_thread_detach_callback)(void);

void
_dispatch_install_thread_detach_callback(dispatch_function_t cb)
{
    if (os_atomic_xchg(&_dispatch_thread_detach_callback, cb, relaxed)) {
        DISPATCH_CLIENT_CRASH(0, "Installing a thread detach callback twice");
    }
}
#endif

#if defined(_WIN32)
static bool
_dispatch_process_is_exiting(void)
{
	// The goal here is to detect if the current thread is executing cleanup
	// code (e.g. FLS destructors) as a result of calling ExitProcess(). Windows
	// doesn't provide an official method of getting this information, so we
	// take advantage of how ExitProcess() works internally. The first thing
	// that it does (according to MSDN) is terminate every other thread in the
	// process. Logically, it should not be possible to create more threads
	// after this point, and Windows indeed enforces this. Try to create a
	// lightweight suspended thread, and if access is denied, assume that this
	// is because the process is exiting.
	//
	// We aren't worried about any race conditions here during process exit.
	// Cleanup code is only run on the thread that already called ExitProcess(),
	// and every other thread will have been forcibly terminated by the time
	// that happens. Additionally, while CreateThread() could conceivably fail
	// due to resource exhaustion, the process would already be in a bad state
	// if that happens. This is only intended to prevent unwanted cleanup code
	// from running, so the worst case is that a thread doesn't clean up after
	// itself when the process is about to die anyway.
	const size_t stack_size = 1;  // As small as possible
	HANDLE thread = CreateThread(NULL, stack_size, NULL, NULL,
			CREATE_SUSPENDED | STACK_SIZE_PARAM_IS_A_RESERVATION, NULL);
	if (thread) {
		// Although Microsoft recommends against using TerminateThread, it's
		// safe to use it here because we know that the thread is suspended and
		// it has not executed any code due to a NULL lpStartAddress. There was
		// a bug in Windows Server 2003 and Windows XP where the initial stack
		// would not be freed, but libdispatch does not support them anyway.
		TerminateThread(thread, 0);
		CloseHandle(thread);
		return false;
	}
	return GetLastError() == ERROR_ACCESS_DENIED;
}
#endif

void DISPATCH_TSD_DTOR_CC
_libdispatch_tsd_cleanup(void *ctx)
{
#if defined(_WIN32)
	// On Windows, exiting a process will still call FLS destructors for the
	// thread that called ExitProcess(). pthreads-based platforms don't call key
	// destructors on exit, so be consistent.
	if (_dispatch_process_is_exiting()) {
		return;
	}
#endif

	struct dispatch_tsd *tsd = (struct dispatch_tsd*) ctx;

	_tsd_call_cleanup(dispatch_priority_key, NULL);
	_tsd_call_cleanup(dispatch_r2k_key, NULL);

	_tsd_call_cleanup(dispatch_queue_key, _dispatch_queue_cleanup);
	_tsd_call_cleanup(dispatch_frame_key, _dispatch_frame_cleanup);
	_tsd_call_cleanup(dispatch_cache_key, _dispatch_cache_cleanup);
	_tsd_call_cleanup(dispatch_context_key, _dispatch_context_cleanup);
	_tsd_call_cleanup(dispatch_pthread_root_queue_observer_hooks_key,
			NULL);
	_tsd_call_cleanup(dispatch_basepri_key, NULL);
#if DISPATCH_INTROSPECTION
	_tsd_call_cleanup(dispatch_introspection_key, NULL);
#elif DISPATCH_PERF_MON
	_tsd_call_cleanup(dispatch_bcounter_key, NULL);
#endif
	_tsd_call_cleanup(dispatch_wlh_key, _dispatch_wlh_cleanup);
	_tsd_call_cleanup(dispatch_voucher_key, _voucher_thread_cleanup);
	_tsd_call_cleanup(dispatch_deferred_items_key,
			_dispatch_deferred_items_cleanup);
#ifdef __ANDROID__
	if (_dispatch_thread_detach_callback) {
		_dispatch_thread_detach_callback();
	}
#endif
	tsd->tid = 0;
}

DISPATCH_NOINLINE
void
libdispatch_tsd_init(void)
{
#if defined(_WIN32)
	FlsSetValue(__dispatch_tsd_key, &__dispatch_tsd);
#else
	pthread_setspecific(__dispatch_tsd_key, &__dispatch_tsd);
#endif /* defined(_WIN32) */
	__dispatch_tsd.tid = gettid();
}
#endif

DISPATCH_NOTHROW
void
_dispatch_queue_atfork_child(void)
{
	dispatch_queue_t main_q = &_dispatch_main_q;
	void *crash = (void *)0x100;
	size_t i;

	if (_dispatch_queue_is_thread_bound(main_q)) {
		_dispatch_queue_set_bound_thread(main_q);
	}

	if (!_dispatch_is_multithreaded_inline()) return;

	main_q->dq_items_head = crash;
	main_q->dq_items_tail = crash;

	_dispatch_mgr_q.dq_items_head = crash;
	_dispatch_mgr_q.dq_items_tail = crash;

	for (i = 0; i < DISPATCH_ROOT_QUEUE_COUNT; i++) {
		_dispatch_root_queues[i].dq_items_head = crash;
		_dispatch_root_queues[i].dq_items_tail = crash;
	}
}

DISPATCH_NOINLINE
void
_dispatch_fork_becomes_unsafe_slow(void)
{
	uint8_t value = os_atomic_or(&_dispatch_unsafe_fork,
			_DISPATCH_UNSAFE_FORK_MULTITHREADED, relaxed);
	if (value & _DISPATCH_UNSAFE_FORK_PROHIBIT) {
		DISPATCH_CLIENT_CRASH(0, "Transition to multithreaded is prohibited");
	}
}

DISPATCH_NOINLINE
void
_dispatch_prohibit_transition_to_multithreaded(bool prohibit)
{
	if (prohibit) {
		uint8_t value = os_atomic_or(&_dispatch_unsafe_fork,
				_DISPATCH_UNSAFE_FORK_PROHIBIT, relaxed);
		if (value & _DISPATCH_UNSAFE_FORK_MULTITHREADED) {
			DISPATCH_CLIENT_CRASH(0, "The executable is already multithreaded");
		}
	} else {
		os_atomic_and(&_dispatch_unsafe_fork,
				(uint8_t)~_DISPATCH_UNSAFE_FORK_PROHIBIT, relaxed);
	}
}

#pragma mark -
#pragma mark dispatch_queue_attr_t

DISPATCH_ALWAYS_INLINE
static inline bool
_dispatch_qos_class_valid(dispatch_qos_class_t qos_class, int relative_priority)
{
	qos_class_t qos = (qos_class_t)qos_class;
	switch (qos) {
	case QOS_CLASS_MAINTENANCE:
	case QOS_CLASS_BACKGROUND:
	case QOS_CLASS_UTILITY:
	case QOS_CLASS_DEFAULT:
	case QOS_CLASS_USER_INITIATED:
	case QOS_CLASS_USER_INTERACTIVE:
	case QOS_CLASS_UNSPECIFIED:
		break;
	default:
		return false;
	}
	if (relative_priority > 0 || relative_priority < QOS_MIN_RELATIVE_PRIORITY){
		return false;
	}
	return true;
}

#define DISPATCH_QUEUE_ATTR_OVERCOMMIT2IDX(overcommit) \
		((overcommit) == _dispatch_queue_attr_overcommit_disabled ? \
		DQA_INDEX_NON_OVERCOMMIT : \
		((overcommit) == _dispatch_queue_attr_overcommit_enabled ? \
		DQA_INDEX_OVERCOMMIT : DQA_INDEX_UNSPECIFIED_OVERCOMMIT))

#define DISPATCH_QUEUE_ATTR_CONCURRENT2IDX(concurrent) \
		((concurrent) ? DQA_INDEX_CONCURRENT : DQA_INDEX_SERIAL)

#define DISPATCH_QUEUE_ATTR_INACTIVE2IDX(inactive) \
		((inactive) ? DQA_INDEX_INACTIVE : DQA_INDEX_ACTIVE)

#define DISPATCH_QUEUE_ATTR_AUTORELEASE_FREQUENCY2IDX(frequency) \
		(frequency)

#define DISPATCH_QUEUE_ATTR_PRIO2IDX(prio) (-(prio))

#define DISPATCH_QUEUE_ATTR_QOS2IDX(qos) (qos)

static inline dispatch_queue_attr_t
_dispatch_get_queue_attr(dispatch_qos_t qos, int prio,
		_dispatch_queue_attr_overcommit_t overcommit,
		dispatch_autorelease_frequency_t frequency,
		bool concurrent, bool inactive)
{
	return (dispatch_queue_attr_t)&_dispatch_queue_attrs
			[DISPATCH_QUEUE_ATTR_QOS2IDX(qos)]
			[DISPATCH_QUEUE_ATTR_PRIO2IDX(prio)]
			[DISPATCH_QUEUE_ATTR_OVERCOMMIT2IDX(overcommit)]
			[DISPATCH_QUEUE_ATTR_AUTORELEASE_FREQUENCY2IDX(frequency)]
			[DISPATCH_QUEUE_ATTR_CONCURRENT2IDX(concurrent)]
			[DISPATCH_QUEUE_ATTR_INACTIVE2IDX(inactive)];
}

dispatch_queue_attr_t
_dispatch_get_default_queue_attr(void)
{
	return _dispatch_get_queue_attr(DISPATCH_QOS_UNSPECIFIED, 0,
				_dispatch_queue_attr_overcommit_unspecified,
				DISPATCH_AUTORELEASE_FREQUENCY_INHERIT, false, false);
}

dispatch_queue_attr_t
dispatch_queue_attr_make_with_qos_class(dispatch_queue_attr_t dqa,
		dispatch_qos_class_t qos_class, int relpri)
{
	if (!_dispatch_qos_class_valid(qos_class, relpri)) {
		return DISPATCH_BAD_INPUT;
	}
	if (!slowpath(dqa)) {
		dqa = _dispatch_get_default_queue_attr();
	} else if (dqa->do_vtable != DISPATCH_VTABLE(queue_attr)) {
		DISPATCH_CLIENT_CRASH(dqa->do_vtable, "Invalid queue attribute");
	}
	return _dispatch_get_queue_attr(_dispatch_qos_from_qos_class(qos_class),
			relpri, dqa->dqa_overcommit, dqa->dqa_autorelease_frequency,
			dqa->dqa_concurrent, dqa->dqa_inactive);
}

dispatch_queue_attr_t
dispatch_queue_attr_make_initially_inactive(dispatch_queue_attr_t dqa)
{
	if (!slowpath(dqa)) {
		dqa = _dispatch_get_default_queue_attr();
	} else if (dqa->do_vtable != DISPATCH_VTABLE(queue_attr)) {
		DISPATCH_CLIENT_CRASH(dqa->do_vtable, "Invalid queue attribute");
	}
	dispatch_priority_t pri = dqa->dqa_qos_and_relpri;
	return _dispatch_get_queue_attr(_dispatch_priority_qos(pri),
			_dispatch_priority_relpri(pri), dqa->dqa_overcommit,
			dqa->dqa_autorelease_frequency, dqa->dqa_concurrent, true);
}

dispatch_queue_attr_t
dispatch_queue_attr_make_with_overcommit(dispatch_queue_attr_t dqa,
		bool overcommit)
{
	if (!slowpath(dqa)) {
		dqa = _dispatch_get_default_queue_attr();
	} else if (dqa->do_vtable != DISPATCH_VTABLE(queue_attr)) {
		DISPATCH_CLIENT_CRASH(dqa->do_vtable, "Invalid queue attribute");
	}
	dispatch_priority_t pri = dqa->dqa_qos_and_relpri;
	return _dispatch_get_queue_attr(_dispatch_priority_qos(pri),
			_dispatch_priority_relpri(pri), overcommit ?
			_dispatch_queue_attr_overcommit_enabled :
			_dispatch_queue_attr_overcommit_disabled,
			dqa->dqa_autorelease_frequency, dqa->dqa_concurrent,
			dqa->dqa_inactive);
}

dispatch_queue_attr_t
dispatch_queue_attr_make_with_autorelease_frequency(dispatch_queue_attr_t dqa,
		dispatch_autorelease_frequency_t frequency)
{
	switch (frequency) {
	case DISPATCH_AUTORELEASE_FREQUENCY_INHERIT:
	case DISPATCH_AUTORELEASE_FREQUENCY_WORK_ITEM:
	case DISPATCH_AUTORELEASE_FREQUENCY_NEVER:
		break;
	}
	if (!slowpath(dqa)) {
		dqa = _dispatch_get_default_queue_attr();
	} else if (dqa->do_vtable != DISPATCH_VTABLE(queue_attr)) {
		DISPATCH_CLIENT_CRASH(dqa->do_vtable, "Invalid queue attribute");
	}
	dispatch_priority_t pri = dqa->dqa_qos_and_relpri;
	return _dispatch_get_queue_attr(_dispatch_priority_qos(pri),
			_dispatch_priority_relpri(pri), dqa->dqa_overcommit,
			frequency, dqa->dqa_concurrent, dqa->dqa_inactive);
}

#pragma mark -
#pragma mark dispatch_queue_t

void
dispatch_queue_set_label_nocopy(dispatch_queue_t dq, const char *label)
{
	if (dq->do_ref_cnt == DISPATCH_OBJECT_GLOBAL_REFCNT) {
		return;
	}
	dispatch_queue_flags_t dqf = _dispatch_queue_atomic_flags(dq);
	if (unlikely(dqf & DQF_LABEL_NEEDS_FREE)) {
		DISPATCH_CLIENT_CRASH(dq, "Cannot change label for this queue");
	}
	dq->dq_label = label;
}

static inline bool
_dispatch_base_queue_is_wlh(dispatch_queue_t dq, dispatch_queue_t tq)
{
	(void)dq; (void)tq;
	return false;
}

static void
_dispatch_queue_inherit_wlh_from_target(dispatch_queue_t dq,
		dispatch_queue_t tq)
{
	uint64_t old_state, new_state, role;

	if (!dx_hastypeflag(tq, QUEUE_ROOT)) {
		role = DISPATCH_QUEUE_ROLE_INNER;
	} else if (_dispatch_base_queue_is_wlh(dq, tq)) {
		role = DISPATCH_QUEUE_ROLE_BASE_WLH;
	} else {
		role = DISPATCH_QUEUE_ROLE_BASE_ANON;
	}

	os_atomic_rmw_loop2o(dq, dq_state, old_state, new_state, relaxed, {
		new_state = old_state & ~DISPATCH_QUEUE_ROLE_MASK;
		new_state |= role;
		if (old_state == new_state) {
			os_atomic_rmw_loop_give_up(break);
		}
	});

	dispatch_wlh_t cur_wlh = _dispatch_get_wlh();
	if (cur_wlh == (dispatch_wlh_t)dq && !_dq_state_is_base_wlh(new_state)) {
		_dispatch_event_loop_leave_immediate(cur_wlh, new_state);
	}
	if (!dx_hastypeflag(tq, QUEUE_ROOT)) {
#if DISPATCH_ALLOW_NON_LEAF_RETARGET
		_dispatch_queue_atomic_flags_set(tq, DQF_TARGETED);
#else
		_dispatch_queue_atomic_flags_set_and_clear(tq, DQF_TARGETED, DQF_LEGACY);
#endif
	}
}

unsigned long volatile _dispatch_queue_serial_numbers =
		DISPATCH_QUEUE_SERIAL_NUMBER_INIT;

dispatch_priority_t
_dispatch_queue_compute_priority_and_wlh(dispatch_queue_t dq,
		dispatch_wlh_t *wlh_out)
{
	dispatch_priority_t p = dq->dq_priority & DISPATCH_PRIORITY_REQUESTED_MASK;
	dispatch_queue_t tq = dq->do_targetq;
	dispatch_priority_t tqp = tq->dq_priority &DISPATCH_PRIORITY_REQUESTED_MASK;
	dispatch_wlh_t wlh = DISPATCH_WLH_ANON;

	if (_dq_state_is_base_wlh(dq->dq_state)) {
		wlh = (dispatch_wlh_t)dq;
	}

	while (unlikely(!dx_hastypeflag(tq, QUEUE_ROOT))) {
		if (unlikely(tq == &_dispatch_mgr_q)) {
			if (wlh_out) *wlh_out = DISPATCH_WLH_ANON;
			return DISPATCH_PRIORITY_FLAG_MANAGER;
		}
		if (unlikely(_dispatch_queue_is_thread_bound(tq))) {
			// thread-bound hierarchies are weird, we need to install
			// from the context of the thread this hierarchy is bound to
			if (wlh_out) *wlh_out = NULL;
			return 0;
		}
		if (unlikely(DISPATCH_QUEUE_IS_SUSPENDED(tq))) {
			// this queue may not be activated yet, so the queue graph may not
			// have stabilized yet
			_dispatch_ktrace1(DISPATCH_PERF_delayed_registration, dq);
			if (wlh_out) *wlh_out = NULL;
			return 0;
		}

		if (_dq_state_is_base_wlh(tq->dq_state)) {
			wlh = (dispatch_wlh_t)tq;
		} else if (unlikely(_dispatch_queue_is_legacy(tq))) {
			// we're not allowed to dereference tq->do_targetq
			_dispatch_ktrace1(DISPATCH_PERF_delayed_registration, dq);
			if (wlh_out) *wlh_out = NULL;
			return 0;
		}

		if (!(tq->dq_priority & DISPATCH_PRIORITY_FLAG_INHERIT)) {
			if (p < tqp) p = tqp;
		}
		tq = tq->do_targetq;
		tqp = tq->dq_priority & DISPATCH_PRIORITY_REQUESTED_MASK;
	}

	if (unlikely(!tqp)) {
		// pthread root queues opt out of QoS
		if (wlh_out) *wlh_out = DISPATCH_WLH_ANON;
		return DISPATCH_PRIORITY_FLAG_MANAGER;
	}
	if (wlh_out) *wlh_out = wlh;
	return _dispatch_priority_inherit_from_root_queue(p, tq);
}

DISPATCH_NOINLINE
static dispatch_queue_t
_dispatch_queue_create_with_target(const char *label, dispatch_queue_attr_t dqa,
		dispatch_queue_t tq, bool legacy)
{
	if (!slowpath(dqa)) {
		dqa = _dispatch_get_default_queue_attr();
	} else if (dqa->do_vtable != DISPATCH_VTABLE(queue_attr)) {
		DISPATCH_CLIENT_CRASH(dqa->do_vtable, "Invalid queue attribute");
	}

	//
	// Step 1: Normalize arguments (qos, overcommit, tq)
	//

	dispatch_qos_t qos = _dispatch_priority_qos(dqa->dqa_qos_and_relpri);
#if !HAVE_PTHREAD_WORKQUEUE_QOS
	if (qos == DISPATCH_QOS_USER_INTERACTIVE) {
		qos = DISPATCH_QOS_USER_INITIATED;
	}
	if (qos == DISPATCH_QOS_MAINTENANCE) {
		qos = DISPATCH_QOS_BACKGROUND;
	}
#endif // !HAVE_PTHREAD_WORKQUEUE_QOS

	_dispatch_queue_attr_overcommit_t overcommit = dqa->dqa_overcommit;
	if (overcommit != _dispatch_queue_attr_overcommit_unspecified && tq) {
		if (tq->do_targetq) {
			DISPATCH_CLIENT_CRASH(tq, "Cannot specify both overcommit and "
					"a non-global target queue");
		}
	}

	if (tq && !tq->do_targetq &&
			tq->do_ref_cnt == DISPATCH_OBJECT_GLOBAL_REFCNT) {
		// Handle discrepancies between attr and target queue, attributes win
		if (overcommit == _dispatch_queue_attr_overcommit_unspecified) {
			if (tq->dq_priority & DISPATCH_PRIORITY_FLAG_OVERCOMMIT) {
				overcommit = _dispatch_queue_attr_overcommit_enabled;
			} else {
				overcommit = _dispatch_queue_attr_overcommit_disabled;
			}
		}
		if (qos == DISPATCH_QOS_UNSPECIFIED) {
			dispatch_qos_t tq_qos = _dispatch_priority_qos(tq->dq_priority);
			tq = _dispatch_get_root_queue(tq_qos,
					overcommit == _dispatch_queue_attr_overcommit_enabled);
		} else {
			tq = NULL;
		}
	} else if (tq && !tq->do_targetq) {
		// target is a pthread or runloop root queue, setting QoS or overcommit
		// is disallowed
		if (overcommit != _dispatch_queue_attr_overcommit_unspecified) {
			DISPATCH_CLIENT_CRASH(tq, "Cannot specify an overcommit attribute "
					"and use this kind of target queue");
		}
		if (qos != DISPATCH_QOS_UNSPECIFIED) {
			DISPATCH_CLIENT_CRASH(tq, "Cannot specify a QoS attribute "
					"and use this kind of target queue");
		}
	} else {
		if (overcommit == _dispatch_queue_attr_overcommit_unspecified) {
			 // Serial queues default to overcommit!
			overcommit = dqa->dqa_concurrent ?
					_dispatch_queue_attr_overcommit_disabled :
					_dispatch_queue_attr_overcommit_enabled;
		}
	}
	if (!tq) {
		tq = _dispatch_get_root_queue(
				qos == DISPATCH_QOS_UNSPECIFIED ? DISPATCH_QOS_DEFAULT : qos,
				overcommit == _dispatch_queue_attr_overcommit_enabled);
		if (slowpath(!tq)) {
			DISPATCH_CLIENT_CRASH(qos, "Invalid queue attribute");
		}
	}

	//
	// Step 2: Initialize the queue
	//

	if (legacy) {
		// if any of these attributes is specified, use non legacy classes
		if (dqa->dqa_inactive || dqa->dqa_autorelease_frequency) {
			legacy = false;
		}
	}

	const void *vtable;
	dispatch_queue_flags_t dqf = 0;
	if (legacy) {
		vtable = DISPATCH_VTABLE(queue);
	} else if (dqa->dqa_concurrent) {
		vtable = DISPATCH_VTABLE(queue_concurrent);
	} else {
		vtable = DISPATCH_VTABLE(queue_serial);
	}
	switch (dqa->dqa_autorelease_frequency) {
	case DISPATCH_AUTORELEASE_FREQUENCY_NEVER:
		dqf |= DQF_AUTORELEASE_NEVER;
		break;
	case DISPATCH_AUTORELEASE_FREQUENCY_WORK_ITEM:
		dqf |= DQF_AUTORELEASE_ALWAYS;
		break;
	}
	if (legacy) {
		dqf |= DQF_LEGACY;
	}
	if (label) {
		const char *tmp = _dispatch_strdup_if_mutable(label);
		if (tmp != label) {
			dqf |= DQF_LABEL_NEEDS_FREE;
			label = tmp;
		}
	}

	dispatch_queue_t dq = _dispatch_object_alloc(vtable,
			sizeof(struct dispatch_queue_s) - DISPATCH_QUEUE_CACHELINE_PAD);
	_dispatch_queue_init(dq, dqf, dqa->dqa_concurrent ?
			DISPATCH_QUEUE_WIDTH_MAX : 1, DISPATCH_QUEUE_ROLE_INNER |
			(dqa->dqa_inactive ? DISPATCH_QUEUE_INACTIVE : 0));

	dq->dq_label = label;
#if HAVE_PTHREAD_WORKQUEUE_QOS
	dq->dq_priority = dqa->dqa_qos_and_relpri;
	if (overcommit == _dispatch_queue_attr_overcommit_enabled) {
		dq->dq_priority |= DISPATCH_PRIORITY_FLAG_OVERCOMMIT;
	}
#endif
	_dispatch_retain(tq);
	if (qos == QOS_CLASS_UNSPECIFIED) {
		// legacy way of inherithing the QoS from the target
		_dispatch_queue_priority_inherit_from_target(dq, tq);
	}
	if (!dqa->dqa_inactive) {
		_dispatch_queue_inherit_wlh_from_target(dq, tq);
	}
	dq->do_targetq = tq;
	_dispatch_object_debug(dq, "%s", __func__);
	return _dispatch_introspection_queue_create(dq);
}

dispatch_queue_t
dispatch_queue_create_with_target(const char *label, dispatch_queue_attr_t dqa,
		dispatch_queue_t tq)
{
	return _dispatch_queue_create_with_target(label, dqa, tq, false);
}

dispatch_queue_t
dispatch_queue_create(const char *label, dispatch_queue_attr_t attr)
{
	return _dispatch_queue_create_with_target(label, attr,
			DISPATCH_TARGET_QUEUE_DEFAULT, true);
}

dispatch_queue_t
dispatch_queue_create_with_accounting_override_voucher(const char *label,
		dispatch_queue_attr_t attr, voucher_t voucher)
{
	(void)label; (void)attr; (void)voucher;
	DISPATCH_CLIENT_CRASH(0, "Unsupported interface");
}

void
_dispatch_queue_destroy(dispatch_queue_t dq, bool *allow_free)
{
	uint64_t dq_state = os_atomic_load2o(dq, dq_state, relaxed);
	uint64_t initial_state = DISPATCH_QUEUE_STATE_INIT_VALUE(dq->dq_width);

	if (dx_hastypeflag(dq, QUEUE_ROOT)) {
		initial_state = DISPATCH_ROOT_QUEUE_STATE_INIT_VALUE;
	}
	dq_state &= ~DISPATCH_QUEUE_MAX_QOS_MASK;
	dq_state &= ~DISPATCH_QUEUE_DIRTY;
	dq_state &= ~DISPATCH_QUEUE_ROLE_MASK;
	if (slowpath(dq_state != initial_state)) {
		if (_dq_state_drain_locked(dq_state)) {
			DISPATCH_CLIENT_CRASH((uintptr_t)dq_state,
					"Release of a locked queue");
		}
#ifndef __LP64__
		dq_state >>= 32;
#endif
		DISPATCH_CLIENT_CRASH((uintptr_t)dq_state,
				"Release of a queue with corrupt state");
	}
	if (slowpath(dq->dq_items_tail)) {
		DISPATCH_CLIENT_CRASH(dq->dq_items_tail,
				"Release of a queue while items are enqueued");
	}

	// trash the queue so that use after free will crash
	dq->dq_items_head = (void *)0x200;
	dq->dq_items_tail = (void *)0x200;

	dispatch_queue_t dqsq = os_atomic_xchg2o(dq, dq_specific_q,
			(void *)0x200, relaxed);
	if (dqsq) {
		_dispatch_release(dqsq);
	}

	// fastpath for queues that never got their storage retained
	if (likely(os_atomic_load2o(dq, dq_sref_cnt, relaxed) == 0)) {
		// poison the state with something that is suspended and is easy to spot
		dq->dq_state = 0xdead000000000000;
		return;
	}

	// Take over freeing the memory from _dispatch_object_dealloc()
	//
	// As soon as we call _dispatch_queue_release_storage(), we forfeit
	// the possibility for the caller of dx_dispose() to finalize the object
	// so that responsibility is ours.
	_dispatch_object_finalize(dq);
	*allow_free = false;
	dq->dq_label = "<released queue, pending free>";
	dq->do_targetq = NULL;
	dq->do_finalizer = NULL;
	dq->do_ctxt = NULL;
	return _dispatch_queue_release_storage(dq);
}

// 6618342 Contact the team that owns the Instrument DTrace probe before
//         renaming this symbol
void
_dispatch_queue_dispose(dispatch_queue_t dq, bool *allow_free)
{
	_dispatch_object_debug(dq, "%s", __func__);
	_dispatch_introspection_queue_dispose(dq);
	if (dq->dq_label && _dispatch_queue_label_needs_free(dq)) {
		free((void*)dq->dq_label);
	}
	_dispatch_queue_destroy(dq, allow_free);
}

void
_dispatch_queue_xref_dispose(dispatch_queue_t dq)
{
	uint64_t dq_state = os_atomic_load2o(dq, dq_state, relaxed);
	if (unlikely(_dq_state_is_suspended(dq_state))) {
		long state = (long)dq_state;
		if (sizeof(long) < sizeof(uint64_t)) state = (long)(dq_state >> 32);
		if (unlikely(_dq_state_is_inactive(dq_state))) {
			// Arguments for and against this assert are within 6705399
			DISPATCH_CLIENT_CRASH(state, "Release of an inactive object");
		}
		DISPATCH_CLIENT_CRASH(dq_state, "Release of a suspended object");
	}
	os_atomic_or2o(dq, dq_atomic_flags, DQF_RELEASED, relaxed);
}

DISPATCH_NOINLINE
static void
_dispatch_queue_suspend_slow(dispatch_queue_t dq)
{
	uint64_t dq_state, value, delta;

	_dispatch_queue_sidelock_lock(dq);

	// what we want to transfer (remove from dq_state)
	delta  = DISPATCH_QUEUE_SUSPEND_HALF * DISPATCH_QUEUE_SUSPEND_INTERVAL;
	// but this is a suspend so add a suspend count at the same time
	delta -= DISPATCH_QUEUE_SUSPEND_INTERVAL;
	if (dq->dq_side_suspend_cnt == 0) {
		// we substract delta from dq_state, and we want to set this bit
		delta -= DISPATCH_QUEUE_HAS_SIDE_SUSPEND_CNT;
	}

	os_atomic_rmw_loop2o(dq, dq_state, dq_state, value, relaxed, {
		// unsigned underflow of the substraction can happen because other
		// threads could have touched this value while we were trying to acquire
		// the lock, or because another thread raced us to do the same operation
		// and got to the lock first.
		if (unlikely(os_sub_overflow(dq_state, delta, &value))) {
			os_atomic_rmw_loop_give_up(goto retry);
		}
	});
	if (unlikely(os_add_overflow(dq->dq_side_suspend_cnt,
			DISPATCH_QUEUE_SUSPEND_HALF, &dq->dq_side_suspend_cnt))) {
		DISPATCH_CLIENT_CRASH(0, "Too many nested calls to dispatch_suspend()");
	}
	return _dispatch_queue_sidelock_unlock(dq);

retry:
	_dispatch_queue_sidelock_unlock(dq);
	return dx_vtable(dq)->do_suspend(dq);
}

void
_dispatch_queue_suspend(dispatch_queue_t dq)
{
	dispatch_assert(dq->do_ref_cnt != DISPATCH_OBJECT_GLOBAL_REFCNT);

	uint64_t dq_state, value;

	os_atomic_rmw_loop2o(dq, dq_state, dq_state, value, relaxed, {
		value = DISPATCH_QUEUE_SUSPEND_INTERVAL;
		if (unlikely(os_add_overflow(dq_state, value, &value))) {
			os_atomic_rmw_loop_give_up({
				return _dispatch_queue_suspend_slow(dq);
			});
		}
		if (!_dq_state_drain_locked(dq_state)) {
			value |= DLOCK_OWNER_MASK;
		}
	});

	if (!_dq_state_is_suspended(dq_state)) {
		// rdar://8181908 we need to extend the queue life for the duration
		// of the call to wakeup at _dispatch_queue_resume() time.
		_dispatch_retain_2(dq);
	}
}

DISPATCH_NOINLINE
static void
_dispatch_queue_resume_slow(dispatch_queue_t dq)
{
	uint64_t dq_state, value, delta;

	_dispatch_queue_sidelock_lock(dq);

	// what we want to transfer
	delta  = DISPATCH_QUEUE_SUSPEND_HALF * DISPATCH_QUEUE_SUSPEND_INTERVAL;
	// but this is a resume so consume a suspend count at the same time
	delta -= DISPATCH_QUEUE_SUSPEND_INTERVAL;
	switch (dq->dq_side_suspend_cnt) {
	case 0:
		goto retry;
	case DISPATCH_QUEUE_SUSPEND_HALF:
		// we will transition the side count to 0, so we want to clear this bit
		delta -= DISPATCH_QUEUE_HAS_SIDE_SUSPEND_CNT;
		break;
	}
	os_atomic_rmw_loop2o(dq, dq_state, dq_state, value, relaxed, {
		// unsigned overflow of the addition can happen because other
		// threads could have touched this value while we were trying to acquire
		// the lock, or because another thread raced us to do the same operation
		// and got to the lock first.
		if (unlikely(os_add_overflow(dq_state, delta, &value))) {
			os_atomic_rmw_loop_give_up(goto retry);
		}
	});
	dq->dq_side_suspend_cnt -= DISPATCH_QUEUE_SUSPEND_HALF;
	return _dispatch_queue_sidelock_unlock(dq);

retry:
	_dispatch_queue_sidelock_unlock(dq);
	return dx_vtable(dq)->do_resume(dq, false);
}

DISPATCH_NOINLINE
static void
_dispatch_queue_resume_finalize_activation(dispatch_queue_t dq)
{
	bool allow_resume = true;
	// Step 2: run the activation finalizer
	if (dx_vtable(dq)->do_finalize_activation) {
		dx_vtable(dq)->do_finalize_activation(dq, &allow_resume);
	}
	// Step 3: consume the suspend count
	if (allow_resume) {
		return dx_vtable(dq)->do_resume(dq, false);
	}
}

void
_dispatch_queue_resume(dispatch_queue_t dq, bool activate)
{
	// covers all suspend and inactive bits, including side suspend bit
	const uint64_t suspend_bits = DISPATCH_QUEUE_SUSPEND_BITS_MASK;
	uint64_t pending_barrier_width =
			(dq->dq_width - 1) * DISPATCH_QUEUE_WIDTH_INTERVAL;
	uint64_t set_owner_and_set_full_width_and_in_barrier =
			_dispatch_lock_value_for_self() | DISPATCH_QUEUE_WIDTH_FULL_BIT |
			DISPATCH_QUEUE_IN_BARRIER;

	// backward compatibility: only dispatch sources can abuse
	// dispatch_resume() to really mean dispatch_activate()
	bool is_source = (dx_metatype(dq) == _DISPATCH_SOURCE_TYPE);
	uint64_t dq_state, value;

	dispatch_assert(dq->do_ref_cnt != DISPATCH_OBJECT_GLOBAL_REFCNT);

	// Activation is a bit tricky as it needs to finalize before the wakeup.
	//
	// If after doing its updates to the suspend count and/or inactive bit,
	// the last suspension related bit that would remain is the
	// NEEDS_ACTIVATION one, then this function:
	//
	// 1. moves the state to { sc:1 i:0 na:0 } (converts the needs-activate into
	//    a suspend count)
	// 2. runs the activation finalizer
	// 3. consumes the suspend count set in (1), and finishes the resume flow
	//
	// Concurrently, some property setters such as setting dispatch source
	// handlers or _dispatch_queue_set_target_queue try to do in-place changes
	// before activation. These protect their action by taking a suspend count.
	// Step (1) above cannot happen if such a setter has locked the object.
	if (activate) {
		// relaxed atomic because this doesn't publish anything, this is only
		// about picking the thread that gets to finalize the activation
		os_atomic_rmw_loop2o(dq, dq_state, dq_state, value, relaxed, {
			if ((dq_state & suspend_bits) ==
					DISPATCH_QUEUE_NEEDS_ACTIVATION + DISPATCH_QUEUE_INACTIVE) {
				// { sc:0 i:1 na:1 } -> { sc:1 i:0 na:0 }
				value = dq_state - DISPATCH_QUEUE_INACTIVE
						- DISPATCH_QUEUE_NEEDS_ACTIVATION
						+ DISPATCH_QUEUE_SUSPEND_INTERVAL;
			} else if (_dq_state_is_inactive(dq_state)) {
				// { sc:>0 i:1 na:1 } -> { i:0 na:1 }
				// simple activation because sc is not 0
				// resume will deal with na:1 later
				value = dq_state - DISPATCH_QUEUE_INACTIVE;
			} else {
				// object already active, this is a no-op, just exit
				os_atomic_rmw_loop_give_up(return);
			}
		});
	} else {
		// release barrier needed to publish the effect of
		// - dispatch_set_target_queue()
		// - dispatch_set_*_handler()
		// - do_finalize_activation()
		os_atomic_rmw_loop2o(dq, dq_state, dq_state, value, release, {
			if ((dq_state & suspend_bits) == DISPATCH_QUEUE_SUSPEND_INTERVAL
					+ DISPATCH_QUEUE_NEEDS_ACTIVATION) {
				// { sc:1 i:0 na:1 } -> { sc:1 i:0 na:0 }
				value = dq_state - DISPATCH_QUEUE_NEEDS_ACTIVATION;
			} else if (is_source && (dq_state & suspend_bits) ==
					DISPATCH_QUEUE_NEEDS_ACTIVATION + DISPATCH_QUEUE_INACTIVE) {
				// { sc:0 i:1 na:1 } -> { sc:1 i:0 na:0 }
				value = dq_state - DISPATCH_QUEUE_INACTIVE
						- DISPATCH_QUEUE_NEEDS_ACTIVATION
						+ DISPATCH_QUEUE_SUSPEND_INTERVAL;
			} else if (unlikely(os_sub_overflow(dq_state,
					DISPATCH_QUEUE_SUSPEND_INTERVAL, &value))) {
				// underflow means over-resume or a suspend count transfer
				// to the side count is needed
				os_atomic_rmw_loop_give_up({
					if (!(dq_state & DISPATCH_QUEUE_HAS_SIDE_SUSPEND_CNT)) {
						goto over_resume;
					}
					return _dispatch_queue_resume_slow(dq);
				});
		//
		// below this, value = dq_state - DISPATCH_QUEUE_SUSPEND_INTERVAL
		//
			} else if (!_dq_state_is_runnable(value)) {
				// Out of width or still suspended.
				// For the former, force _dispatch_queue_non_barrier_complete
				// to reconsider whether it has work to do
				value |= DISPATCH_QUEUE_DIRTY;
			} else if (!_dq_state_drain_locked_by(value, DLOCK_OWNER_MASK)) {
				dispatch_assert(_dq_state_drain_locked(value));
				// still locked by someone else, make drain_try_unlock() fail
				// and reconsider whether it has work to do
				value |= DISPATCH_QUEUE_DIRTY;
			} else if (!is_source && (_dq_state_has_pending_barrier(value) ||
					value + pending_barrier_width <
					DISPATCH_QUEUE_WIDTH_FULL_BIT)) {
				// if we can, acquire the full width drain lock
				// and then perform a lock transfer
				//
				// However this is never useful for a source where there are no
				// sync waiters, so never take the lock and do a plain wakeup
				value &= DISPATCH_QUEUE_DRAIN_PRESERVED_BITS_MASK;
				value |= set_owner_and_set_full_width_and_in_barrier;
			} else {
				// clear overrides and force a wakeup
				value &= ~DISPATCH_QUEUE_DRAIN_UNLOCK_MASK;
				value &= ~DISPATCH_QUEUE_MAX_QOS_MASK;
			}
		});
	}

	if ((dq_state ^ value) & DISPATCH_QUEUE_NEEDS_ACTIVATION) {
		// we cleared the NEEDS_ACTIVATION bit and we have a valid suspend count
		return _dispatch_queue_resume_finalize_activation(dq);
	}

	if (activate) {
		// if we're still in an activate codepath here we should have
		// { sc:>0 na:1 }, if not we've got a corrupt state
		if (unlikely(!_dq_state_is_suspended(value))) {
			DISPATCH_CLIENT_CRASH(dq, "Invalid suspension state");
		}
		return;
	}

	if (_dq_state_is_suspended(value)) {
		return;
	}

	if (_dq_state_is_dirty(dq_state)) {
		// <rdar://problem/14637483>
		// dependency ordering for dq state changes that were flushed
		// and not acted upon
		os_atomic_thread_fence(dependency);
		dq = os_atomic_force_dependency_on(dq, dq_state);
	}
	// Balancing the retain_2 done in suspend() for rdar://8181908
	dispatch_wakeup_flags_t flags = DISPATCH_WAKEUP_CONSUME_2;
	if ((dq_state ^ value) & DISPATCH_QUEUE_IN_BARRIER) {
		flags |= DISPATCH_WAKEUP_BARRIER_COMPLETE;
	} else if (!_dq_state_is_runnable(value)) {
		if (_dq_state_is_base_wlh(dq_state)) {
			_dispatch_event_loop_assert_not_owned((dispatch_wlh_t)dq);
		}
		return _dispatch_release_2(dq);
	}
	dispatch_assert(!_dq_state_received_sync_wait(dq_state));
	dispatch_assert(!_dq_state_in_sync_transfer(dq_state));
	return dx_wakeup(dq, _dq_state_max_qos(dq_state), flags);

over_resume:
	if (unlikely(_dq_state_is_inactive(dq_state))) {
		DISPATCH_CLIENT_CRASH(dq, "Over-resume of an inactive object");
	}
	DISPATCH_CLIENT_CRASH(dq, "Over-resume of an object");
}

const char *
dispatch_queue_get_label(dispatch_queue_t dq)
{
	if (slowpath(dq == DISPATCH_CURRENT_QUEUE_LABEL)) {
		dq = _dispatch_get_current_queue();
	}
	return dq->dq_label ? dq->dq_label : "";
}

qos_class_t
dispatch_queue_get_qos_class(dispatch_queue_t dq, int *relpri_ptr)
{
	dispatch_qos_class_t qos = _dispatch_priority_qos(dq->dq_priority);
	if (relpri_ptr) {
		*relpri_ptr = qos ? _dispatch_priority_relpri(dq->dq_priority) : 0;
	}
	return _dispatch_qos_to_qos_class(qos);
}

static void
_dispatch_queue_set_width2(void *ctxt)
{
	int w = (int)(intptr_t)ctxt; // intentional truncation
	uint32_t tmp;
	dispatch_queue_t dq = _dispatch_queue_get_current();

	if (w >= 0) {
		tmp = w ? (unsigned int)w : 1;
	} else {
		dispatch_qos_t qos = _dispatch_qos_from_pp(_dispatch_get_priority());
		switch (w) {
		case DISPATCH_QUEUE_WIDTH_MAX_PHYSICAL_CPUS:
			tmp = _dispatch_qos_max_parallelism(qos,
					DISPATCH_MAX_PARALLELISM_PHYSICAL);
			break;
		case DISPATCH_QUEUE_WIDTH_ACTIVE_CPUS:
			tmp = _dispatch_qos_max_parallelism(qos,
					DISPATCH_MAX_PARALLELISM_ACTIVE);
			break;
		case DISPATCH_QUEUE_WIDTH_MAX_LOGICAL_CPUS:
		default:
			tmp = _dispatch_qos_max_parallelism(qos, 0);
			break;
		}
	}
	if (tmp > DISPATCH_QUEUE_WIDTH_MAX) {
		tmp = DISPATCH_QUEUE_WIDTH_MAX;
	}

	dispatch_queue_flags_t old_dqf, new_dqf;
	os_atomic_rmw_loop2o(dq, dq_atomic_flags, old_dqf, new_dqf, relaxed, {
		new_dqf = (old_dqf & DQF_FLAGS_MASK) | DQF_WIDTH(tmp);
	});
	_dispatch_queue_inherit_wlh_from_target(dq, dq->do_targetq);
	_dispatch_object_debug(dq, "%s", __func__);
}

void
dispatch_queue_set_width(dispatch_queue_t dq, long width)
{
	if (unlikely(dq->do_ref_cnt == DISPATCH_OBJECT_GLOBAL_REFCNT ||
			dx_hastypeflag(dq, QUEUE_ROOT) ||
			dx_hastypeflag(dq, QUEUE_BASE))) {
		return;
	}

	unsigned long type = dx_type(dq);
	switch (type) {
	case DISPATCH_QUEUE_LEGACY_TYPE:
	case DISPATCH_QUEUE_CONCURRENT_TYPE:
		break;
	case DISPATCH_QUEUE_SERIAL_TYPE:
		DISPATCH_CLIENT_CRASH(type, "Cannot set width of a serial queue");
	default:
		DISPATCH_CLIENT_CRASH(type, "Unexpected dispatch object type");
	}

	if (likely((int)width >= 0)) {
		_dispatch_barrier_trysync_or_async_f(dq, (void*)(intptr_t)width,
				_dispatch_queue_set_width2);
	} else {
		// The negative width constants need to execute on the queue to
		// query the queue QoS
		_dispatch_barrier_async_detached_f(dq, (void*)(intptr_t)width,
				_dispatch_queue_set_width2);
	}
}

static void
_dispatch_queue_legacy_set_target_queue(void *ctxt)
{
	dispatch_queue_t dq = _dispatch_queue_get_current();
	dispatch_queue_t tq = ctxt;
	dispatch_queue_t otq = dq->do_targetq;

	if (_dispatch_queue_atomic_flags(dq) & DQF_TARGETED) {
#if DISPATCH_ALLOW_NON_LEAF_RETARGET
		_dispatch_ktrace3(DISPATCH_PERF_non_leaf_retarget, dq, otq, tq);
		_dispatch_bug_deprecated("Changing the target of a queue "
				"already targeted by other dispatch objects");
#else
		DISPATCH_CLIENT_CRASH(0, "Cannot change the target of a queue "
				"already targeted by other dispatch objects");
#endif
	}

	_dispatch_queue_priority_inherit_from_target(dq, tq);
	_dispatch_queue_inherit_wlh_from_target(dq, tq);
#if HAVE_PTHREAD_WORKQUEUE_QOS
	// see _dispatch_queue_class_wakeup()
	_dispatch_queue_sidelock_lock(dq);
#endif
	dq->do_targetq = tq;
#if HAVE_PTHREAD_WORKQUEUE_QOS
	// see _dispatch_queue_class_wakeup()
	_dispatch_queue_sidelock_unlock(dq);
#endif

	_dispatch_object_debug(dq, "%s", __func__);
	_dispatch_introspection_target_queue_changed(dq);
	_dispatch_release_tailcall(otq);
}

void
_dispatch_queue_set_target_queue(dispatch_queue_t dq, dispatch_queue_t tq)
{
	dispatch_assert(dq->do_ref_cnt != DISPATCH_OBJECT_GLOBAL_REFCNT &&
			dq->do_targetq);

	if (unlikely(!tq)) {
		bool is_concurrent_q = (dq->dq_width > 1);
		tq = _dispatch_get_root_queue(DISPATCH_QOS_DEFAULT, !is_concurrent_q);
	}

	if (_dispatch_queue_try_inactive_suspend(dq)) {
		_dispatch_object_set_target_queue_inline(dq, tq);
		return dx_vtable(dq)->do_resume(dq, false);
	}

#if !DISPATCH_ALLOW_NON_LEAF_RETARGET
	if (_dispatch_queue_atomic_flags(dq) & DQF_TARGETED) {
		DISPATCH_CLIENT_CRASH(0, "Cannot change the target of a queue "
				"already targeted by other dispatch objects");
	}
#endif

	if (unlikely(!_dispatch_queue_is_legacy(dq))) {
#if DISPATCH_ALLOW_NON_LEAF_RETARGET
		if (_dispatch_queue_atomic_flags(dq) & DQF_TARGETED) {
			DISPATCH_CLIENT_CRASH(0, "Cannot change the target of a queue "
					"already targeted by other dispatch objects");
		}
#endif
		DISPATCH_CLIENT_CRASH(0, "Cannot change the target of this object "
				"after it has been activated");
	}

	unsigned long type = dx_type(dq);
	switch (type) {
	case DISPATCH_QUEUE_LEGACY_TYPE:
#if DISPATCH_ALLOW_NON_LEAF_RETARGET
		if (_dispatch_queue_atomic_flags(dq) & DQF_TARGETED) {
			_dispatch_bug_deprecated("Changing the target of a queue "
					"already targeted by other dispatch objects");
		}
#endif
		break;
	case DISPATCH_SOURCE_KEVENT_TYPE:
	case DISPATCH_MACH_CHANNEL_TYPE:
		_dispatch_ktrace1(DISPATCH_PERF_post_activate_retarget, dq);
		_dispatch_bug_deprecated("Changing the target of a source "
				"after it has been activated");
		break;
	default:
		DISPATCH_CLIENT_CRASH(type, "Unexpected dispatch object type");
	}

	_dispatch_retain(tq);
	return _dispatch_barrier_trysync_or_async_f(dq, tq,
			_dispatch_queue_legacy_set_target_queue);
}

#pragma mark -
#pragma mark dispatch_mgr_queue

#if DISPATCH_USE_MGR_THREAD && DISPATCH_ENABLE_PTHREAD_ROOT_QUEUES
static struct dispatch_pthread_root_queue_context_s
		_dispatch_mgr_root_queue_pthread_context;
static struct dispatch_root_queue_context_s
		_dispatch_mgr_root_queue_context = {{{
#if DISPATCH_USE_WORKQUEUES
	.dgq_kworkqueue = (void*)(~0ul),
#endif
	.dgq_ctxt = &_dispatch_mgr_root_queue_pthread_context,
	.dgq_thread_pool_size = 1,
}}};

static struct dispatch_queue_s _dispatch_mgr_root_queue = {
	DISPATCH_GLOBAL_OBJECT_HEADER(queue_root),
	.dq_state = DISPATCH_ROOT_QUEUE_STATE_INIT_VALUE,
	.do_ctxt = &_dispatch_mgr_root_queue_context,
	.dq_label = "com.apple.root.libdispatch-manager",
	.dq_atomic_flags = DQF_WIDTH(DISPATCH_QUEUE_WIDTH_POOL),
	.dq_priority = DISPATCH_PRIORITY_FLAG_MANAGER |
			DISPATCH_PRIORITY_SATURATED_OVERRIDE,
	.dq_serialnum = 3,
};
#endif // DISPATCH_USE_MGR_THREAD && DISPATCH_ENABLE_PTHREAD_ROOT_QUEUES

#if DISPATCH_ENABLE_PTHREAD_ROOT_QUEUES || DISPATCH_USE_KEVENT_WORKQUEUE
static struct {
	volatile int prio;
	volatile qos_class_t qos;
	int default_prio;
	int policy;
#if defined(_WIN32)
	HANDLE hThread;
#else
	pthread_t tid;
#endif
} _dispatch_mgr_sched;

static dispatch_once_t _dispatch_mgr_sched_pred;

#if HAVE_PTHREAD_WORKQUEUE_QOS
// TODO: switch to "event-reflector thread" property <rdar://problem/18126138>
// Must be kept in sync with list of qos classes in sys/qos.h
static const int _dispatch_mgr_sched_qos2prio[] = {
	[QOS_CLASS_MAINTENANCE] = 4,
	[QOS_CLASS_BACKGROUND] = 4,
	[QOS_CLASS_UTILITY] = 20,
	[QOS_CLASS_DEFAULT] = 31,
	[QOS_CLASS_USER_INITIATED] = 37,
	[QOS_CLASS_USER_INTERACTIVE] = 47,
};
#endif // HAVE_PTHREAD_WORKQUEUE_QOS

#if defined(_WIN32)
static void
_dispatch_mgr_sched_init(void *ctx DISPATCH_UNUSED)
{
	_dispatch_mgr_sched.policy = 0;
	_dispatch_mgr_sched.default_prio = THREAD_PRIORITY_NORMAL;
	_dispatch_mgr_sched.prio = _dispatch_mgr_sched.default_prio;
}
#else
static void
_dispatch_mgr_sched_init(void *ctxt DISPATCH_UNUSED)
{
	struct sched_param param;
#if DISPATCH_USE_MGR_THREAD && DISPATCH_ENABLE_PTHREAD_ROOT_QUEUES
	pthread_attr_t *attr;
	attr = &_dispatch_mgr_root_queue_pthread_context.dpq_thread_attr;
#else
	pthread_attr_t a, *attr = &a;
#endif
	(void)dispatch_assume_zero(pthread_attr_init(attr));
	(void)dispatch_assume_zero(pthread_attr_getschedpolicy(attr,
			&_dispatch_mgr_sched.policy));
	(void)dispatch_assume_zero(pthread_attr_getschedparam(attr, &param));
#if HAVE_PTHREAD_WORKQUEUE_QOS
	qos_class_t qos = qos_class_main();
	if (qos == QOS_CLASS_DEFAULT) {
		qos = QOS_CLASS_USER_INITIATED; // rdar://problem/17279292
	}
	if (qos) {
		_dispatch_mgr_sched.qos = qos;
		param.sched_priority = _dispatch_mgr_sched_qos2prio[qos];
	}
#endif
	_dispatch_mgr_sched.default_prio = param.sched_priority;
	_dispatch_mgr_sched.prio = _dispatch_mgr_sched.default_prio;
}
#endif /* defined(_WIN32) */
#endif // DISPATCH_ENABLE_PTHREAD_ROOT_QUEUES || DISPATCH_USE_KEVENT_WORKQUEUE

#if DISPATCH_USE_MGR_THREAD && DISPATCH_ENABLE_PTHREAD_ROOT_QUEUES
#if defined(_WIN32)
DISPATCH_NOINLINE
static PHANDLE
_dispatch_mgr_root_queue_init(void)
{
	dispatch_once_f(&_dispatch_mgr_sched_pred, NULL, _dispatch_mgr_sched_init);
	return &_dispatch_mgr_sched.hThread;
}
#else
DISPATCH_NOINLINE
static pthread_t *
_dispatch_mgr_root_queue_init(void)
{
	dispatch_once_f(&_dispatch_mgr_sched_pred, NULL, _dispatch_mgr_sched_init);
	struct sched_param param;
	pthread_attr_t *attr;
	attr = &_dispatch_mgr_root_queue_pthread_context.dpq_thread_attr;
	(void)dispatch_assume_zero(pthread_attr_setdetachstate(attr,
			PTHREAD_CREATE_DETACHED));
#if !DISPATCH_DEBUG
	(void)dispatch_assume_zero(pthread_attr_setstacksize(attr, 64 * 1024));
#endif
#if HAVE_PTHREAD_WORKQUEUE_QOS
	qos_class_t qos = _dispatch_mgr_sched.qos;
	if (qos) {
		if (_dispatch_set_qos_class_enabled) {
			(void)dispatch_assume_zero(pthread_attr_set_qos_class_np(attr,
					qos, 0));
		}
	}
#endif
	param.sched_priority = _dispatch_mgr_sched.prio;
	if (param.sched_priority > _dispatch_mgr_sched.default_prio) {
		(void)dispatch_assume_zero(pthread_attr_setschedparam(attr, &param));
	}
	return &_dispatch_mgr_sched.tid;
}
#endif

static inline void
_dispatch_mgr_priority_apply(void)
{
#if defined(_WIN32)
	int nPriority = _dispatch_mgr_sched.prio;
	do {
		if (nPriority > _dispatch_mgr_sched.default_prio) {
			// TODO(compnerd) set thread scheduling policy
			dispatch_assume_zero(SetThreadPriority(_dispatch_mgr_sched.hThread, nPriority));
			nPriority = GetThreadPriority(_dispatch_mgr_sched.hThread);
		}
	} while (_dispatch_mgr_sched.prio > nPriority);
#else
	struct sched_param param;
	do {
		param.sched_priority = _dispatch_mgr_sched.prio;
		if (param.sched_priority > _dispatch_mgr_sched.default_prio) {
			(void)dispatch_assume_zero(pthread_setschedparam(
					_dispatch_mgr_sched.tid, _dispatch_mgr_sched.policy,
					&param));
		}
	} while (_dispatch_mgr_sched.prio > param.sched_priority);
#endif
}

DISPATCH_NOINLINE
void
_dispatch_mgr_priority_init(void)
{
#if defined(_WIN32)
	int nPriority = GetThreadPriority(_dispatch_mgr_sched.hThread);
	if (slowpath(_dispatch_mgr_sched.prio > nPriority)) {
		return _dispatch_mgr_priority_apply();
	}
#else
	struct sched_param param;
	pthread_attr_t *attr;
	attr = &_dispatch_mgr_root_queue_pthread_context.dpq_thread_attr;
	(void)dispatch_assume_zero(pthread_attr_getschedparam(attr, &param));
#if HAVE_PTHREAD_WORKQUEUE_QOS
	qos_class_t qos = 0;
	(void)pthread_attr_get_qos_class_np(attr, &qos, NULL);
	if (_dispatch_mgr_sched.qos > qos && _dispatch_set_qos_class_enabled) {
		(void)pthread_set_qos_class_self_np(_dispatch_mgr_sched.qos, 0);
		int p = _dispatch_mgr_sched_qos2prio[_dispatch_mgr_sched.qos];
		if (p > param.sched_priority) {
			param.sched_priority = p;
		}
	}
#endif
	if (slowpath(_dispatch_mgr_sched.prio > param.sched_priority)) {
		return _dispatch_mgr_priority_apply();
	}
#endif
}
#endif // DISPATCH_USE_MGR_THREAD && DISPATCH_ENABLE_PTHREAD_ROOT_QUEUES

#if !defined(_WIN32)
#if DISPATCH_ENABLE_PTHREAD_ROOT_QUEUES
DISPATCH_NOINLINE
static void
_dispatch_mgr_priority_raise(const pthread_attr_t *attr)
{
	dispatch_once_f(&_dispatch_mgr_sched_pred, NULL, _dispatch_mgr_sched_init);
	struct sched_param param;
	(void)dispatch_assume_zero(pthread_attr_getschedparam(attr, &param));
#if HAVE_PTHREAD_WORKQUEUE_QOS
	qos_class_t q, qos = 0;
	(void)pthread_attr_get_qos_class_np((pthread_attr_t *)attr, &qos, NULL);
	if (qos) {
		param.sched_priority = _dispatch_mgr_sched_qos2prio[qos];
		os_atomic_rmw_loop2o(&_dispatch_mgr_sched, qos, q, qos, relaxed, {
			if (q >= qos) os_atomic_rmw_loop_give_up(break);
		});
	}
#endif
	int p, prio = param.sched_priority;
	os_atomic_rmw_loop2o(&_dispatch_mgr_sched, prio, p, prio, relaxed, {
		if (p >= prio) os_atomic_rmw_loop_give_up(return);
	});
#if DISPATCH_USE_KEVENT_WORKQUEUE
	_dispatch_root_queues_init();
	if (_dispatch_kevent_workqueue_enabled) {
		pthread_priority_t pp = 0;
		if (prio > _dispatch_mgr_sched.default_prio) {
			// The values of _PTHREAD_PRIORITY_SCHED_PRI_FLAG and
			// _PTHREAD_PRIORITY_ROOTQUEUE_FLAG overlap, but that is not
			// problematic in this case, since it the second one is only ever
			// used on dq_priority fields.
			// We never pass the _PTHREAD_PRIORITY_ROOTQUEUE_FLAG to a syscall,
			// it is meaningful to libdispatch only.
			pp = (pthread_priority_t)prio | _PTHREAD_PRIORITY_SCHED_PRI_FLAG;
		} else if (qos) {
			pp = _pthread_qos_class_encode(qos, 0, 0);
		}
		if (pp) {
			int r = _pthread_workqueue_set_event_manager_priority(pp);
			(void)dispatch_assume_zero(r);
		}
		return;
	}
#endif
#if DISPATCH_USE_MGR_THREAD
	if (_dispatch_mgr_sched.tid) {
		return _dispatch_mgr_priority_apply();
	}
#endif
}
#endif // DISPATCH_ENABLE_PTHREAD_ROOT_QUEUES
#endif

#if DISPATCH_USE_KEVENT_WORKQUEUE
void
_dispatch_kevent_workqueue_init(void)
{
	// Initialize kevent workqueue support
	_dispatch_root_queues_init();
	if (!_dispatch_kevent_workqueue_enabled) return;
	dispatch_once_f(&_dispatch_mgr_sched_pred, NULL, _dispatch_mgr_sched_init);
	qos_class_t qos = _dispatch_mgr_sched.qos;
	int prio = _dispatch_mgr_sched.prio;
	pthread_priority_t pp = 0;
	if (qos) {
		pp = _pthread_qos_class_encode(qos, 0, 0);
	}
	if (prio > _dispatch_mgr_sched.default_prio) {
		pp = (pthread_priority_t)prio | _PTHREAD_PRIORITY_SCHED_PRI_FLAG;
	}
	if (pp) {
		int r = _pthread_workqueue_set_event_manager_priority(pp);
		(void)dispatch_assume_zero(r);
	}
}
#endif // DISPATCH_USE_KEVENT_WORKQUEUE

#pragma mark -
#pragma mark dispatch_pthread_root_queue

#if DISPATCH_ENABLE_PTHREAD_ROOT_QUEUES
static dispatch_queue_t
_dispatch_pthread_root_queue_create(const char *label, unsigned long flags,
		const pthread_attr_t *attr, dispatch_block_t configure,
		dispatch_pthread_root_queue_observer_hooks_t observer_hooks)
{
	dispatch_queue_t dq;
	dispatch_root_queue_context_t qc;
	dispatch_pthread_root_queue_context_t pqc;
	dispatch_queue_flags_t dqf = 0;
	size_t dqs;
	int32_t pool_size = flags & _DISPATCH_PTHREAD_ROOT_QUEUE_FLAG_POOL_SIZE ?
			(int8_t)(flags & ~_DISPATCH_PTHREAD_ROOT_QUEUE_FLAG_POOL_SIZE) : 0;

	dqs = sizeof(struct dispatch_queue_s) - DISPATCH_QUEUE_CACHELINE_PAD;
	dqs = roundup(dqs, _Alignof(struct dispatch_root_queue_context_s));
	dq = _dispatch_object_alloc(DISPATCH_VTABLE(queue_root), dqs +
			sizeof(struct dispatch_root_queue_context_s) +
			sizeof(struct dispatch_pthread_root_queue_context_s));
	qc = (void*)dq + dqs;
	dispatch_assert((uintptr_t)qc % _Alignof(__typeof__(*qc)) == 0);
	pqc = (void*)qc + sizeof(struct dispatch_root_queue_context_s);
	dispatch_assert((uintptr_t)pqc % _Alignof(__typeof__(*pqc)) == 0);
	if (label) {
		const char *tmp = _dispatch_strdup_if_mutable(label);
		if (tmp != label) {
			dqf |= DQF_LABEL_NEEDS_FREE;
			label = tmp;
		}
	}

	_dispatch_queue_init(dq, dqf, DISPATCH_QUEUE_WIDTH_POOL, 0);
	dq->dq_label = label;
	dq->dq_state = DISPATCH_ROOT_QUEUE_STATE_INIT_VALUE;
	dq->do_ctxt = qc;
	dq->dq_priority = DISPATCH_PRIORITY_SATURATED_OVERRIDE;

	pqc->dpq_thread_mediator.do_vtable = DISPATCH_VTABLE(semaphore);
	qc->dgq_ctxt = pqc;
#if DISPATCH_USE_WORKQUEUES
	qc->dgq_kworkqueue = (void*)(~0ul);
#endif
	_dispatch_root_queue_init_pthread_pool(qc, pool_size, true);

#if defined(_WIN32)
	dispatch_assert(attr == NULL);
#else
	if (attr) {
		memcpy(&pqc->dpq_thread_attr, attr, sizeof(pthread_attr_t));
		_dispatch_mgr_priority_raise(&pqc->dpq_thread_attr);
	} else {
		(void)dispatch_assume_zero(pthread_attr_init(&pqc->dpq_thread_attr));
	}
	(void)dispatch_assume_zero(pthread_attr_setdetachstate(
			&pqc->dpq_thread_attr, PTHREAD_CREATE_DETACHED));
#endif
	if (configure) {
		pqc->dpq_thread_configure = _dispatch_Block_copy(configure);
	}
	if (observer_hooks) {
		pqc->dpq_observer_hooks = *observer_hooks;
	}
	_dispatch_object_debug(dq, "%s", __func__);
	return _dispatch_introspection_queue_create(dq);
}

dispatch_queue_t
dispatch_pthread_root_queue_create(const char *label, unsigned long flags,
		const pthread_attr_t *attr, dispatch_block_t configure)
{
#if defined(_WIN32)
	dispatch_assert(attr == NULL);
#endif
	return _dispatch_pthread_root_queue_create(label, flags, attr, configure,
			NULL);
}

#if DISPATCH_IOHID_SPI
dispatch_queue_t
_dispatch_pthread_root_queue_create_with_observer_hooks_4IOHID(const char *label,
		unsigned long flags, const pthread_attr_t *attr,
		dispatch_pthread_root_queue_observer_hooks_t observer_hooks,
		dispatch_block_t configure)
{
	if (!observer_hooks->queue_will_execute ||
			!observer_hooks->queue_did_execute) {
		DISPATCH_CLIENT_CRASH(0, "Invalid pthread root queue observer hooks");
	}
	return _dispatch_pthread_root_queue_create(label, flags, attr, configure,
			observer_hooks);
}
#endif

dispatch_queue_t
dispatch_pthread_root_queue_copy_current(void)
{
	dispatch_queue_t dq = _dispatch_queue_get_current();
	if (!dq) return NULL;
	while (unlikely(dq->do_targetq)) {
		dq = dq->do_targetq;
	}
	if (dx_type(dq) != DISPATCH_QUEUE_GLOBAL_ROOT_TYPE ||
			dq->do_xref_cnt == DISPATCH_OBJECT_GLOBAL_REFCNT) {
		return NULL;
	}
	return (dispatch_queue_t)_os_object_retain_with_resurrect(dq->_as_os_obj);
}

#endif // DISPATCH_ENABLE_PTHREAD_ROOT_QUEUES

void
_dispatch_pthread_root_queue_dispose(dispatch_queue_t dq, bool *allow_free)
{
	if (slowpath(dq->do_ref_cnt == DISPATCH_OBJECT_GLOBAL_REFCNT)) {
		DISPATCH_INTERNAL_CRASH(dq, "Global root queue disposed");
	}
	_dispatch_object_debug(dq, "%s", __func__);
	_dispatch_introspection_queue_dispose(dq);
#if DISPATCH_USE_PTHREAD_POOL
	dispatch_root_queue_context_t qc = dq->do_ctxt;
	dispatch_pthread_root_queue_context_t pqc = qc->dgq_ctxt;

#if !defined(_WIN32)
	pthread_attr_destroy(&pqc->dpq_thread_attr);
#endif
	_dispatch_semaphore_dispose(&pqc->dpq_thread_mediator, NULL);
	if (pqc->dpq_thread_configure) {
		Block_release(pqc->dpq_thread_configure);
	}
	dq->do_targetq = _dispatch_get_root_queue(DISPATCH_QOS_DEFAULT, false);
#endif
	if (dq->dq_label && _dispatch_queue_label_needs_free(dq)) {
		free((void*)dq->dq_label);
	}
	_dispatch_queue_destroy(dq, allow_free);
}

#pragma mark -
#pragma mark dispatch_queue_specific

struct dispatch_queue_specific_queue_s {
	DISPATCH_QUEUE_HEADER(queue_specific_queue);
	TAILQ_HEAD(dispatch_queue_specific_head_s,
			dispatch_queue_specific_s) dqsq_contexts;
} DISPATCH_ATOMIC64_ALIGN;

struct dispatch_queue_specific_s {
	const void *dqs_key;
	void *dqs_ctxt;
	dispatch_function_t dqs_destructor;
	TAILQ_ENTRY(dispatch_queue_specific_s) dqs_list;
};
DISPATCH_DECL(dispatch_queue_specific);

void
_dispatch_queue_specific_queue_dispose(dispatch_queue_specific_queue_t dqsq,
		bool *allow_free)
{
	dispatch_queue_specific_t dqs, tmp;
	dispatch_queue_t rq = _dispatch_get_root_queue(DISPATCH_QOS_DEFAULT, false);

	TAILQ_FOREACH_SAFE(dqs, &dqsq->dqsq_contexts, dqs_list, tmp) {
		if (dqs->dqs_destructor) {
			dispatch_async_f(rq, dqs->dqs_ctxt, dqs->dqs_destructor);
		}
		free(dqs);
	}
	_dispatch_queue_destroy(dqsq->_as_dq, allow_free);
}

static void
_dispatch_queue_init_specific(dispatch_queue_t dq)
{
	dispatch_queue_specific_queue_t dqsq;

	dqsq = _dispatch_object_alloc(DISPATCH_VTABLE(queue_specific_queue),
			sizeof(struct dispatch_queue_specific_queue_s));
	_dispatch_queue_init(dqsq->_as_dq, DQF_NONE, DISPATCH_QUEUE_WIDTH_MAX,
			DISPATCH_QUEUE_ROLE_BASE_ANON);
	dqsq->do_xref_cnt = -1;
	dqsq->do_targetq = _dispatch_get_root_queue(
			DISPATCH_QOS_USER_INITIATED, true);
	dqsq->dq_label = "queue-specific";
	TAILQ_INIT(&dqsq->dqsq_contexts);
	if (slowpath(!os_atomic_cmpxchg2o(dq, dq_specific_q, NULL,
			dqsq->_as_dq, release))) {
		_dispatch_release(dqsq->_as_dq);
	}
}

static void
_dispatch_queue_set_specific(void *ctxt)
{
	dispatch_queue_specific_t dqs, dqsn = ctxt;
	dispatch_queue_specific_queue_t dqsq =
			(dispatch_queue_specific_queue_t)_dispatch_queue_get_current();

	TAILQ_FOREACH(dqs, &dqsq->dqsq_contexts, dqs_list) {
		if (dqs->dqs_key == dqsn->dqs_key) {
			// Destroy previous context for existing key
			if (dqs->dqs_destructor) {
				dispatch_async_f(_dispatch_get_root_queue(
						DISPATCH_QOS_DEFAULT, false), dqs->dqs_ctxt,
						dqs->dqs_destructor);
			}
			if (dqsn->dqs_ctxt) {
				// Copy new context for existing key
				dqs->dqs_ctxt = dqsn->dqs_ctxt;
				dqs->dqs_destructor = dqsn->dqs_destructor;
			} else {
				// Remove context storage for existing key
				TAILQ_REMOVE(&dqsq->dqsq_contexts, dqs, dqs_list);
				free(dqs);
			}
			return free(dqsn);
		}
	}
	// Insert context storage for new key
	TAILQ_INSERT_TAIL(&dqsq->dqsq_contexts, dqsn, dqs_list);
}

DISPATCH_NOINLINE
void
dispatch_queue_set_specific(dispatch_queue_t dq, const void *key,
	void *ctxt, dispatch_function_t destructor)
{
	if (slowpath(!key)) {
		return;
	}
	dispatch_queue_specific_t dqs;

	dqs = _dispatch_calloc(1, sizeof(struct dispatch_queue_specific_s));
	dqs->dqs_key = key;
	dqs->dqs_ctxt = ctxt;
	dqs->dqs_destructor = destructor;
	if (slowpath(!dq->dq_specific_q)) {
		_dispatch_queue_init_specific(dq);
	}
	_dispatch_barrier_trysync_or_async_f(dq->dq_specific_q, dqs,
			_dispatch_queue_set_specific);
}

static void
_dispatch_queue_get_specific(void *ctxt)
{
	void **ctxtp = ctxt;
	void *key = *ctxtp;
	dispatch_queue_specific_queue_t dqsq =
			(dispatch_queue_specific_queue_t)_dispatch_queue_get_current();
	dispatch_queue_specific_t dqs;

	TAILQ_FOREACH(dqs, &dqsq->dqsq_contexts, dqs_list) {
		if (dqs->dqs_key == key) {
			*ctxtp = dqs->dqs_ctxt;
			return;
		}
	}
	*ctxtp = NULL;
}

DISPATCH_ALWAYS_INLINE
static inline void *
_dispatch_queue_get_specific_inline(dispatch_queue_t dq, const void *key)
{
	void *ctxt = NULL;
	if (fastpath(dx_metatype(dq) == _DISPATCH_QUEUE_TYPE && dq->dq_specific_q)){
		ctxt = (void *)key;
		dispatch_sync_f(dq->dq_specific_q, &ctxt, _dispatch_queue_get_specific);
	}
	return ctxt;
}

DISPATCH_NOINLINE
void *
dispatch_queue_get_specific(dispatch_queue_t dq, const void *key)
{
	if (slowpath(!key)) {
		return NULL;
	}
	return _dispatch_queue_get_specific_inline(dq, key);
}

DISPATCH_NOINLINE
void *
dispatch_get_specific(const void *key)
{
	if (slowpath(!key)) {
		return NULL;
	}
	void *ctxt = NULL;
	dispatch_queue_t dq = _dispatch_queue_get_current();

	while (slowpath(dq)) {
		ctxt = _dispatch_queue_get_specific_inline(dq, key);
		if (ctxt) break;
		dq = dq->do_targetq;
	}
	return ctxt;
}

#if DISPATCH_IOHID_SPI
bool
_dispatch_queue_is_exclusively_owned_by_current_thread_4IOHID(
		dispatch_queue_t dq) // rdar://problem/18033810
{
	if (dq->dq_width != 1) {
		DISPATCH_CLIENT_CRASH(dq->dq_width, "Invalid queue type");
	}
	uint64_t dq_state = os_atomic_load2o(dq, dq_state, relaxed);
	return _dq_state_drain_locked_by_self(dq_state);
}
#endif

#pragma mark -
#pragma mark dispatch_queue_debug

size_t
_dispatch_queue_debug_attr(dispatch_queue_t dq, char* buf, size_t bufsiz)
{
	size_t offset = 0;
	dispatch_queue_t target = dq->do_targetq;
	const char *tlabel = target && target->dq_label ? target->dq_label : "";
	uint64_t dq_state = os_atomic_load2o(dq, dq_state, relaxed);

	offset += dsnprintf(&buf[offset], bufsiz - offset, "sref = %d, "
			"target = %s[%p], width = 0x%x, state = 0x%016llx",
			dq->dq_sref_cnt + 1, tlabel, target, dq->dq_width,
			(unsigned long long)dq_state);
	if (_dq_state_is_suspended(dq_state)) {
		offset += dsnprintf(&buf[offset], bufsiz - offset, ", suspended = %d",
			_dq_state_suspend_cnt(dq_state));
	}
	if (_dq_state_is_inactive(dq_state)) {
		offset += dsnprintf(&buf[offset], bufsiz - offset, ", inactive");
	} else if (_dq_state_needs_activation(dq_state)) {
		offset += dsnprintf(&buf[offset], bufsiz - offset, ", needs-activation");
	}
	if (_dq_state_is_enqueued(dq_state)) {
		offset += dsnprintf(&buf[offset], bufsiz - offset, ", enqueued");
	}
	if (_dq_state_is_dirty(dq_state)) {
		offset += dsnprintf(&buf[offset], bufsiz - offset, ", dirty");
	}
	dispatch_qos_t qos = _dq_state_max_qos(dq_state);
	if (qos) {
		offset += dsnprintf(&buf[offset], bufsiz - offset, ", max qos %d", qos);
	}
	mach_port_t owner = _dq_state_drain_owner(dq_state);
	if (!_dispatch_queue_is_thread_bound(dq) && owner) {
		offset += dsnprintf(&buf[offset], bufsiz - offset, ", draining on 0x%x",
				owner);
	}
	if (_dq_state_is_in_barrier(dq_state)) {
		offset += dsnprintf(&buf[offset], bufsiz - offset, ", in-barrier");
	} else  {
		offset += dsnprintf(&buf[offset], bufsiz - offset, ", in-flight = %d",
				_dq_state_used_width(dq_state, dq->dq_width));
	}
	if (_dq_state_has_pending_barrier(dq_state)) {
		offset += dsnprintf(&buf[offset], bufsiz - offset, ", pending-barrier");
	}
	if (_dispatch_queue_is_thread_bound(dq)) {
		offset += dsnprintf(&buf[offset], bufsiz - offset, ", thread = 0x%x ",
				owner);
	}
	return offset;
}

size_t
dispatch_queue_debug(dispatch_queue_t dq, char* buf, size_t bufsiz)
{
	size_t offset = 0;
	offset += dsnprintf(&buf[offset], bufsiz - offset, "%s[%p] = { ",
			dq->dq_label ? dq->dq_label : dx_kind(dq), dq);
	offset += _dispatch_object_debug_attr(dq, &buf[offset], bufsiz - offset);
	offset += _dispatch_queue_debug_attr(dq, &buf[offset], bufsiz - offset);
	offset += dsnprintf(&buf[offset], bufsiz - offset, "}");
	return offset;
}

#if DISPATCH_DEBUG
void
dispatch_debug_queue(dispatch_queue_t dq, const char* str) {
	if (fastpath(dq)) {
		_dispatch_object_debug(dq, "%s", str);
	} else {
		_dispatch_log("queue[NULL]: %s", str);
	}
}
#endif

#if DISPATCH_PERF_MON

#define DISPATCH_PERF_MON_BUCKETS 8

static struct {
	uint64_t volatile time_total;
	uint64_t volatile count_total;
	uint64_t volatile thread_total;
} _dispatch_stats[DISPATCH_PERF_MON_BUCKETS];
DISPATCH_USED static size_t _dispatch_stat_buckets = DISPATCH_PERF_MON_BUCKETS;

void
_dispatch_queue_merge_stats(uint64_t start, bool trace, perfmon_thread_type type)
{
	uint64_t delta = _dispatch_absolute_time() - start;
	unsigned long count;
	int bucket = 0;
	count = (unsigned long)_dispatch_thread_getspecific(dispatch_bcounter_key);
	_dispatch_thread_setspecific(dispatch_bcounter_key, NULL);
	if (count == 0) {
		bucket = 0;
		if (trace) _dispatch_ktrace1(DISPATCH_PERF_MON_worker_useless, type);
	} else {
		bucket = MIN(DISPATCH_PERF_MON_BUCKETS - 1,
					 (int)sizeof(count) * CHAR_BIT - __builtin_clzl(count));
		os_atomic_add(&_dispatch_stats[bucket].count_total, count, relaxed);
	}
	os_atomic_add(&_dispatch_stats[bucket].time_total, delta, relaxed);
	os_atomic_inc(&_dispatch_stats[bucket].thread_total, relaxed);
	if (trace) {
		_dispatch_ktrace3(DISPATCH_PERF_MON_worker_thread_end, count, delta, type);
	}
}

#endif

#pragma mark -
#pragma mark _dispatch_set_priority_and_mach_voucher
#if HAVE_PTHREAD_WORKQUEUE_QOS

DISPATCH_NOINLINE
void
_dispatch_set_priority_and_mach_voucher_slow(pthread_priority_t pp,
		mach_voucher_t kv)
{
	_pthread_set_flags_t pflags = 0;
	if (pp && _dispatch_set_qos_class_enabled) {
		pthread_priority_t old_pri = _dispatch_get_priority();
		if (pp != old_pri) {
			if (old_pri & _PTHREAD_PRIORITY_NEEDS_UNBIND_FLAG) {
				pflags |= _PTHREAD_SET_SELF_WQ_KEVENT_UNBIND;
				// when we unbind, overcomitness can flip, so we need to learn
				// it from the defaultpri, see _dispatch_priority_compute_update
				pp |= (_dispatch_get_basepri() &
						DISPATCH_PRIORITY_FLAG_OVERCOMMIT);
			} else {
				// else we need to keep the one that is set in the current pri
				pp |= (old_pri & _PTHREAD_PRIORITY_OVERCOMMIT_FLAG);
			}
			if (likely(old_pri & ~_PTHREAD_PRIORITY_FLAGS_MASK)) {
				pflags |= _PTHREAD_SET_SELF_QOS_FLAG;
			}
			uint64_t mgr_dq_state =
					os_atomic_load2o(&_dispatch_mgr_q, dq_state, relaxed);
			if (unlikely(_dq_state_drain_locked_by_self(mgr_dq_state))) {
				DISPATCH_INTERNAL_CRASH(pp,
						"Changing the QoS while on the manager queue");
			}
			if (unlikely(pp & _PTHREAD_PRIORITY_EVENT_MANAGER_FLAG)) {
				DISPATCH_INTERNAL_CRASH(pp, "Cannot raise oneself to manager");
			}
			if (old_pri & _PTHREAD_PRIORITY_EVENT_MANAGER_FLAG) {
				DISPATCH_INTERNAL_CRASH(old_pri,
						"Cannot turn a manager thread into a normal one");
			}
		}
	}
	if (kv != VOUCHER_NO_MACH_VOUCHER) {
#if VOUCHER_USE_MACH_VOUCHER
		pflags |= _PTHREAD_SET_SELF_VOUCHER_FLAG;
#endif
	}
	if (!pflags) return;
	int r = _pthread_set_properties_self(pflags, pp, kv);
	if (r == EINVAL) {
		DISPATCH_INTERNAL_CRASH(pp, "_pthread_set_properties_self failed");
	}
	(void)dispatch_assume_zero(r);
}

DISPATCH_NOINLINE
voucher_t
_dispatch_set_priority_and_voucher_slow(pthread_priority_t priority,
		voucher_t v, dispatch_thread_set_self_t flags)
{
	voucher_t ov = DISPATCH_NO_VOUCHER;
	mach_voucher_t kv = VOUCHER_NO_MACH_VOUCHER;
	if (v != DISPATCH_NO_VOUCHER) {
		bool retained = flags & DISPATCH_VOUCHER_CONSUME;
		ov = _voucher_get();
		if (ov == v && (flags & DISPATCH_VOUCHER_REPLACE)) {
			if (retained && v) _voucher_release_no_dispose(v);
			ov = DISPATCH_NO_VOUCHER;
		} else {
			if (!retained && v) _voucher_retain(v);
			kv = _voucher_swap_and_get_mach_voucher(ov, v);
		}
	}
	if (!(flags & DISPATCH_THREAD_PARK)) {
		_dispatch_set_priority_and_mach_voucher_slow(priority, kv);
	}
	if (ov != DISPATCH_NO_VOUCHER && (flags & DISPATCH_VOUCHER_REPLACE)) {
		if (ov) _voucher_release(ov);
		ov = DISPATCH_NO_VOUCHER;
	}
	return ov;
}
#endif
#pragma mark -
#pragma mark dispatch_continuation_t

const struct dispatch_continuation_vtable_s _dispatch_continuation_vtables[] = {
	DC_VTABLE_ENTRY(ASYNC_REDIRECT,
		.do_kind = "dc-redirect",
		.do_invoke = _dispatch_async_redirect_invoke),
#if HAVE_MACH
	DC_VTABLE_ENTRY(MACH_SEND_BARRRIER_DRAIN,
		.do_kind = "dc-mach-send-drain",
		.do_invoke = _dispatch_mach_send_barrier_drain_invoke),
	DC_VTABLE_ENTRY(MACH_SEND_BARRIER,
		.do_kind = "dc-mach-send-barrier",
		.do_invoke = _dispatch_mach_barrier_invoke),
	DC_VTABLE_ENTRY(MACH_RECV_BARRIER,
		.do_kind = "dc-mach-recv-barrier",
		.do_invoke = _dispatch_mach_barrier_invoke),
	DC_VTABLE_ENTRY(MACH_ASYNC_REPLY,
		.do_kind = "dc-mach-async-reply",
		.do_invoke = _dispatch_mach_msg_async_reply_invoke),
#endif
#if HAVE_PTHREAD_WORKQUEUE_QOS
	DC_VTABLE_ENTRY(OVERRIDE_STEALING,
		.do_kind = "dc-override-stealing",
		.do_invoke = _dispatch_queue_override_invoke),
	DC_VTABLE_ENTRY(OVERRIDE_OWNING,
		.do_kind = "dc-override-owning",
		.do_invoke = _dispatch_queue_override_invoke),
#endif
};

static void
_dispatch_force_cache_cleanup(void)
{
	dispatch_continuation_t dc;
	dc = _dispatch_thread_getspecific(dispatch_cache_key);
	if (dc) {
		_dispatch_thread_setspecific(dispatch_cache_key, NULL);
		_dispatch_cache_cleanup(dc);
	}
}

DISPATCH_NOINLINE
static void DISPATCH_TSD_DTOR_CC
_dispatch_cache_cleanup(void *value)
{
	dispatch_continuation_t dc, next_dc = value;

	while ((dc = next_dc)) {
		next_dc = dc->do_next;
		_dispatch_continuation_free_to_heap(dc);
	}
}

#if DISPATCH_USE_MEMORYPRESSURE_SOURCE
DISPATCH_NOINLINE
void
_dispatch_continuation_free_to_cache_limit(dispatch_continuation_t dc)
{
	_dispatch_continuation_free_to_heap(dc);
	dispatch_continuation_t next_dc;
	dc = _dispatch_thread_getspecific(dispatch_cache_key);
	int cnt;
	if (!dc || (cnt = dc->dc_cache_cnt -
			_dispatch_continuation_cache_limit) <= 0) {
		return;
	}
	do {
		next_dc = dc->do_next;
		_dispatch_continuation_free_to_heap(dc);
	} while (--cnt && (dc = next_dc));
	_dispatch_thread_setspecific(dispatch_cache_key, next_dc);
}
#endif

DISPATCH_NOINLINE
static void
_dispatch_continuation_push(dispatch_queue_t dq, dispatch_continuation_t dc)
{
	dx_push(dq, dc, _dispatch_continuation_override_qos(dq, dc));
}

DISPATCH_ALWAYS_INLINE
static inline void
_dispatch_continuation_async2(dispatch_queue_t dq, dispatch_continuation_t dc,
		bool barrier)
{
	if (fastpath(barrier || !DISPATCH_QUEUE_USES_REDIRECTION(dq->dq_width))) {
		return _dispatch_continuation_push(dq, dc);
	}
	return _dispatch_async_f2(dq, dc);
}

DISPATCH_NOINLINE
void
_dispatch_continuation_async(dispatch_queue_t dq, dispatch_continuation_t dc)
{
	_dispatch_continuation_async2(dq, dc,
			dc->dc_flags & DISPATCH_OBJ_BARRIER_BIT);
}

#pragma mark -
#pragma mark dispatch_block_create

#if __BLOCKS__

DISPATCH_ALWAYS_INLINE
static inline bool
_dispatch_block_flags_valid(dispatch_block_flags_t flags)
{
	return ((flags & ~DISPATCH_BLOCK_API_MASK) == 0);
}

DISPATCH_ALWAYS_INLINE
static inline dispatch_block_flags_t
_dispatch_block_normalize_flags(dispatch_block_flags_t flags)
{
	if (flags & (DISPATCH_BLOCK_NO_VOUCHER|DISPATCH_BLOCK_DETACHED)) {
		flags |= DISPATCH_BLOCK_HAS_VOUCHER;
	}
	if (flags & (DISPATCH_BLOCK_NO_QOS_CLASS|DISPATCH_BLOCK_DETACHED)) {
		flags |= DISPATCH_BLOCK_HAS_PRIORITY;
	}
	return flags;
}

static inline dispatch_block_t
_dispatch_block_create_with_voucher_and_priority(dispatch_block_flags_t flags,
		voucher_t voucher, pthread_priority_t pri, dispatch_block_t block)
{
	flags = _dispatch_block_normalize_flags(flags);
	bool assign = (flags & DISPATCH_BLOCK_ASSIGN_CURRENT);

	if (assign && !(flags & DISPATCH_BLOCK_HAS_VOUCHER)) {
#if OS_VOUCHER_ACTIVITY_SPI
		voucher = VOUCHER_CURRENT;
#endif
		flags |= DISPATCH_BLOCK_HAS_VOUCHER;
	}
#if OS_VOUCHER_ACTIVITY_SPI
	if (voucher == VOUCHER_CURRENT) {
		voucher = _voucher_get();
	}
#endif
	if (assign && !(flags & DISPATCH_BLOCK_HAS_PRIORITY)) {
		pri = _dispatch_priority_propagate();
		flags |= DISPATCH_BLOCK_HAS_PRIORITY;
	}
	dispatch_block_t db = _dispatch_block_create(flags, voucher, pri, block);
#if DISPATCH_DEBUG
	dispatch_assert(_dispatch_block_get_data(db));
#endif
	return db;
}

dispatch_block_t
dispatch_block_create(dispatch_block_flags_t flags, dispatch_block_t block)
{
	if (!_dispatch_block_flags_valid(flags)) return DISPATCH_BAD_INPUT;
	return _dispatch_block_create_with_voucher_and_priority(flags, NULL, 0,
			block);
}

dispatch_block_t
dispatch_block_create_with_qos_class(dispatch_block_flags_t flags,
		dispatch_qos_class_t qos_class, int relative_priority,
		dispatch_block_t block)
{
	if (!_dispatch_block_flags_valid(flags) ||
			!_dispatch_qos_class_valid(qos_class, relative_priority)) {
		return DISPATCH_BAD_INPUT;
	}
	flags |= DISPATCH_BLOCK_HAS_PRIORITY;
	pthread_priority_t pri = 0;
#if HAVE_PTHREAD_WORKQUEUE_QOS
	pri = _pthread_qos_class_encode(qos_class, relative_priority, 0);
#endif
	return _dispatch_block_create_with_voucher_and_priority(flags, NULL,
			pri, block);
}

dispatch_block_t
dispatch_block_create_with_voucher(dispatch_block_flags_t flags,
		voucher_t voucher, dispatch_block_t block)
{
	if (!_dispatch_block_flags_valid(flags)) return DISPATCH_BAD_INPUT;
	flags |= DISPATCH_BLOCK_HAS_VOUCHER;
	return _dispatch_block_create_with_voucher_and_priority(flags, voucher, 0,
			block);
}

dispatch_block_t
dispatch_block_create_with_voucher_and_qos_class(dispatch_block_flags_t flags,
		voucher_t voucher, dispatch_qos_class_t qos_class,
		int relative_priority, dispatch_block_t block)
{
	if (!_dispatch_block_flags_valid(flags) ||
			!_dispatch_qos_class_valid(qos_class, relative_priority)) {
		return DISPATCH_BAD_INPUT;
	}
	flags |= (DISPATCH_BLOCK_HAS_VOUCHER|DISPATCH_BLOCK_HAS_PRIORITY);
	pthread_priority_t pri = 0;
#if HAVE_PTHREAD_WORKQUEUE_QOS
	pri = _pthread_qos_class_encode(qos_class, relative_priority, 0);
#endif
	return _dispatch_block_create_with_voucher_and_priority(flags, voucher,
			pri, block);
}

void
dispatch_block_perform(dispatch_block_flags_t flags, dispatch_block_t block)
{
	if (!_dispatch_block_flags_valid(flags)) {
		DISPATCH_CLIENT_CRASH(flags, "Invalid flags passed to "
				"dispatch_block_perform()");
	}
	flags = _dispatch_block_normalize_flags(flags);
	struct dispatch_block_private_data_s dbpds =
			DISPATCH_BLOCK_PRIVATE_DATA_PERFORM_INITIALIZER(flags, block);
	return _dispatch_block_invoke_direct(&dbpds);
}

#define _dbpd_group(dbpd) ((dbpd)->dbpd_group)

void
_dispatch_block_invoke_direct(const struct dispatch_block_private_data_s *dbcpd)
{
	dispatch_block_private_data_t dbpd = (dispatch_block_private_data_t)dbcpd;
	dispatch_block_flags_t flags = dbpd->dbpd_flags;
	unsigned int atomic_flags = dbpd->dbpd_atomic_flags;
	if (slowpath(atomic_flags & DBF_WAITED)) {
		DISPATCH_CLIENT_CRASH(atomic_flags, "A block object may not be both "
				"run more than once and waited for");
	}
	if (atomic_flags & DBF_CANCELED) goto out;

	pthread_priority_t op = 0, p = 0;
	op = _dispatch_block_invoke_should_set_priority(flags, dbpd->dbpd_priority);
	if (op) {
		p = dbpd->dbpd_priority;
	}
	voucher_t ov, v = DISPATCH_NO_VOUCHER;
	if (flags & DISPATCH_BLOCK_HAS_VOUCHER) {
		v = dbpd->dbpd_voucher;
	}
	ov = _dispatch_set_priority_and_voucher(p, v, 0);
	dbpd->dbpd_thread = _dispatch_tid_self();
	_dispatch_client_callout(dbpd->dbpd_block,
			_dispatch_Block_invoke(dbpd->dbpd_block));
	_dispatch_reset_priority_and_voucher(op, ov);
out:
	if ((atomic_flags & DBF_PERFORM) == 0) {
		if (os_atomic_inc2o(dbpd, dbpd_performed, relaxed) == 1) {
			dispatch_group_leave(_dbpd_group(dbpd));
		}
	}
}

void
_dispatch_block_sync_invoke(void *block)
{
	dispatch_block_t b = block;
	dispatch_block_private_data_t dbpd = _dispatch_block_get_data(b);
	dispatch_block_flags_t flags = dbpd->dbpd_flags;
	unsigned int atomic_flags = dbpd->dbpd_atomic_flags;
	if (unlikely(atomic_flags & DBF_WAITED)) {
		DISPATCH_CLIENT_CRASH(atomic_flags, "A block object may not be both "
				"run more than once and waited for");
	}
	if (atomic_flags & DBF_CANCELED) goto out;

	voucher_t ov = DISPATCH_NO_VOUCHER;
	if (flags & DISPATCH_BLOCK_HAS_VOUCHER) {
		ov = _dispatch_adopt_priority_and_set_voucher(0, dbpd->dbpd_voucher, 0);
	}
	dbpd->dbpd_block();
	_dispatch_reset_voucher(ov, 0);
out:
	if ((atomic_flags & DBF_PERFORM) == 0) {
		if (os_atomic_inc2o(dbpd, dbpd_performed, relaxed) == 1) {
			dispatch_group_leave(_dbpd_group(dbpd));
		}
	}

	os_mpsc_queue_t oq;
	oq = os_atomic_xchg2o(dbpd, dbpd_queue, NULL, relaxed);
	if (oq) {
		// balances dispatch_{,barrier_,}sync
		_os_object_release_internal_n(oq->_as_os_obj, 2);
	}
}

#if DISPATCH_USE_KEVENT_WORKQUEUE
static void
_dispatch_block_async_invoke_reset_max_qos(dispatch_queue_t dq,
		dispatch_qos_t qos)
{
	uint64_t old_state, new_state, qos_bits = _dq_state_from_qos(qos);

	// Only dispatch queues can reach this point (as opposed to sources or more
	// complex objects) which allows us to handle the DIRTY bit protocol by only
	// looking at the tail
	dispatch_assert(dx_metatype(dq) == _DISPATCH_QUEUE_TYPE);

again:
	os_atomic_rmw_loop2o(dq, dq_state, old_state, new_state, relaxed, {
		dispatch_assert(_dq_state_is_base_wlh(old_state));
		if ((old_state & DISPATCH_QUEUE_MAX_QOS_MASK) <= qos_bits) {
			// Nothing to do if the QoS isn't going down
			os_atomic_rmw_loop_give_up(return);
		}
		if (_dq_state_is_dirty(old_state)) {
			os_atomic_rmw_loop_give_up({
				// just renew the drain lock with an acquire barrier, to see
				// what the enqueuer that set DIRTY has done.
				// the xor generates better assembly as DISPATCH_QUEUE_DIRTY
				// is already in a register
				os_atomic_xor2o(dq, dq_state, DISPATCH_QUEUE_DIRTY, acquire);
				if (!dq->dq_items_tail) {
					goto again;
				}
				return;
			});
		}

		new_state  = old_state;
		new_state &= ~DISPATCH_QUEUE_MAX_QOS_MASK;
		new_state |= qos_bits;
	});

	_dispatch_deferred_items_get()->ddi_wlh_needs_update = true;
	_dispatch_event_loop_drain(KEVENT_FLAG_IMMEDIATE);
}
#endif // DISPATCH_USE_KEVENT_WORKQUEUE

#define DISPATCH_BLOCK_ASYNC_INVOKE_RELEASE           0x1
#define DISPATCH_BLOCK_ASYNC_INVOKE_NO_OVERRIDE_RESET 0x2

DISPATCH_NOINLINE
static void
_dispatch_block_async_invoke2(dispatch_block_t b, unsigned long invoke_flags)
{
	dispatch_block_private_data_t dbpd = _dispatch_block_get_data(b);
	unsigned int atomic_flags = dbpd->dbpd_atomic_flags;
	if (slowpath(atomic_flags & DBF_WAITED)) {
		DISPATCH_CLIENT_CRASH(atomic_flags, "A block object may not be both "
				"run more than once and waited for");
	}

#if DISPATCH_USE_KEVENT_WORKQUEUE
	if (unlikely((dbpd->dbpd_flags &
			DISPATCH_BLOCK_IF_LAST_RESET_QUEUE_QOS_OVERRIDE) &&
			!(invoke_flags & DISPATCH_BLOCK_ASYNC_INVOKE_NO_OVERRIDE_RESET))) {
		dispatch_queue_t dq = _dispatch_get_current_queue();
		dispatch_qos_t qos = _dispatch_qos_from_pp(_dispatch_get_priority());
		if ((dispatch_wlh_t)dq == _dispatch_get_wlh() && !dq->dq_items_tail) {
			_dispatch_block_async_invoke_reset_max_qos(dq, qos);
		}
	}
#endif // DISPATCH_USE_KEVENT_WORKQUEUE

	if (!slowpath(atomic_flags & DBF_CANCELED)) {
		dbpd->dbpd_block();
	}
	if ((atomic_flags & DBF_PERFORM) == 0) {
		if (os_atomic_inc2o(dbpd, dbpd_performed, relaxed) == 1) {
			dispatch_group_leave(_dbpd_group(dbpd));
		}
	}

	os_mpsc_queue_t oq = os_atomic_xchg2o(dbpd, dbpd_queue, NULL, relaxed);
	if (oq) {
		// balances dispatch_{,barrier_,group_}async
		_os_object_release_internal_n_inline(oq->_as_os_obj, 2);
	}

	if (invoke_flags & DISPATCH_BLOCK_ASYNC_INVOKE_RELEASE) {
		Block_release(b);
	}
}

static void
_dispatch_block_async_invoke(void *block)
{
	_dispatch_block_async_invoke2(block, 0);
}

static void
_dispatch_block_async_invoke_and_release(void *block)
{
	_dispatch_block_async_invoke2(block, DISPATCH_BLOCK_ASYNC_INVOKE_RELEASE);
}

static void
_dispatch_block_async_invoke_and_release_mach_barrier(void *block)
{
	_dispatch_block_async_invoke2(block, DISPATCH_BLOCK_ASYNC_INVOKE_RELEASE |
			DISPATCH_BLOCK_ASYNC_INVOKE_NO_OVERRIDE_RESET);
}

DISPATCH_ALWAYS_INLINE
static inline bool
_dispatch_block_supports_wait_and_cancel(dispatch_block_private_data_t dbpd)
{
	return dbpd && !(dbpd->dbpd_flags &
			DISPATCH_BLOCK_IF_LAST_RESET_QUEUE_QOS_OVERRIDE);
}

void
dispatch_block_cancel(dispatch_block_t db)
{
	dispatch_block_private_data_t dbpd = _dispatch_block_get_data(db);
	if (unlikely(!_dispatch_block_supports_wait_and_cancel(dbpd))) {
		DISPATCH_CLIENT_CRASH(db, "Invalid block object passed to "
				"dispatch_block_cancel()");
	}
	(void)os_atomic_or2o(dbpd, dbpd_atomic_flags, DBF_CANCELED, relaxed);
}

long
dispatch_block_testcancel(dispatch_block_t db)
{
	dispatch_block_private_data_t dbpd = _dispatch_block_get_data(db);
	if (unlikely(!_dispatch_block_supports_wait_and_cancel(dbpd))) {
		DISPATCH_CLIENT_CRASH(db, "Invalid block object passed to "
				"dispatch_block_testcancel()");
	}
	return (bool)(dbpd->dbpd_atomic_flags & DBF_CANCELED);
}

long
dispatch_block_wait(dispatch_block_t db, dispatch_time_t timeout)
{
	dispatch_block_private_data_t dbpd = _dispatch_block_get_data(db);
	if (unlikely(!_dispatch_block_supports_wait_and_cancel(dbpd))) {
		DISPATCH_CLIENT_CRASH(db, "Invalid block object passed to "
				"dispatch_block_wait()");
	}

	unsigned int flags = os_atomic_or_orig2o(dbpd, dbpd_atomic_flags,
			DBF_WAITING, relaxed);
	if (slowpath(flags & (DBF_WAITED | DBF_WAITING))) {
		DISPATCH_CLIENT_CRASH(flags, "A block object may not be waited for "
				"more than once");
	}

	// <rdar://problem/17703192> If we know the queue where this block is
	// enqueued, or the thread that's executing it, then we should boost
	// it here.

	pthread_priority_t pp = _dispatch_get_priority();

	os_mpsc_queue_t boost_oq;
	boost_oq = os_atomic_xchg2o(dbpd, dbpd_queue, NULL, relaxed);
	if (boost_oq) {
		// release balances dispatch_{,barrier_,group_}async.
		// Can't put the queue back in the timeout case: the block might
		// finish after we fell out of group_wait and see our NULL, so
		// neither of us would ever release. Side effect: After a _wait
		// that times out, subsequent waits will not boost the qos of the
		// still-running block.
		dx_wakeup(boost_oq, _dispatch_qos_from_pp(pp),
				DISPATCH_WAKEUP_BLOCK_WAIT | DISPATCH_WAKEUP_CONSUME_2);
	}

	mach_port_t boost_th = dbpd->dbpd_thread;
	if (boost_th) {
		_dispatch_thread_override_start(boost_th, pp, dbpd);
	}

	int performed = os_atomic_load2o(dbpd, dbpd_performed, relaxed);
	if (slowpath(performed > 1 || (boost_th && boost_oq))) {
		DISPATCH_CLIENT_CRASH(performed, "A block object may not be both "
				"run more than once and waited for");
	}

	long ret = dispatch_group_wait(_dbpd_group(dbpd), timeout);

	if (boost_th) {
		_dispatch_thread_override_end(boost_th, dbpd);
	}

	if (ret) {
		// timed out: reverse our changes
		(void)os_atomic_and2o(dbpd, dbpd_atomic_flags,
				~DBF_WAITING, relaxed);
	} else {
		(void)os_atomic_or2o(dbpd, dbpd_atomic_flags,
				DBF_WAITED, relaxed);
		// don't need to re-test here: the second call would see
		// the first call's WAITING
	}

	return ret;
}

void
dispatch_block_notify(dispatch_block_t db, dispatch_queue_t queue,
		dispatch_block_t notification_block)
{
	dispatch_block_private_data_t dbpd = _dispatch_block_get_data(db);
	if (!dbpd) {
		DISPATCH_CLIENT_CRASH(db, "Invalid block object passed to "
				"dispatch_block_notify()");
	}
	int performed = os_atomic_load2o(dbpd, dbpd_performed, relaxed);
	if (slowpath(performed > 1)) {
		DISPATCH_CLIENT_CRASH(performed, "A block object may not be both "
				"run more than once and observed");
	}

	return dispatch_group_notify(_dbpd_group(dbpd), queue, notification_block);
}

DISPATCH_NOINLINE
void
_dispatch_continuation_init_slow(dispatch_continuation_t dc,
		dispatch_queue_class_t dqu, dispatch_block_flags_t flags)
{
	dispatch_block_private_data_t dbpd = _dispatch_block_get_data(dc->dc_ctxt);
	dispatch_block_flags_t block_flags = dbpd->dbpd_flags;
	uintptr_t dc_flags = dc->dc_flags;
	os_mpsc_queue_t oq = dqu._oq;

	// balanced in d_block_async_invoke_and_release or d_block_wait
	if (os_atomic_cmpxchg2o(dbpd, dbpd_queue, NULL, oq, relaxed)) {
		_os_object_retain_internal_n_inline(oq->_as_os_obj, 2);
	}

	if (dc_flags & DISPATCH_OBJ_MACH_BARRIER) {
		dispatch_assert(dc_flags & DISPATCH_OBJ_CONSUME_BIT);
		dc->dc_func = _dispatch_block_async_invoke_and_release_mach_barrier;
	} else if (dc_flags & DISPATCH_OBJ_CONSUME_BIT) {
		dc->dc_func = _dispatch_block_async_invoke_and_release;
	} else {
		dc->dc_func = _dispatch_block_async_invoke;
	}

	flags |= block_flags;
	if (block_flags & DISPATCH_BLOCK_HAS_PRIORITY) {
		_dispatch_continuation_priority_set(dc, dbpd->dbpd_priority, flags);
	} else {
		_dispatch_continuation_priority_set(dc, dc->dc_priority, flags);
	}
	if (block_flags & DISPATCH_BLOCK_BARRIER) {
		dc_flags |= DISPATCH_OBJ_BARRIER_BIT;
	}
	if (block_flags & DISPATCH_BLOCK_HAS_VOUCHER) {
		voucher_t v = dbpd->dbpd_voucher;
		dc->dc_voucher = v ? _voucher_retain(v) : NULL;
		dc_flags |= DISPATCH_OBJ_ENFORCE_VOUCHER;
		_dispatch_voucher_debug("continuation[%p] set", dc->dc_voucher, dc);
		_dispatch_voucher_ktrace_dc_push(dc);
	} else {
		_dispatch_continuation_voucher_set(dc, oq, flags);
	}
	dc_flags |= DISPATCH_OBJ_BLOCK_PRIVATE_DATA_BIT;
	dc->dc_flags = dc_flags;
}

#endif // __BLOCKS__
#pragma mark -
#pragma mark dispatch_barrier_async

DISPATCH_NOINLINE
static void
_dispatch_async_f_slow(dispatch_queue_t dq, void *ctxt,
		dispatch_function_t func, pthread_priority_t pp,
		dispatch_block_flags_t flags, uintptr_t dc_flags)
{
	dispatch_continuation_t dc = _dispatch_continuation_alloc_from_heap();
	_dispatch_continuation_init_f(dc, dq, ctxt, func, pp, flags, dc_flags);
	_dispatch_continuation_async(dq, dc);
}

DISPATCH_ALWAYS_INLINE
static inline void
_dispatch_barrier_async_f2(dispatch_queue_t dq, void *ctxt,
		dispatch_function_t func, pthread_priority_t pp,
		dispatch_block_flags_t flags)
{
	dispatch_continuation_t dc = _dispatch_continuation_alloc_cacheonly();
	uintptr_t dc_flags = DISPATCH_OBJ_CONSUME_BIT | DISPATCH_OBJ_BARRIER_BIT;

	if (!fastpath(dc)) {
		return _dispatch_async_f_slow(dq, ctxt, func, pp, flags, dc_flags);
	}

	_dispatch_continuation_init_f(dc, dq, ctxt, func, pp, flags, dc_flags);
	_dispatch_continuation_push(dq, dc);
}

DISPATCH_NOINLINE
void
dispatch_barrier_async_f(dispatch_queue_t dq, void *ctxt,
		dispatch_function_t func)
{
	_dispatch_barrier_async_f2(dq, ctxt, func, 0, 0);
}

DISPATCH_NOINLINE
void
_dispatch_barrier_async_detached_f(dispatch_queue_t dq, void *ctxt,
		dispatch_function_t func)
{
	dispatch_continuation_t dc = _dispatch_continuation_alloc();
	dc->dc_flags = DISPATCH_OBJ_CONSUME_BIT | DISPATCH_OBJ_BARRIER_BIT;
	dc->dc_func = func;
	dc->dc_ctxt = ctxt;
	dc->dc_voucher = DISPATCH_NO_VOUCHER;
	dc->dc_priority = DISPATCH_NO_PRIORITY;
	dx_push(dq, dc, 0);
}

#ifdef __BLOCKS__
void
dispatch_barrier_async(dispatch_queue_t dq, dispatch_block_t work)
{
	dispatch_continuation_t dc = _dispatch_continuation_alloc();
	uintptr_t dc_flags = DISPATCH_OBJ_CONSUME_BIT | DISPATCH_OBJ_BARRIER_BIT;

	_dispatch_continuation_init(dc, dq, work, 0, 0, dc_flags);
	_dispatch_continuation_push(dq, dc);
}
#endif

#pragma mark -
#pragma mark dispatch_async

void
_dispatch_async_redirect_invoke(dispatch_continuation_t dc,
		dispatch_invoke_context_t dic, dispatch_invoke_flags_t flags)
{
	dispatch_thread_frame_s dtf;
	struct dispatch_continuation_s *other_dc = dc->dc_other;
	dispatch_invoke_flags_t ctxt_flags = (dispatch_invoke_flags_t)dc->dc_ctxt;
	// if we went through _dispatch_root_queue_push_override,
	// the "right" root queue was stuffed into dc_func
	dispatch_queue_t assumed_rq = (dispatch_queue_t)dc->dc_func;
	dispatch_queue_t dq = dc->dc_data, rq, old_dq;
	dispatch_priority_t old_dbp;

	if (ctxt_flags) {
		flags &= ~_DISPATCH_INVOKE_AUTORELEASE_MASK;
		flags |= ctxt_flags;
	}
	old_dq = _dispatch_get_current_queue();
	if (assumed_rq) {
		old_dbp = _dispatch_root_queue_identity_assume(assumed_rq);
		_dispatch_set_basepri(dq->dq_priority);
	} else {
		old_dbp = _dispatch_set_basepri(dq->dq_priority);
	}

	_dispatch_thread_frame_push(&dtf, dq);
	_dispatch_continuation_pop_forwarded(dc, DISPATCH_NO_VOUCHER,
			DISPATCH_OBJ_CONSUME_BIT, {
		_dispatch_continuation_pop(other_dc, dic, flags, dq);
	});
	_dispatch_thread_frame_pop(&dtf);
	if (assumed_rq) _dispatch_queue_set_current(old_dq);
	_dispatch_reset_basepri(old_dbp);

	rq = dq->do_targetq;
	while (slowpath(rq->do_targetq) && rq != old_dq) {
		_dispatch_queue_non_barrier_complete(rq);
		rq = rq->do_targetq;
	}

	_dispatch_queue_non_barrier_complete(dq);
	_dispatch_release_tailcall(dq); // pairs with _dispatch_async_redirect_wrap
}

DISPATCH_ALWAYS_INLINE
static inline dispatch_continuation_t
_dispatch_async_redirect_wrap(dispatch_queue_t dq, dispatch_object_t dou)
{
	dispatch_continuation_t dc = _dispatch_continuation_alloc();

	dou._do->do_next = NULL;
	dc->do_vtable = DC_VTABLE(ASYNC_REDIRECT);
	dc->dc_func = NULL;
	dc->dc_ctxt = (void *)(uintptr_t)_dispatch_queue_autorelease_frequency(dq);
	dc->dc_data = dq;
	dc->dc_other = dou._do;
	dc->dc_voucher = DISPATCH_NO_VOUCHER;
	dc->dc_priority = DISPATCH_NO_PRIORITY;
	_dispatch_retain(dq); // released in _dispatch_async_redirect_invoke
	return dc;
}

DISPATCH_NOINLINE
static void
_dispatch_async_f_redirect(dispatch_queue_t dq,
		dispatch_object_t dou, dispatch_qos_t qos)
{
	if (!slowpath(_dispatch_object_is_redirection(dou))) {
		dou._dc = _dispatch_async_redirect_wrap(dq, dou);
	}
	dq = dq->do_targetq;

	// Find the queue to redirect to
	while (slowpath(DISPATCH_QUEUE_USES_REDIRECTION(dq->dq_width))) {
		if (!fastpath(_dispatch_queue_try_acquire_async(dq))) {
			break;
		}
		if (!dou._dc->dc_ctxt) {
			// find first queue in descending target queue order that has
			// an autorelease frequency set, and use that as the frequency for
			// this continuation.
			dou._dc->dc_ctxt = (void *)
					(uintptr_t)_dispatch_queue_autorelease_frequency(dq);
		}
		dq = dq->do_targetq;
	}

	dx_push(dq, dou, qos);
}

DISPATCH_ALWAYS_INLINE
static inline void
_dispatch_continuation_redirect(dispatch_queue_t dq,
		struct dispatch_object_s *dc)
{
	_dispatch_trace_continuation_pop(dq, dc);
	// This is a re-redirect, overrides have already been applied
	// by _dispatch_async_f2.
	// However we want to end up on the root queue matching `dc` qos, so pick up
	// the current override of `dq` which includes dc's overrde (and maybe more)
	uint64_t dq_state = os_atomic_load2o(dq, dq_state, relaxed);
	_dispatch_async_f_redirect(dq, dc, _dq_state_max_qos(dq_state));
	_dispatch_introspection_queue_item_complete(dc);
}

DISPATCH_NOINLINE
static void
_dispatch_async_f2(dispatch_queue_t dq, dispatch_continuation_t dc)
{
	// <rdar://problem/24738102&24743140> reserving non barrier width
	// doesn't fail if only the ENQUEUED bit is set (unlike its barrier width
	// equivalent), so we have to check that this thread hasn't enqueued
	// anything ahead of this call or we can break ordering
	if (slowpath(dq->dq_items_tail)) {
		return _dispatch_continuation_push(dq, dc);
	}

	if (slowpath(!_dispatch_queue_try_acquire_async(dq))) {
		return _dispatch_continuation_push(dq, dc);
	}

	return _dispatch_async_f_redirect(dq, dc,
			_dispatch_continuation_override_qos(dq, dc));
}

DISPATCH_ALWAYS_INLINE
static inline void
_dispatch_async_f(dispatch_queue_t dq, void *ctxt, dispatch_function_t func,
		pthread_priority_t pp, dispatch_block_flags_t flags)
{
	dispatch_continuation_t dc = _dispatch_continuation_alloc_cacheonly();
	uintptr_t dc_flags = DISPATCH_OBJ_CONSUME_BIT;

	if (!fastpath(dc)) {
		return _dispatch_async_f_slow(dq, ctxt, func, pp, flags, dc_flags);
	}

	_dispatch_continuation_init_f(dc, dq, ctxt, func, pp, flags, dc_flags);
	_dispatch_continuation_async2(dq, dc, false);
}

DISPATCH_NOINLINE
void
dispatch_async_f(dispatch_queue_t dq, void *ctxt, dispatch_function_t func)
{
	_dispatch_async_f(dq, ctxt, func, 0, 0);
}

DISPATCH_NOINLINE
void
dispatch_async_enforce_qos_class_f(dispatch_queue_t dq, void *ctxt,
		dispatch_function_t func)
{
	_dispatch_async_f(dq, ctxt, func, 0, DISPATCH_BLOCK_ENFORCE_QOS_CLASS);
}

#ifdef __BLOCKS__
void
dispatch_async(dispatch_queue_t dq, dispatch_block_t work)
{
	dispatch_continuation_t dc = _dispatch_continuation_alloc();
	uintptr_t dc_flags = DISPATCH_OBJ_CONSUME_BIT;

	_dispatch_continuation_init(dc, dq, work, 0, 0, dc_flags);
	_dispatch_continuation_async(dq, dc);
}
#endif

#pragma mark -
#pragma mark dispatch_group_async

DISPATCH_ALWAYS_INLINE
static inline void
_dispatch_continuation_group_async(dispatch_group_t dg, dispatch_queue_t dq,
		dispatch_continuation_t dc)
{
	dispatch_group_enter(dg);
	dc->dc_data = dg;
	_dispatch_continuation_async(dq, dc);
}

DISPATCH_NOINLINE
void
dispatch_group_async_f(dispatch_group_t dg, dispatch_queue_t dq, void *ctxt,
		dispatch_function_t func)
{
	dispatch_continuation_t dc = _dispatch_continuation_alloc();
	uintptr_t dc_flags = DISPATCH_OBJ_CONSUME_BIT | DISPATCH_OBJ_GROUP_BIT;

	_dispatch_continuation_init_f(dc, dq, ctxt, func, 0, 0, dc_flags);
	_dispatch_continuation_group_async(dg, dq, dc);
}

#ifdef __BLOCKS__
void
dispatch_group_async(dispatch_group_t dg, dispatch_queue_t dq,
		dispatch_block_t db)
{
	dispatch_continuation_t dc = _dispatch_continuation_alloc();
	uintptr_t dc_flags = DISPATCH_OBJ_CONSUME_BIT | DISPATCH_OBJ_GROUP_BIT;

	_dispatch_continuation_init(dc, dq, db, 0, 0, dc_flags);
	_dispatch_continuation_group_async(dg, dq, dc);
}
#endif

#pragma mark -
#pragma mark _dispatch_sync_invoke / _dispatch_sync_complete

DISPATCH_NOINLINE
static void
_dispatch_queue_non_barrier_complete(dispatch_queue_t dq)
{
	uint64_t old_state, new_state, owner_self = _dispatch_lock_value_for_self();

	// see _dispatch_queue_resume()
	os_atomic_rmw_loop2o(dq, dq_state, old_state, new_state, relaxed, {
		new_state = old_state - DISPATCH_QUEUE_WIDTH_INTERVAL;
		if (unlikely(_dq_state_drain_locked(old_state))) {
			// make drain_try_unlock() fail and reconsider whether there's
			// enough width now for a new item
			new_state |= DISPATCH_QUEUE_DIRTY;
		} else if (likely(_dq_state_is_runnable(new_state))) {
			uint64_t full_width = new_state;
			if (_dq_state_has_pending_barrier(old_state)) {
				full_width -= DISPATCH_QUEUE_PENDING_BARRIER;
				full_width += DISPATCH_QUEUE_WIDTH_INTERVAL;
				full_width += DISPATCH_QUEUE_IN_BARRIER;
			} else {
				full_width += dq->dq_width * DISPATCH_QUEUE_WIDTH_INTERVAL;
				full_width += DISPATCH_QUEUE_IN_BARRIER;
			}
			if ((full_width & DISPATCH_QUEUE_WIDTH_MASK) ==
					DISPATCH_QUEUE_WIDTH_FULL_BIT) {
				new_state = full_width;
				new_state &= ~DISPATCH_QUEUE_DIRTY;
				new_state |= owner_self;
			} else if (_dq_state_is_dirty(old_state)) {
				new_state |= DISPATCH_QUEUE_ENQUEUED;
			}
		}
	});

	if ((old_state ^ new_state) & DISPATCH_QUEUE_IN_BARRIER) {
		if (_dq_state_is_dirty(old_state)) {
			// <rdar://problem/14637483>
			// dependency ordering for dq state changes that were flushed
			// and not acted upon
			os_atomic_thread_fence(dependency);
			dq = os_atomic_force_dependency_on(dq, old_state);
		}
		return _dispatch_queue_barrier_complete(dq, 0, 0);
	}

	if ((old_state ^ new_state) & DISPATCH_QUEUE_ENQUEUED) {
		_dispatch_retain_2(dq);
		dispatch_assert(!_dq_state_is_base_wlh(new_state));
		return dx_push(dq->do_targetq, dq, _dq_state_max_qos(new_state));
	}
}


DISPATCH_ALWAYS_INLINE
static inline void
_dispatch_sync_function_invoke_inline(dispatch_queue_t dq, void *ctxt,
		dispatch_function_t func)
{
	dispatch_thread_frame_s dtf;
	_dispatch_thread_frame_push(&dtf, dq);
	_dispatch_client_callout(ctxt, func);
	_dispatch_perfmon_workitem_inc();
	_dispatch_thread_frame_pop(&dtf);
}

DISPATCH_NOINLINE
static void
_dispatch_sync_function_invoke(dispatch_queue_t dq, void *ctxt,
		dispatch_function_t func)
{
	_dispatch_sync_function_invoke_inline(dq, ctxt, func);
}

DISPATCH_NOINLINE
static void
_dispatch_sync_complete_recurse(dispatch_queue_t dq, dispatch_queue_t stop_dq,
		uintptr_t dc_flags)
{
	bool barrier = (dc_flags & DISPATCH_OBJ_BARRIER_BIT);
	do {
		if (dq == stop_dq) return;
		if (barrier) {
			_dispatch_queue_barrier_complete(dq, 0, 0);
		} else {
			_dispatch_queue_non_barrier_complete(dq);
		}
		dq = dq->do_targetq;
		barrier = (dq->dq_width == 1);
	} while (unlikely(dq->do_targetq));
}

DISPATCH_NOINLINE
static void
_dispatch_sync_invoke_and_complete_recurse(dispatch_queue_t dq, void *ctxt,
		dispatch_function_t func, uintptr_t dc_flags)
{
	_dispatch_sync_function_invoke_inline(dq, ctxt, func);
	_dispatch_sync_complete_recurse(dq, NULL, dc_flags);
}

DISPATCH_NOINLINE
static void
_dispatch_sync_invoke_and_complete(dispatch_queue_t dq, void *ctxt,
		dispatch_function_t func)
{
	_dispatch_sync_function_invoke_inline(dq, ctxt, func);
	_dispatch_queue_non_barrier_complete(dq);
}

DISPATCH_NOINLINE
static void
_dispatch_barrier_sync_invoke_and_complete(dispatch_queue_t dq, void *ctxt,
		dispatch_function_t func)
{
	_dispatch_sync_function_invoke_inline(dq, ctxt, func);
	dx_wakeup(dq, 0, DISPATCH_WAKEUP_BARRIER_COMPLETE);
}

/*
 * This is an optimized version of _dispatch_barrier_sync_invoke_and_complete
 *
 * For queues we can cheat and inline the unlock code, which is invalid
 * for objects with a more complex state machine (sources or mach channels)
 */
DISPATCH_NOINLINE
static void
_dispatch_queue_barrier_sync_invoke_and_complete(dispatch_queue_t dq,
		void *ctxt, dispatch_function_t func)
{
	_dispatch_sync_function_invoke_inline(dq, ctxt, func);
	if (unlikely(dq->dq_items_tail || dq->dq_width > 1)) {
		return _dispatch_queue_barrier_complete(dq, 0, 0);
	}

	// Presence of any of these bits requires more work that only
	// _dispatch_queue_barrier_complete() handles properly
	//
	// Note: testing for RECEIVED_OVERRIDE or RECEIVED_SYNC_WAIT without
	// checking the role is sloppy, but is a super fast check, and neither of
	// these bits should be set if the lock was never contended/discovered.
	const uint64_t fail_unlock_mask = DISPATCH_QUEUE_SUSPEND_BITS_MASK |
			DISPATCH_QUEUE_ENQUEUED | DISPATCH_QUEUE_DIRTY |
			DISPATCH_QUEUE_RECEIVED_OVERRIDE | DISPATCH_QUEUE_SYNC_TRANSFER |
			DISPATCH_QUEUE_RECEIVED_SYNC_WAIT;
	uint64_t old_state, new_state;

	// similar to _dispatch_queue_drain_try_unlock
	os_atomic_rmw_loop2o(dq, dq_state, old_state, new_state, release, {
		new_state  = old_state - DISPATCH_QUEUE_SERIAL_DRAIN_OWNED;
		new_state &= ~DISPATCH_QUEUE_DRAIN_UNLOCK_MASK;
		new_state &= ~DISPATCH_QUEUE_MAX_QOS_MASK;
		if (unlikely(old_state & fail_unlock_mask)) {
			os_atomic_rmw_loop_give_up({
				return _dispatch_queue_barrier_complete(dq, 0, 0);
			});
		}
	});
	if (_dq_state_is_base_wlh(old_state)) {
		_dispatch_event_loop_assert_not_owned((dispatch_wlh_t)dq);
	}
}

#pragma mark -
#pragma mark _dispatch_sync_wait / _dispatch_sync_waiter_wake

#define DISPATCH_SYNC_WAITER_NO_UNLOCK (~0ull)

DISPATCH_NOINLINE
static void
_dispatch_sync_waiter_wake(dispatch_sync_context_t dsc,
		dispatch_wlh_t wlh, uint64_t old_state, uint64_t new_state)
{
	dispatch_wlh_t waiter_wlh = dsc->dc_data;

	if (_dq_state_in_sync_transfer(old_state) ||
			_dq_state_in_sync_transfer(new_state) ||
			(waiter_wlh != DISPATCH_WLH_ANON)) {
		_dispatch_event_loop_wake_owner(dsc, wlh, old_state, new_state);
	}
	if (waiter_wlh == DISPATCH_WLH_ANON) {
		if (dsc->dsc_override_qos > dsc->dsc_override_qos_floor) {
			_dispatch_wqthread_override_start(dsc->dsc_waiter,
					dsc->dsc_override_qos);
		}
		_dispatch_thread_event_signal(&dsc->dsc_event);
	}
	_dispatch_introspection_queue_item_complete(dsc->_as_dc);
}

DISPATCH_NOINLINE
static void
_dispatch_sync_waiter_redirect_or_wake(dispatch_queue_t dq, uint64_t owned,
		dispatch_object_t dou)
{
	dispatch_sync_context_t dsc = (dispatch_sync_context_t)dou._dc;
	uint64_t next_owner = 0, old_state, new_state;
	dispatch_wlh_t wlh = NULL;

	_dispatch_trace_continuation_pop(dq, dsc->_as_dc);

	if (owned == DISPATCH_SYNC_WAITER_NO_UNLOCK) {
		dispatch_assert(!(dsc->dc_flags & DISPATCH_OBJ_BARRIER_BIT));
		new_state = old_state = os_atomic_load2o(dq, dq_state, relaxed);
	} else {
		if (dsc->dc_flags & DISPATCH_OBJ_BARRIER_BIT) {
			next_owner = _dispatch_lock_value_from_tid(dsc->dsc_waiter);
		}
		os_atomic_rmw_loop2o(dq, dq_state, old_state, new_state, release, {
			new_state  = old_state - owned;
			new_state &= ~DISPATCH_QUEUE_DRAIN_UNLOCK_MASK;
			new_state &= ~DISPATCH_QUEUE_DIRTY;
			new_state |= next_owner;
			if (_dq_state_is_base_wlh(old_state)) {
				new_state |= DISPATCH_QUEUE_SYNC_TRANSFER;
			}
		});
		if (_dq_state_is_base_wlh(old_state)) {
			wlh = (dispatch_wlh_t)dq;
		} else if (_dq_state_received_override(old_state)) {
			// Ensure that the root queue sees that this thread was overridden.
			_dispatch_set_basepri_override_qos(_dq_state_max_qos(old_state));
		}
	}

	if (dsc->dc_data == DISPATCH_WLH_ANON) {
		if (dsc->dsc_override_qos < _dq_state_max_qos(old_state)) {
			dsc->dsc_override_qos = _dq_state_max_qos(old_state);
		}
	}

	if (unlikely(_dq_state_is_inner_queue(old_state))) {
		dispatch_queue_t tq = dq->do_targetq;
		if (likely(tq->dq_width == 1)) {
			dsc->dc_flags = DISPATCH_OBJ_BARRIER_BIT |
					DISPATCH_OBJ_SYNC_WAITER_BIT;
		} else {
			dsc->dc_flags = DISPATCH_OBJ_SYNC_WAITER_BIT;
		}
		_dispatch_introspection_queue_item_complete(dsc->_as_dc);
		return _dispatch_queue_push_sync_waiter(tq, dsc, 0);
	}

	return _dispatch_sync_waiter_wake(dsc, wlh, old_state, new_state);
}

DISPATCH_NOINLINE
static void
_dispatch_queue_class_barrier_complete(dispatch_queue_t dq, dispatch_qos_t qos,
		dispatch_wakeup_flags_t flags, dispatch_queue_wakeup_target_t target,
		uint64_t owned)
{
	uint64_t old_state, new_state, enqueue;
	dispatch_queue_t tq;

	if (target == DISPATCH_QUEUE_WAKEUP_MGR) {
		tq = &_dispatch_mgr_q;
		enqueue = DISPATCH_QUEUE_ENQUEUED_ON_MGR;
	} else if (target) {
		tq = (target == DISPATCH_QUEUE_WAKEUP_TARGET) ? dq->do_targetq : target;
		enqueue = DISPATCH_QUEUE_ENQUEUED;
	} else {
		tq = NULL;
		enqueue = 0;
	}

	os_atomic_rmw_loop2o(dq, dq_state, old_state, new_state, release, {
		new_state  = _dq_state_merge_qos(old_state - owned, qos);
		new_state &= ~DISPATCH_QUEUE_DRAIN_UNLOCK_MASK;
		if (unlikely(_dq_state_is_suspended(old_state))) {
			new_state |= DLOCK_OWNER_MASK;
		} else if (enqueue) {
			new_state |= enqueue;
		} else if (unlikely(_dq_state_is_dirty(old_state))) {
			os_atomic_rmw_loop_give_up({
				// just renew the drain lock with an acquire barrier, to see
				// what the enqueuer that set DIRTY has done.
				// the xor generates better assembly as DISPATCH_QUEUE_DIRTY
				// is already in a register
				os_atomic_xor2o(dq, dq_state, DISPATCH_QUEUE_DIRTY, acquire);
				flags |= DISPATCH_WAKEUP_BARRIER_COMPLETE;
				return dx_wakeup(dq, qos, flags);
			});
		} else if (_dq_state_is_base_wlh(old_state)) {
			new_state &= ~DISPATCH_QUEUE_MAX_QOS_MASK;
			new_state &= ~DISPATCH_QUEUE_ENQUEUED;
		} else {
			new_state &= ~DISPATCH_QUEUE_MAX_QOS_MASK;
		}
	});
	old_state -= owned;
	dispatch_assert(_dq_state_drain_locked_by_self(old_state));
	dispatch_assert(!_dq_state_is_enqueued_on_manager(old_state));


	if (_dq_state_received_override(old_state)) {
		// Ensure that the root queue sees that this thread was overridden.
		_dispatch_set_basepri_override_qos(_dq_state_max_qos(old_state));
	}

	if (tq) {
		if (likely((old_state ^ new_state) & enqueue)) {
			dispatch_assert(_dq_state_is_enqueued(new_state));
			dispatch_assert(flags & DISPATCH_WAKEUP_CONSUME_2);
			return _dispatch_queue_push_queue(tq, dq, new_state);
		}
#if HAVE_PTHREAD_WORKQUEUE_QOS
		// <rdar://problem/27694093> when doing sync to async handoff
		// if the queue received an override we have to forecefully redrive
		// the same override so that a new stealer is enqueued because
		// the previous one may be gone already
		if (_dq_state_should_override(new_state)) {
			return _dispatch_queue_class_wakeup_with_override(dq, new_state,
					flags);
		}
#endif
	}
	if (flags & DISPATCH_WAKEUP_CONSUME_2) {
		return _dispatch_release_2_tailcall(dq);
	}
}

DISPATCH_NOINLINE
static void
_dispatch_queue_barrier_complete(dispatch_queue_t dq, dispatch_qos_t qos,
		dispatch_wakeup_flags_t flags)
{
	dispatch_continuation_t dc_tmp, dc_start = NULL, dc_end = NULL;
	dispatch_queue_wakeup_target_t target = DISPATCH_QUEUE_WAKEUP_NONE;
	struct dispatch_object_s *dc = NULL;
	uint64_t owned = DISPATCH_QUEUE_IN_BARRIER +
			dq->dq_width * DISPATCH_QUEUE_WIDTH_INTERVAL;
	size_t count = 0;

	dispatch_assert(dx_metatype(dq) == _DISPATCH_QUEUE_TYPE);

	if (dq->dq_items_tail && !DISPATCH_QUEUE_IS_SUSPENDED(dq)) {
		dc = _dispatch_queue_head(dq);
		if (!_dispatch_object_is_sync_waiter(dc)) {
			// not a slow item, needs to wake up
		} else if (likely(dq->dq_width == 1) ||
				_dispatch_object_is_barrier(dc)) {
			// rdar://problem/8290662 "barrier/writer lock transfer"
			dc_start = dc_end = (dispatch_continuation_t)dc;
			owned = 0;
			count = 1;
			dc = _dispatch_queue_next(dq, dc);
		} else {
			// <rdar://problem/10164594> "reader lock transfer"
			// we must not wake waiters immediately because our right
			// for dequeuing is granted through holding the full "barrier" width
			// which a signaled work item could relinquish out from our feet
			dc_start = (dispatch_continuation_t)dc;
			do {
				// no check on width here because concurrent queues
				// do not respect width for blocked readers, the thread
				// is already spent anyway
				dc_end = (dispatch_continuation_t)dc;
				owned -= DISPATCH_QUEUE_WIDTH_INTERVAL;
				count++;
				dc = _dispatch_queue_next(dq, dc);
			} while (dc && _dispatch_object_is_sync_waiter_non_barrier(dc));
		}

		if (count) {
			do {
				dc_tmp = dc_start;
				dc_start = dc_start->do_next;
				_dispatch_sync_waiter_redirect_or_wake(dq, owned, dc_tmp);
				owned = DISPATCH_SYNC_WAITER_NO_UNLOCK;
			} while (dc_tmp != dc_end);
			if (flags & DISPATCH_WAKEUP_CONSUME_2) {
				return _dispatch_release_2_tailcall(dq);
			}
			return;
		}
		if (!(flags & DISPATCH_WAKEUP_CONSUME_2)) {
			_dispatch_retain_2(dq);
			flags |= DISPATCH_WAKEUP_CONSUME_2;
		}
		target = DISPATCH_QUEUE_WAKEUP_TARGET;
	}

	return _dispatch_queue_class_barrier_complete(dq, qos, flags, target,owned);
}

#if DISPATCH_COCOA_COMPAT
static void
_dispatch_sync_thread_bound_invoke(void *ctxt)
{
	dispatch_sync_context_t dsc = ctxt;
	dispatch_queue_t cq = _dispatch_queue_get_current();
	dispatch_queue_t orig_dq = dsc->dc_other;
	dispatch_thread_frame_s dtf;
	dispatch_assert(_dispatch_queue_is_thread_bound(cq));

	// the block runs on the thread the queue is bound to and not
	// on the calling thread, but we mean to see the calling thread
	// dispatch thread frames, so we fake the link, and then undo it
	_dispatch_thread_frame_push_and_rebase(&dtf, orig_dq, &dsc->dsc_dtf);
	_dispatch_client_callout(dsc->dsc_ctxt, dsc->dsc_func);
	_dispatch_thread_frame_pop(&dtf);

	// communicate back to _dispatch_sync_wait who the thread bound queue
	// was so that we skip it during _dispatch_sync_complete_recurse
	dsc->dc_other = cq;
	dsc->dsc_func = NULL;
	_dispatch_thread_event_signal(&dsc->dsc_event); // release
}
#endif

DISPATCH_ALWAYS_INLINE
static inline uint64_t
_dispatch_sync_wait_prepare(dispatch_queue_t dq)
{
	uint64_t old_state, new_state;

	os_atomic_rmw_loop2o(dq, dq_state, old_state, new_state, relaxed, {
		if (_dq_state_is_suspended(old_state) ||
				!_dq_state_is_base_wlh(old_state)) {
			os_atomic_rmw_loop_give_up(return old_state);
		}
		if (!_dq_state_drain_locked(old_state) ||
				_dq_state_in_sync_transfer(old_state)) {
			os_atomic_rmw_loop_give_up(return old_state);
		}
		new_state = old_state | DISPATCH_QUEUE_RECEIVED_SYNC_WAIT;
	});
	return new_state;
}

static void
_dispatch_sync_waiter_compute_wlh(dispatch_queue_t dq,
		dispatch_sync_context_t dsc)
{
	bool needs_locking = _dispatch_queue_is_legacy(dq);

	if (needs_locking) {
		dsc->dsc_release_storage = true;
		_dispatch_queue_sidelock_lock(dq);
	}

	dispatch_queue_t tq = dq->do_targetq;
	uint64_t dq_state = _dispatch_sync_wait_prepare(tq);

	if (_dq_state_is_suspended(dq_state) ||
			_dq_state_is_base_anon(dq_state)) {
		dsc->dsc_release_storage = false;
		dsc->dc_data = DISPATCH_WLH_ANON;
	} else if (_dq_state_is_base_wlh(dq_state)) {
		if (dsc->dsc_release_storage) {
			_dispatch_queue_retain_storage(tq);
		}
		dsc->dc_data = (dispatch_wlh_t)tq;
	} else {
		_dispatch_sync_waiter_compute_wlh(tq, dsc);
	}
	if (needs_locking) _dispatch_queue_sidelock_unlock(dq);
}

DISPATCH_NOINLINE
static void
_dispatch_sync_wait(dispatch_queue_t top_dq, void *ctxt,
		dispatch_function_t func, uintptr_t top_dc_flags,
		dispatch_queue_t dq, uintptr_t dc_flags)
{
	pthread_priority_t pp = _dispatch_get_priority();
	dispatch_tid tid = _dispatch_tid_self();
	dispatch_qos_t qos;
	uint64_t dq_state;

	dq_state = _dispatch_sync_wait_prepare(dq);
	if (unlikely(_dq_state_drain_locked_by(dq_state, tid))) {
		DISPATCH_CLIENT_CRASH((uintptr_t)dq_state,
				"dispatch_sync called on queue "
				"already owned by current thread");
	}

	struct dispatch_sync_context_s dsc = {
		.dc_flags    = dc_flags | DISPATCH_OBJ_SYNC_WAITER_BIT,
		.dc_other    = top_dq,
		.dc_priority = pp | _PTHREAD_PRIORITY_ENFORCE_FLAG,
		.dc_voucher  = DISPATCH_NO_VOUCHER,
		.dsc_func    = func,
		.dsc_ctxt    = ctxt,
		.dsc_waiter  = tid,
	};
	if (_dq_state_is_suspended(dq_state) ||
			_dq_state_is_base_anon(dq_state)) {
		dsc.dc_data = DISPATCH_WLH_ANON;
	} else if (_dq_state_is_base_wlh(dq_state)) {
		dsc.dc_data = (dispatch_wlh_t)dq;
	} else {
		_dispatch_sync_waiter_compute_wlh(dq, &dsc);
	}
#if DISPATCH_COCOA_COMPAT
	// It's preferred to execute synchronous blocks on the current thread
	// due to thread-local side effects, etc. However, blocks submitted
	// to the main thread MUST be run on the main thread
	//
	// Since we don't know whether that will happen, save the frame linkage
	// for the sake of _dispatch_sync_thread_bound_invoke
	_dispatch_thread_frame_save_state(&dsc.dsc_dtf);

	// Since the continuation doesn't have the CONSUME bit, the voucher will be
	// retained on adoption on the thread bound queue if it happens so we can
	// borrow this thread's reference
	dsc.dc_voucher = _voucher_get();
	dsc.dc_func = _dispatch_sync_thread_bound_invoke;
	dsc.dc_ctxt = &dsc;
#endif

	if (dsc.dc_data == DISPATCH_WLH_ANON) {
		dsc.dsc_override_qos_floor = dsc.dsc_override_qos =
				_dispatch_get_basepri_override_qos_floor();
		qos = _dispatch_qos_from_pp(pp);
		_dispatch_thread_event_init(&dsc.dsc_event);
	} else {
		qos = 0;
	}
	_dispatch_queue_push_sync_waiter(dq, &dsc, qos);
	if (dsc.dc_data == DISPATCH_WLH_ANON) {
		_dispatch_thread_event_wait(&dsc.dsc_event); // acquire
		_dispatch_thread_event_destroy(&dsc.dsc_event);
		// If _dispatch_sync_waiter_wake() gave this thread an override,
		// ensure that the root queue sees it.
		if (dsc.dsc_override_qos > dsc.dsc_override_qos_floor) {
			_dispatch_set_basepri_override_qos(dsc.dsc_override_qos);
		}
	} else {
		_dispatch_event_loop_wait_for_ownership(&dsc);
	}
	_dispatch_introspection_sync_begin(top_dq);
#if DISPATCH_COCOA_COMPAT
	if (unlikely(dsc.dsc_func == NULL)) {
		// Queue bound to a non-dispatch thread, the continuation already ran
		// so just unlock all the things, except for the thread bound queue
		dispatch_queue_t bound_dq = dsc.dc_other;
		return _dispatch_sync_complete_recurse(top_dq, bound_dq, top_dc_flags);
	}
#endif
	_dispatch_sync_invoke_and_complete_recurse(top_dq, ctxt, func,top_dc_flags);
}

DISPATCH_NOINLINE
static void
_dispatch_sync_f_slow(dispatch_queue_t dq, void *ctxt,
		dispatch_function_t func, uintptr_t dc_flags)
{
	if (unlikely(!dq->do_targetq)) {
		return _dispatch_sync_function_invoke(dq, ctxt, func);
	}
	_dispatch_sync_wait(dq, ctxt, func, dc_flags, dq, dc_flags);
}

#pragma mark -
#pragma mark dispatch_sync / dispatch_barrier_sync

DISPATCH_NOINLINE
static void
_dispatch_sync_recurse(dispatch_queue_t dq, void *ctxt,
		dispatch_function_t func, uintptr_t dc_flags)
{
	dispatch_tid tid = _dispatch_tid_self();
	dispatch_queue_t tq = dq->do_targetq;

	do {
		if (likely(tq->dq_width == 1)) {
			if (unlikely(!_dispatch_queue_try_acquire_barrier_sync(tq, tid))) {
				return _dispatch_sync_wait(dq, ctxt, func, dc_flags, tq,
						DISPATCH_OBJ_BARRIER_BIT);
			}
		} else {
			if (unlikely(!_dispatch_queue_try_reserve_sync_width(tq))) {
				return _dispatch_sync_wait(dq, ctxt, func, dc_flags, tq, 0);
			}
		}
		tq = tq->do_targetq;
	} while (unlikely(tq->do_targetq));

	return _dispatch_sync_invoke_and_complete_recurse(dq, ctxt, func, dc_flags);
}

DISPATCH_NOINLINE
void
dispatch_barrier_sync_f(dispatch_queue_t dq, void *ctxt,
		dispatch_function_t func)
{
	dispatch_tid tid = _dispatch_tid_self();

	// The more correct thing to do would be to merge the qos of the thread
	// that just acquired the barrier lock into the queue state.
	//
	// However this is too expensive for the fastpath, so skip doing it.
	// The chosen tradeoff is that if an enqueue on a lower priority thread
	// contends with this fastpath, this thread may receive a useless override.
	//
	// Global concurrent queues and queues bound to non-dispatch threads
	// always fall into the slow case, see DISPATCH_ROOT_QUEUE_STATE_INIT_VALUE
	if (unlikely(!_dispatch_queue_try_acquire_barrier_sync(dq, tid))) {
		return _dispatch_sync_f_slow(dq, ctxt, func, DISPATCH_OBJ_BARRIER_BIT);
	}

	_dispatch_introspection_sync_begin(dq);
	if (unlikely(dq->do_targetq->do_targetq)) {
		return _dispatch_sync_recurse(dq, ctxt, func, DISPATCH_OBJ_BARRIER_BIT);
	}
	_dispatch_queue_barrier_sync_invoke_and_complete(dq, ctxt, func);
}

DISPATCH_NOINLINE
void
dispatch_sync_f(dispatch_queue_t dq, void *ctxt, dispatch_function_t func)
{
	if (likely(dq->dq_width == 1)) {
		return dispatch_barrier_sync_f(dq, ctxt, func);
	}

	// Global concurrent queues and queues bound to non-dispatch threads
	// always fall into the slow case, see DISPATCH_ROOT_QUEUE_STATE_INIT_VALUE
	if (unlikely(!_dispatch_queue_try_reserve_sync_width(dq))) {
		return _dispatch_sync_f_slow(dq, ctxt, func, 0);
	}

	_dispatch_introspection_sync_begin(dq);
	if (unlikely(dq->do_targetq->do_targetq)) {
		return _dispatch_sync_recurse(dq, ctxt, func, 0);
	}
	_dispatch_sync_invoke_and_complete(dq, ctxt, func);
}

#ifdef __BLOCKS__
DISPATCH_NOINLINE
static void
_dispatch_sync_block_with_private_data(dispatch_queue_t dq,
		dispatch_block_t work, dispatch_block_flags_t flags)
{
	dispatch_block_private_data_t dbpd = _dispatch_block_get_data(work);
	pthread_priority_t op = 0, p = 0;

	flags |= dbpd->dbpd_flags;
	op = _dispatch_block_invoke_should_set_priority(flags, dbpd->dbpd_priority);
	if (op) {
		p = dbpd->dbpd_priority;
	}
	voucher_t ov, v = DISPATCH_NO_VOUCHER;
	if (flags & DISPATCH_BLOCK_HAS_VOUCHER) {
		v = dbpd->dbpd_voucher;
	}
	ov = _dispatch_set_priority_and_voucher(p, v, 0);

	// balanced in d_block_sync_invoke or d_block_wait
	if (os_atomic_cmpxchg2o(dbpd, dbpd_queue, NULL, dq->_as_oq, relaxed)) {
		_dispatch_retain_2(dq);
	}
	if (flags & DISPATCH_BLOCK_BARRIER) {
		dispatch_barrier_sync_f(dq, work, _dispatch_block_sync_invoke);
	} else {
		dispatch_sync_f(dq, work, _dispatch_block_sync_invoke);
	}
	_dispatch_reset_priority_and_voucher(op, ov);
}

void
dispatch_barrier_sync(dispatch_queue_t dq, dispatch_block_t work)
{
	if (unlikely(_dispatch_block_has_private_data(work))) {
		dispatch_block_flags_t flags = DISPATCH_BLOCK_BARRIER;
		return _dispatch_sync_block_with_private_data(dq, work, flags);
	}
	dispatch_barrier_sync_f(dq, work, _dispatch_Block_invoke(work));
}

void
dispatch_sync(dispatch_queue_t dq, dispatch_block_t work)
{
	if (unlikely(_dispatch_block_has_private_data(work))) {
		return _dispatch_sync_block_with_private_data(dq, work, 0);
	}
	dispatch_sync_f(dq, work, _dispatch_Block_invoke(work));
}
#endif // __BLOCKS__

#pragma mark -
#pragma mark dispatch_trysync

// Use for mutation of queue-/source-internal state only
// ignores target queue hierarchy!
DISPATCH_NOINLINE
void
_dispatch_barrier_trysync_or_async_f(dispatch_queue_t dq, void *ctxt,
		dispatch_function_t func)
{
	dispatch_tid tid = _dispatch_tid_self();
	if (unlikely(!_dispatch_queue_try_acquire_barrier_sync(dq, tid))) {
		return _dispatch_barrier_async_detached_f(dq, ctxt, func);
	}
	_dispatch_barrier_sync_invoke_and_complete(dq, ctxt, func);
}

DISPATCH_NOINLINE
static long
_dispatch_trysync_recurse(dispatch_queue_t dq, void *ctxt,
		dispatch_function_t f, uintptr_t dc_flags)
{
	dispatch_tid tid = _dispatch_tid_self();
	dispatch_queue_t q, tq = dq->do_targetq;

	for (;;) {
		if (likely(tq->do_targetq == NULL)) {
			_dispatch_sync_invoke_and_complete_recurse(dq, ctxt, f, dc_flags);
			return true;
		}
		if (unlikely(_dispatch_queue_cannot_trysync(tq))) {
			for (q = dq; q != tq; q = q->do_targetq) {
				_dispatch_queue_atomic_flags_set(q, DQF_CANNOT_TRYSYNC);
			}
			break;
		}
		if (likely(tq->dq_width == 1)) {
			if (unlikely(!_dispatch_queue_try_acquire_barrier_sync(tq, tid))) {
				break;
			}
		} else {
			if (unlikely(!_dispatch_queue_try_reserve_sync_width(tq))) {
				break;
			}
		}
		tq = tq->do_targetq;
	}

	_dispatch_sync_complete_recurse(dq, tq, dc_flags);
	return false;
}

DISPATCH_NOINLINE
long
_dispatch_barrier_trysync_f(dispatch_queue_t dq, void *ctxt,
		dispatch_function_t f)
{
	dispatch_tid tid = _dispatch_tid_self();
	if (unlikely(!dq->do_targetq)) {
		DISPATCH_CLIENT_CRASH(dq, "_dispatch_trsync called on a root queue");
	}
	if (unlikely(_dispatch_queue_cannot_trysync(dq))) {
		return false;
	}
	if (unlikely(!_dispatch_queue_try_acquire_barrier_sync(dq, tid))) {
		return false;
	}
	return _dispatch_trysync_recurse(dq, ctxt, f, DISPATCH_OBJ_BARRIER_BIT);
}

DISPATCH_NOINLINE
long
_dispatch_trysync_f(dispatch_queue_t dq, void *ctxt, dispatch_function_t f)
{
	if (likely(dq->dq_width == 1)) {
		return _dispatch_barrier_trysync_f(dq, ctxt, f);
	}
	if (unlikely(!dq->do_targetq)) {
		DISPATCH_CLIENT_CRASH(dq, "_dispatch_trsync called on a root queue");
	}
	if (unlikely(_dispatch_queue_cannot_trysync(dq))) {
		return false;
	}
	if (unlikely(!_dispatch_queue_try_reserve_sync_width(dq))) {
		return false;
	}
	return _dispatch_trysync_recurse(dq, ctxt, f, 0);
}

#pragma mark -
#pragma mark dispatch_queue_wakeup

DISPATCH_NOINLINE
void
_dispatch_queue_wakeup(dispatch_queue_t dq, dispatch_qos_t qos,
		dispatch_wakeup_flags_t flags)
{
	dispatch_queue_wakeup_target_t target = DISPATCH_QUEUE_WAKEUP_NONE;

	if (unlikely(flags & DISPATCH_WAKEUP_BARRIER_COMPLETE)) {
		return _dispatch_queue_barrier_complete(dq, qos, flags);
	}
	if (_dispatch_queue_class_probe(dq)) {
		target = DISPATCH_QUEUE_WAKEUP_TARGET;
	}
	return _dispatch_queue_class_wakeup(dq, qos, flags, target);
}

#if DISPATCH_COCOA_COMPAT
DISPATCH_ALWAYS_INLINE
static inline bool
_dispatch_runloop_handle_is_valid(dispatch_runloop_handle_t handle)
{
#if TARGET_OS_MAC
	return MACH_PORT_VALID(handle);
#elif defined(__linux__)
	return handle >= 0;
#else
#error "runloop support not implemented on this platform"
#endif
}

DISPATCH_ALWAYS_INLINE
static inline dispatch_runloop_handle_t
_dispatch_runloop_queue_get_handle(dispatch_queue_t dq)
{
#if TARGET_OS_MAC
	return ((dispatch_runloop_handle_t)(uintptr_t)dq->do_ctxt);
#elif defined(__linux__)
	// decode: 0 is a valid fd, so offset by 1 to distinguish from NULL
	return ((dispatch_runloop_handle_t)(uintptr_t)dq->do_ctxt) - 1;
#else
#error "runloop support not implemented on this platform"
#endif
}

DISPATCH_ALWAYS_INLINE
static inline void
_dispatch_runloop_queue_set_handle(dispatch_queue_t dq, dispatch_runloop_handle_t handle)
{
#if TARGET_OS_MAC
	dq->do_ctxt = (void *)(uintptr_t)handle;
#elif defined(__linux__)
	// encode: 0 is a valid fd, so offset by 1 to distinguish from NULL
	dq->do_ctxt = (void *)(uintptr_t)(handle + 1);
#else
#error "runloop support not implemented on this platform"
#endif
}

DISPATCH_ALWAYS_INLINE
static inline dispatch_qos_t
_dispatch_runloop_queue_reset_max_qos(dispatch_queue_class_t dqu)
{
	uint64_t old_state, clear_bits = DISPATCH_QUEUE_MAX_QOS_MASK |
			DISPATCH_QUEUE_RECEIVED_OVERRIDE;
	old_state = os_atomic_and_orig2o(dqu._dq, dq_state, ~clear_bits, relaxed);
	return _dq_state_max_qos(old_state);
}
#endif // DISPATCH_COCOA_COMPAT

void
_dispatch_runloop_queue_wakeup(dispatch_queue_t dq, dispatch_qos_t qos,
		dispatch_wakeup_flags_t flags)
{
#if DISPATCH_COCOA_COMPAT
	if (slowpath(_dispatch_queue_atomic_flags(dq) & DQF_RELEASED)) {
		// <rdar://problem/14026816>
		return _dispatch_queue_wakeup(dq, qos, flags);
	}

	if (flags & DISPATCH_WAKEUP_MAKE_DIRTY) {
		os_atomic_or2o(dq, dq_state, DISPATCH_QUEUE_DIRTY, release);
	}
	if (_dispatch_queue_class_probe(dq)) {
		return _dispatch_runloop_queue_poke(dq, qos, flags);
	}

	qos = _dispatch_runloop_queue_reset_max_qos(dq);
	if (qos) {
		mach_port_t owner = DISPATCH_QUEUE_DRAIN_OWNER(dq);
		if (_dispatch_queue_class_probe(dq)) {
			_dispatch_runloop_queue_poke(dq, qos, flags);
		}
		_dispatch_thread_override_end(owner, dq);
		return;
	}
	if (flags & DISPATCH_WAKEUP_CONSUME_2) {
		return _dispatch_release_2_tailcall(dq);
	}
#else
	return _dispatch_queue_wakeup(dq, qos, flags);
#endif
}

void
_dispatch_main_queue_wakeup(dispatch_queue_t dq, dispatch_qos_t qos,
		dispatch_wakeup_flags_t flags)
{
#if DISPATCH_COCOA_COMPAT
	if (_dispatch_queue_is_thread_bound(dq)) {
		return _dispatch_runloop_queue_wakeup(dq, qos, flags);
	}
#endif
	return _dispatch_queue_wakeup(dq, qos, flags);
}

#pragma mark -
#pragma mark dispatch root queues poke

#if DISPATCH_COCOA_COMPAT
static inline void
_dispatch_runloop_queue_class_poke(dispatch_queue_t dq)
{
	dispatch_runloop_handle_t handle = _dispatch_runloop_queue_get_handle(dq);
	if (!_dispatch_runloop_handle_is_valid(handle)) {
		return;
	}

#if HAVE_MACH
	mach_port_t mp = handle;
	kern_return_t kr = _dispatch_send_wakeup_runloop_thread(mp, 0);
	switch (kr) {
	case MACH_SEND_TIMEOUT:
	case MACH_SEND_TIMED_OUT:
	case MACH_SEND_INVALID_DEST:
		break;
	default:
		(void)dispatch_assume_zero(kr);
		break;
	}
#elif defined(__linux__)
	int result;
	do {
		result = eventfd_write(handle, 1);
	} while (result == -1 && errno == EINTR);
	(void)dispatch_assume_zero(result);
#else
#error "runloop support not implemented on this platform"
#endif
}

DISPATCH_NOINLINE
static void
_dispatch_runloop_queue_poke(dispatch_queue_t dq, dispatch_qos_t qos,
		dispatch_wakeup_flags_t flags)
{
	// it's not useful to handle WAKEUP_MAKE_DIRTY because mach_msg() will have
	// a release barrier and that when runloop queues stop being thread-bound
	// they have a non optional wake-up to start being a "normal" queue
	// either in _dispatch_runloop_queue_xref_dispose,
	// or in _dispatch_queue_cleanup2() for the main thread.
	uint64_t old_state, new_state;

	if (dq == &_dispatch_main_q) {
		dispatch_once_f(&_dispatch_main_q_handle_pred, dq,
				_dispatch_runloop_queue_handle_init);
	}

	os_atomic_rmw_loop2o(dq, dq_state, old_state, new_state, relaxed, {
		new_state = _dq_state_merge_qos(old_state, qos);
		if (old_state == new_state) {
			os_atomic_rmw_loop_give_up(goto no_change);
		}
	});

	dispatch_qos_t dq_qos = _dispatch_priority_qos(dq->dq_priority);
	if (qos > dq_qos) {
		mach_port_t owner = _dq_state_drain_owner(new_state);
		pthread_priority_t pp = _dispatch_qos_to_pp(qos);
		_dispatch_thread_override_start(owner, pp, dq);
		if (_dq_state_max_qos(old_state) > dq_qos) {
			_dispatch_thread_override_end(owner, dq);
		}
	}
no_change:
	_dispatch_runloop_queue_class_poke(dq);
	if (flags & DISPATCH_WAKEUP_CONSUME_2) {
		return _dispatch_release_2_tailcall(dq);
	}
}
#endif

DISPATCH_NOINLINE
static void
_dispatch_global_queue_poke_slow(dispatch_queue_t dq, int n, int floor)
{
	dispatch_root_queue_context_t qc = dq->do_ctxt;
	int remaining = n;
	int r = ENOSYS;

	_dispatch_root_queues_init();
	_dispatch_debug_root_queue(dq, __func__);
#if DISPATCH_USE_WORKQUEUES
#if DISPATCH_USE_PTHREAD_POOL
	if (qc->dgq_kworkqueue != (void*)(~0ul))
#endif
	{
		_dispatch_root_queue_debug("requesting new worker thread for global "
				"queue: %p", dq);
#if DISPATCH_USE_LEGACY_WORKQUEUE_FALLBACK
		if (qc->dgq_kworkqueue) {
			pthread_workitem_handle_t wh;
			unsigned int gen_cnt;
			do {
				r = pthread_workqueue_additem_np(qc->dgq_kworkqueue,
						_dispatch_worker_thread4, dq, &wh, &gen_cnt);
				(void)dispatch_assume_zero(r);
			} while (--remaining);
			return;
		}
#endif // DISPATCH_USE_LEGACY_WORKQUEUE_FALLBACK
#if HAVE_PTHREAD_WORKQUEUE_QOS
		r = _pthread_workqueue_addthreads(remaining,
				_dispatch_priority_to_pp(dq->dq_priority));
#elif DISPATCH_USE_PTHREAD_WORKQUEUE_SETDISPATCH_NP
		r = pthread_workqueue_addthreads_np(qc->dgq_wq_priority,
				qc->dgq_wq_options, remaining);
#endif
		(void)dispatch_assume_zero(r);
		return;
	}
#endif // DISPATCH_USE_WORKQUEUES
#if DISPATCH_USE_PTHREAD_POOL
	dispatch_pthread_root_queue_context_t pqc = qc->dgq_ctxt;
	if (fastpath(pqc->dpq_thread_mediator.do_vtable)) {
		while (dispatch_semaphore_signal(&pqc->dpq_thread_mediator)) {
			_dispatch_root_queue_debug("signaled sleeping worker for "
					"global queue: %p", dq);
			if (!--remaining) {
				return;
			}
		}
	}

	bool overcommit = dq->dq_priority & DISPATCH_PRIORITY_FLAG_OVERCOMMIT;
	if (overcommit) {
		os_atomic_add2o(qc, dgq_pending, remaining, relaxed);
	} else {
		if (!os_atomic_cmpxchg2o(qc, dgq_pending, 0, remaining, relaxed)) {
			_dispatch_root_queue_debug("worker thread request still pending for "
					"global queue: %p", dq);
			return;
		}
	}

	int32_t can_request, t_count;
	// seq_cst with atomic store to tail <rdar://problem/16932833>
	t_count = os_atomic_load2o(qc, dgq_thread_pool_size, ordered);
	do {
		can_request = t_count < floor ? 0 : t_count - floor;
		if (remaining > can_request) {
			_dispatch_root_queue_debug("pthread pool reducing request from %d to %d",
					remaining, can_request);
			os_atomic_sub2o(qc, dgq_pending, remaining - can_request, relaxed);
			remaining = can_request;
		}
		if (remaining == 0) {
			_dispatch_root_queue_debug("pthread pool is full for root queue: "
					"%p", dq);
			return;
		}
	} while (!os_atomic_cmpxchgvw2o(qc, dgq_thread_pool_size, t_count,
			t_count - remaining, &t_count, acquire));

#if defined(_WIN32)
#if DISPATCH_USE_MGR_THREAD && DISPATCH_ENABLE_PTHREAD_ROOT_QUEUES
	if (slowpath(dq == &_dispatch_mgr_root_queue)) {
		_dispatch_mgr_root_queue_init();
	}
#endif
	do {
		_dispatch_retain(dq); // released in _dispatch_worker_thread
#if DISPATCH_DEBUG
		unsigned dwStackSize = 0;
#else
		unsigned dwStackSize = 64 * 1024;
#endif
		uintptr_t hThread = 0;
		while (!(hThread = _beginthreadex(NULL, dwStackSize, _dispatch_worker_thread_thunk, dq, STACK_SIZE_PARAM_IS_A_RESERVATION, NULL))) {
			if (errno != EAGAIN) {
				(void)dispatch_assume(hThread);
			}
			_dispatch_temporary_resource_shortage();
		}
		if (_dispatch_mgr_sched.prio > _dispatch_mgr_sched.default_prio) {
			(void)dispatch_assume_zero(SetThreadPriority((HANDLE)hThread, _dispatch_mgr_sched.prio) == TRUE);
		}
		CloseHandle((HANDLE)hThread);
	} while (--remaining);
#else
	pthread_attr_t *attr = &pqc->dpq_thread_attr;
	pthread_t tid, *pthr = &tid;
#if DISPATCH_USE_MGR_THREAD && DISPATCH_ENABLE_PTHREAD_ROOT_QUEUES
	if (slowpath(dq == &_dispatch_mgr_root_queue)) {
		pthr = _dispatch_mgr_root_queue_init();
	}
#endif
	do {
		_dispatch_retain(dq); // released in _dispatch_worker_thread
		while ((r = pthread_create(pthr, attr, _dispatch_worker_thread, dq))) {
			if (r != EAGAIN) {
				(void)dispatch_assume_zero(r);
			}
			_dispatch_temporary_resource_shortage();
		}
	} while (--remaining);
#endif
#endif // DISPATCH_USE_PTHREAD_POOL
}

DISPATCH_NOINLINE
void
_dispatch_global_queue_poke(dispatch_queue_t dq, int n, int floor)
{
	if (!_dispatch_queue_class_probe(dq)) {
		return;
	}
#if DISPATCH_USE_WORKQUEUES
	dispatch_root_queue_context_t qc = dq->do_ctxt;
	if (
#if DISPATCH_USE_PTHREAD_POOL
			(qc->dgq_kworkqueue != (void*)(~0ul)) &&
#endif
			!os_atomic_cmpxchg2o(qc, dgq_pending, 0, n, relaxed)) {
		_dispatch_root_queue_debug("worker thread request still pending for "
				"global queue: %p", dq);
		return;
	}
#endif // DISPATCH_USE_WORKQUEUES
	return _dispatch_global_queue_poke_slow(dq, n, floor);
}

#pragma mark -
#pragma mark dispatch_queue_drain

void
_dispatch_continuation_pop(dispatch_object_t dou, dispatch_invoke_context_t dic,
		dispatch_invoke_flags_t flags, dispatch_queue_t dq)
{
	_dispatch_continuation_pop_inline(dou, dic, flags, dq);
}

void
_dispatch_continuation_invoke(dispatch_object_t dou, voucher_t ov,
		dispatch_invoke_flags_t flags)
{
	_dispatch_continuation_invoke_inline(dou, ov, flags);
}

DISPATCH_NOINLINE
static void
_dispatch_return_to_kernel(void)
{
#if DISPATCH_USE_KEVENT_WORKQUEUE
	if (unlikely(_dispatch_get_wlh() == DISPATCH_WLH_ANON)) {
		_dispatch_clear_return_to_kernel();
	} else {
		_dispatch_event_loop_drain(KEVENT_FLAG_IMMEDIATE);
	}
#endif
}

void
_dispatch_poll_for_events_4launchd(void)
{
#if DISPATCH_USE_KEVENT_WORKQUEUE
	if (_dispatch_get_wlh()) {
		dispatch_assert(_dispatch_deferred_items_get()->ddi_wlh_servicing);
		_dispatch_event_loop_drain(KEVENT_FLAG_IMMEDIATE);
	}
#endif
}

#if HAVE_PTHREAD_WORKQUEUE_NARROWING
static os_atomic(uint64_t) _dispatch_narrowing_deadlines[DISPATCH_QOS_MAX];
#if !DISPATCH_TIME_UNIT_USES_NANOSECONDS
static uint64_t _dispatch_narrow_check_interval_cache;
#endif

DISPATCH_ALWAYS_INLINE
static inline uint64_t
_dispatch_narrow_check_interval(void)
{
#if DISPATCH_TIME_UNIT_USES_NANOSECONDS
	return 50 * NSEC_PER_MSEC;
#else
	if (_dispatch_narrow_check_interval_cache == 0) {
		_dispatch_narrow_check_interval_cache =
				_dispatch_time_nano2mach(50 * NSEC_PER_MSEC);
	}
	return _dispatch_narrow_check_interval_cache;
#endif
}

DISPATCH_ALWAYS_INLINE
static inline void
_dispatch_queue_drain_init_narrowing_check_deadline(dispatch_invoke_context_t dic,
		dispatch_priority_t pri)
{
	if (_dispatch_priority_qos(pri) &&
			!(pri & DISPATCH_PRIORITY_FLAG_OVERCOMMIT)) {
		dic->dic_next_narrow_check = _dispatch_approximate_time() +
				_dispatch_narrow_check_interval();
	}
}

DISPATCH_NOINLINE
static bool
_dispatch_queue_drain_should_narrow_slow(uint64_t now,
		dispatch_invoke_context_t dic)
{
	if (dic->dic_next_narrow_check != DISPATCH_THREAD_IS_NARROWING) {
		pthread_priority_t pp = _dispatch_get_priority();
		dispatch_qos_t qos = _dispatch_qos_from_pp(pp);
		if (unlikely(!qos || qos > countof(_dispatch_narrowing_deadlines))) {
			DISPATCH_CLIENT_CRASH(pp, "Thread QoS corruption");
		}
		size_t idx = qos - 1; // no entry needed for DISPATCH_QOS_UNSPECIFIED
		os_atomic(uint64_t) *deadline = &_dispatch_narrowing_deadlines[idx];
		uint64_t oldval, newval = now + _dispatch_narrow_check_interval();

		dic->dic_next_narrow_check = newval;
		os_atomic_rmw_loop(deadline, oldval, newval, relaxed, {
			if (now < oldval) {
				os_atomic_rmw_loop_give_up(return false);
			}
		});

		if (!_pthread_workqueue_should_narrow(pp)) {
			return false;
		}
		dic->dic_next_narrow_check = DISPATCH_THREAD_IS_NARROWING;
	}
	return true;
}

DISPATCH_ALWAYS_INLINE
static inline bool
_dispatch_queue_drain_should_narrow(dispatch_invoke_context_t dic)
{
	uint64_t next_check = dic->dic_next_narrow_check;
	if (unlikely(next_check)) {
		uint64_t now = _dispatch_approximate_time();
		if (unlikely(next_check < now)) {
			return _dispatch_queue_drain_should_narrow_slow(now, dic);
		}
	}
	return false;
}
#else
#define _dispatch_queue_drain_init_narrowing_check_deadline(rq, dic) ((void)0)
#define _dispatch_queue_drain_should_narrow(dic)  false
#endif

/*
 * Drain comes in 2 flavours (serial/concurrent) and 2 modes
 * (redirecting or not).
 *
 * Serial
 * ~~~~~~
 * Serial drain is about serial queues (width == 1). It doesn't support
 * the redirecting mode, which doesn't make sense, and treats all continuations
 * as barriers. Bookkeeping is minimal in serial flavour, most of the loop
 * is optimized away.
 *
 * Serial drain stops if the width of the queue grows to larger than 1.
 * Going through a serial drain prevents any recursive drain from being
 * redirecting.
 *
 * Concurrent
 * ~~~~~~~~~~
 * When in non-redirecting mode (meaning one of the target queues is serial),
 * non-barriers and barriers alike run in the context of the drain thread.
 * Slow non-barrier items are still all signaled so that they can make progress
 * toward the dispatch_sync() that will serialize them all .
 *
 * In redirecting mode, non-barrier work items are redirected downward.
 *
 * Concurrent drain stops if the width of the queue becomes 1, so that the
 * queue drain moves to the more efficient serial mode.
 */
DISPATCH_ALWAYS_INLINE
static dispatch_queue_wakeup_target_t
_dispatch_queue_drain(dispatch_queue_t dq, dispatch_invoke_context_t dic,
		dispatch_invoke_flags_t flags, uint64_t *owned_ptr, bool serial_drain)
{
	dispatch_queue_t orig_tq = dq->do_targetq;
	dispatch_thread_frame_s dtf;
	struct dispatch_object_s *dc = NULL, *next_dc;
	uint64_t dq_state, owned = *owned_ptr;

	if (unlikely(!dq->dq_items_tail)) return NULL;

	_dispatch_thread_frame_push(&dtf, dq);
	if (serial_drain || _dq_state_is_in_barrier(owned)) {
		// we really own `IN_BARRIER + dq->dq_width * WIDTH_INTERVAL`
		// but width can change while draining barrier work items, so we only
		// convert to `dq->dq_width * WIDTH_INTERVAL` when we drop `IN_BARRIER`
		owned = DISPATCH_QUEUE_IN_BARRIER;
	} else {
		owned &= DISPATCH_QUEUE_WIDTH_MASK;
	}

	dc = _dispatch_queue_head(dq);
	goto first_iteration;

	for (;;) {
		dc = next_dc;
		if (unlikely(dic->dic_deferred)) {
			goto out_with_deferred_compute_owned;
		}
		if (unlikely(_dispatch_needs_to_return_to_kernel())) {
			_dispatch_return_to_kernel();
		}
		if (unlikely(!dc)) {
			if (!dq->dq_items_tail) {
				break;
			}
			dc = _dispatch_queue_head(dq);
		}
		if (unlikely(serial_drain != (dq->dq_width == 1))) {
			break;
		}
		if (unlikely(_dispatch_queue_drain_should_narrow(dic))) {
			break;
		}

first_iteration:
		dq_state = os_atomic_load(&dq->dq_state, relaxed);
		if (unlikely(_dq_state_is_suspended(dq_state))) {
			break;
		}
		if (unlikely(orig_tq != dq->do_targetq)) {
			break;
		}

		if (serial_drain || _dispatch_object_is_barrier(dc)) {
			if (!serial_drain && owned != DISPATCH_QUEUE_IN_BARRIER) {
				if (!_dispatch_queue_try_upgrade_full_width(dq, owned)) {
					goto out_with_no_width;
				}
				owned = DISPATCH_QUEUE_IN_BARRIER;
			}
			next_dc = _dispatch_queue_next(dq, dc);
			if (_dispatch_object_is_sync_waiter(dc)) {
				owned = 0;
				dic->dic_deferred = dc;
				goto out_with_deferred;
			}
		} else {
			if (owned == DISPATCH_QUEUE_IN_BARRIER) {
				// we just ran barrier work items, we have to make their
				// effect visible to other sync work items on other threads
				// that may start coming in after this point, hence the
				// release barrier
				os_atomic_xor2o(dq, dq_state, owned, release);
				owned = dq->dq_width * DISPATCH_QUEUE_WIDTH_INTERVAL;
			} else if (unlikely(owned == 0)) {
				if (_dispatch_object_is_sync_waiter(dc)) {
					// sync "readers" don't observe the limit
					_dispatch_queue_reserve_sync_width(dq);
				} else if (!_dispatch_queue_try_acquire_async(dq)) {
					goto out_with_no_width;
				}
				owned = DISPATCH_QUEUE_WIDTH_INTERVAL;
			}

			next_dc = _dispatch_queue_next(dq, dc);
			if (_dispatch_object_is_sync_waiter(dc)) {
				owned -= DISPATCH_QUEUE_WIDTH_INTERVAL;
				_dispatch_sync_waiter_redirect_or_wake(dq,
						DISPATCH_SYNC_WAITER_NO_UNLOCK, dc);
				continue;
			}

			if (flags & DISPATCH_INVOKE_REDIRECTING_DRAIN) {
				owned -= DISPATCH_QUEUE_WIDTH_INTERVAL;
				_dispatch_continuation_redirect(dq, dc);
				continue;
			}
		}

		_dispatch_continuation_pop_inline(dc, dic, flags, dq);
	}

	if (owned == DISPATCH_QUEUE_IN_BARRIER) {
		// if we're IN_BARRIER we really own the full width too
		owned += dq->dq_width * DISPATCH_QUEUE_WIDTH_INTERVAL;
	}
	if (dc) {
		owned = _dispatch_queue_adjust_owned(dq, owned, dc);
	}
	*owned_ptr &= DISPATCH_QUEUE_ENQUEUED | DISPATCH_QUEUE_ENQUEUED_ON_MGR;
	*owned_ptr |= owned;
	_dispatch_thread_frame_pop(&dtf);
	return dc ? dq->do_targetq : NULL;

out_with_no_width:
	*owned_ptr &= DISPATCH_QUEUE_ENQUEUED | DISPATCH_QUEUE_ENQUEUED_ON_MGR;
	_dispatch_thread_frame_pop(&dtf);
	return DISPATCH_QUEUE_WAKEUP_WAIT_FOR_EVENT;

out_with_deferred_compute_owned:
	if (serial_drain) {
		owned = DISPATCH_QUEUE_IN_BARRIER + DISPATCH_QUEUE_WIDTH_INTERVAL;
	} else {
		if (owned == DISPATCH_QUEUE_IN_BARRIER) {
			// if we're IN_BARRIER we really own the full width too
			owned += dq->dq_width * DISPATCH_QUEUE_WIDTH_INTERVAL;
		}
		if (dc) {
			owned = _dispatch_queue_adjust_owned(dq, owned, dc);
		}
	}
out_with_deferred:
	*owned_ptr &= DISPATCH_QUEUE_ENQUEUED | DISPATCH_QUEUE_ENQUEUED_ON_MGR;
	*owned_ptr |= owned;
	if (unlikely(flags & DISPATCH_INVOKE_DISALLOW_SYNC_WAITERS)) {
		DISPATCH_INTERNAL_CRASH(dc,
				"Deferred continuation on source, mach channel or mgr");
	}
	_dispatch_thread_frame_pop(&dtf);
	return dq->do_targetq;
}

DISPATCH_NOINLINE
static dispatch_queue_wakeup_target_t
_dispatch_queue_concurrent_drain(dispatch_queue_t dq,
		dispatch_invoke_context_t dic, dispatch_invoke_flags_t flags,
		uint64_t *owned)
{
	return _dispatch_queue_drain(dq, dic, flags, owned, false);
}

DISPATCH_NOINLINE
dispatch_queue_wakeup_target_t
_dispatch_queue_serial_drain(dispatch_queue_t dq, dispatch_invoke_context_t dic,
		dispatch_invoke_flags_t flags, uint64_t *owned)
{
	flags &= ~(dispatch_invoke_flags_t)DISPATCH_INVOKE_REDIRECTING_DRAIN;
	return _dispatch_queue_drain(dq, dic, flags, owned, true);
}

#if DISPATCH_COCOA_COMPAT
DISPATCH_NOINLINE
static void
_dispatch_main_queue_update_priority_from_thread(void)
{
	dispatch_queue_t dq = &_dispatch_main_q;
	uint64_t dq_state = os_atomic_load2o(dq, dq_state, relaxed);
	mach_port_t owner = _dq_state_drain_owner(dq_state);

	dispatch_priority_t main_pri =
			_dispatch_priority_from_pp_strip_flags(_dispatch_get_priority());
	dispatch_qos_t main_qos = _dispatch_priority_qos(main_pri);
	dispatch_qos_t max_qos = _dq_state_max_qos(dq_state);
	dispatch_qos_t old_qos = _dispatch_priority_qos(dq->dq_priority);

	// the main thread QoS was adjusted by someone else, learn the new QoS
	// and reinitialize _dispatch_main_q.dq_priority
	dq->dq_priority = _dispatch_priority_with_override_qos(main_pri, main_qos);

	if (old_qos < max_qos && main_qos == DISPATCH_QOS_UNSPECIFIED) {
		// main thread is opted out of QoS and we had an override
		return _dispatch_thread_override_end(owner, dq);
	}

	if (old_qos < max_qos && max_qos <= main_qos) {
		// main QoS was raised, and we had an override which is now useless
		return _dispatch_thread_override_end(owner, dq);
	}

	if (main_qos < max_qos && max_qos <= old_qos) {
		// main thread QoS was lowered, and we actually need an override
		pthread_priority_t pp = _dispatch_qos_to_pp(max_qos);
		return _dispatch_thread_override_start(owner, pp, dq);
	}
}

static void
_dispatch_main_queue_drain(void)
{
	dispatch_queue_t dq = &_dispatch_main_q;
	dispatch_thread_frame_s dtf;

	if (!dq->dq_items_tail) {
		return;
	}

	_dispatch_perfmon_start_notrace();
	if (!fastpath(_dispatch_queue_is_thread_bound(dq))) {
		DISPATCH_CLIENT_CRASH(0, "_dispatch_main_queue_callback_4CF called"
				" after dispatch_main()");
	}
	uint64_t dq_state = os_atomic_load2o(dq, dq_state, relaxed);
	if (unlikely(!_dq_state_drain_locked_by_self(dq_state))) {
		DISPATCH_CLIENT_CRASH((uintptr_t)dq_state,
				"_dispatch_main_queue_callback_4CF called"
				" from the wrong thread");
	}

	dispatch_once_f(&_dispatch_main_q_handle_pred, dq,
			_dispatch_runloop_queue_handle_init);

	// <rdar://problem/23256682> hide the frame chaining when CFRunLoop
	// drains the main runloop, as this should not be observable that way
	_dispatch_adopt_wlh_anon();
	_dispatch_thread_frame_push_and_rebase(&dtf, dq, NULL);

	pthread_priority_t pp = _dispatch_get_priority();
	dispatch_priority_t pri = _dispatch_priority_from_pp(pp);
	dispatch_qos_t qos = _dispatch_priority_qos(pri);
	voucher_t voucher = _voucher_copy();

	if (unlikely(qos != _dispatch_priority_qos(dq->dq_priority))) {
		_dispatch_main_queue_update_priority_from_thread();
	}
	dispatch_priority_t old_dbp = _dispatch_set_basepri(pri);
	_dispatch_set_basepri_override_qos(DISPATCH_QOS_SATURATED);

	dispatch_invoke_context_s dic = { };
	struct dispatch_object_s *dc, *next_dc, *tail;
	dc = os_mpsc_capture_snapshot(dq, dq_items, &tail);
	do {
		next_dc = os_mpsc_pop_snapshot_head(dc, tail, do_next);
		_dispatch_continuation_pop_inline(dc, &dic, DISPATCH_INVOKE_NONE, dq);
	} while ((dc = next_dc));

	dx_wakeup(dq, 0, 0);
	_dispatch_voucher_debug("main queue restore", voucher);
	_dispatch_reset_basepri(old_dbp);
	_dispatch_reset_basepri_override();
	_dispatch_reset_priority_and_voucher(pp, voucher);
	_dispatch_thread_frame_pop(&dtf);
	_dispatch_reset_wlh();
	_dispatch_force_cache_cleanup();
	_dispatch_perfmon_end_notrace();
}

static bool
_dispatch_runloop_queue_drain_one(dispatch_queue_t dq)
{
	if (!dq->dq_items_tail) {
		return false;
	}
	_dispatch_perfmon_start_notrace();
	dispatch_thread_frame_s dtf;
	bool should_reset_wlh = _dispatch_adopt_wlh_anon_recurse();
	_dispatch_thread_frame_push(&dtf, dq);
	pthread_priority_t pp = _dispatch_get_priority();
	dispatch_priority_t pri = _dispatch_priority_from_pp(pp);
	voucher_t voucher = _voucher_copy();
	dispatch_priority_t old_dbp = _dispatch_set_basepri(pri);
	_dispatch_set_basepri_override_qos(DISPATCH_QOS_SATURATED);

	dispatch_invoke_context_s dic = { };
	struct dispatch_object_s *dc, *next_dc;
	dc = _dispatch_queue_head(dq);
	next_dc = _dispatch_queue_next(dq, dc);
	_dispatch_continuation_pop_inline(dc, &dic, DISPATCH_INVOKE_NONE, dq);

	if (!next_dc) {
		dx_wakeup(dq, 0, 0);
	}

	_dispatch_voucher_debug("runloop queue restore", voucher);
	_dispatch_reset_basepri(old_dbp);
	_dispatch_reset_basepri_override();
	_dispatch_reset_priority_and_voucher(pp, voucher);
	_dispatch_thread_frame_pop(&dtf);
	if (should_reset_wlh) _dispatch_reset_wlh();
	_dispatch_force_cache_cleanup();
	_dispatch_perfmon_end_notrace();
	return next_dc;
}
#endif

void
_dispatch_mgr_queue_drain(void)
{
	const dispatch_invoke_flags_t flags = DISPATCH_INVOKE_MANAGER_DRAIN;
	dispatch_invoke_context_s dic = { };
	dispatch_queue_t dq = &_dispatch_mgr_q;
	uint64_t owned = DISPATCH_QUEUE_SERIAL_DRAIN_OWNED;

	if (dq->dq_items_tail) {
		_dispatch_perfmon_start();
		_dispatch_set_basepri_override_qos(DISPATCH_QOS_SATURATED);
		if (slowpath(_dispatch_queue_serial_drain(dq, &dic, flags, &owned))) {
			DISPATCH_INTERNAL_CRASH(0, "Interrupted drain on manager queue");
		}
		_dispatch_voucher_debug("mgr queue clear", NULL);
		_voucher_clear();
		_dispatch_reset_basepri_override();
		_dispatch_perfmon_end(perfmon_thread_manager);
	}

#if DISPATCH_USE_KEVENT_WORKQUEUE
	if (!_dispatch_kevent_workqueue_enabled)
#endif
	{
		_dispatch_force_cache_cleanup();
	}
}

#pragma mark -
#pragma mark dispatch_queue_invoke

void
_dispatch_queue_drain_sync_waiter(dispatch_queue_t dq,
		dispatch_invoke_context_t dic, dispatch_invoke_flags_t flags,
		uint64_t owned)
{
	struct dispatch_object_s *dc = dic->dic_deferred;
	dispatch_assert(_dispatch_object_is_sync_waiter(dc));
	dic->dic_deferred = NULL;
	if (flags & DISPATCH_INVOKE_WLH) {
		// Leave the enqueued bit in place, completion of the last sync waiter
		// in the handoff chain is responsible for dequeuing
		//
		// We currently have a +2 to consume, but we need to keep a +1
		// for the thread request
		dispatch_assert(_dq_state_is_enqueued_on_target(owned));
		dispatch_assert(!_dq_state_is_enqueued_on_manager(owned));
		owned &= ~DISPATCH_QUEUE_ENQUEUED;
		_dispatch_release_no_dispose(dq);
	} else {
		// The sync waiter must own a reference
		_dispatch_release_2_no_dispose(dq);
	}
	return _dispatch_sync_waiter_redirect_or_wake(dq, owned, dc);
}

void
_dispatch_queue_finalize_activation(dispatch_queue_t dq,
		DISPATCH_UNUSED bool *allow_resume)
{
	dispatch_queue_t tq = dq->do_targetq;
	_dispatch_queue_priority_inherit_from_target(dq, tq);
	_dispatch_queue_inherit_wlh_from_target(dq, tq);
}

DISPATCH_ALWAYS_INLINE
static inline dispatch_queue_wakeup_target_t
dispatch_queue_invoke2(dispatch_queue_t dq, dispatch_invoke_context_t dic,
		dispatch_invoke_flags_t flags, uint64_t *owned)
{
	dispatch_queue_t otq = dq->do_targetq;
	dispatch_queue_t cq = _dispatch_queue_get_current();

	if (slowpath(cq != otq)) {
		return otq;
	}
	if (dq->dq_width == 1) {
		return _dispatch_queue_serial_drain(dq, dic, flags, owned);
	}
	return _dispatch_queue_concurrent_drain(dq, dic, flags, owned);
}

// 6618342 Contact the team that owns the Instrument DTrace probe before
//         renaming this symbol
DISPATCH_NOINLINE
void
_dispatch_queue_invoke(dispatch_queue_t dq, dispatch_invoke_context_t dic,
		dispatch_invoke_flags_t flags)
{
	_dispatch_queue_class_invoke(dq, dic, flags, 0, dispatch_queue_invoke2);
}

#pragma mark -
#pragma mark dispatch_queue_class_wakeup

#if HAVE_PTHREAD_WORKQUEUE_QOS
void
_dispatch_queue_override_invoke(dispatch_continuation_t dc,
		dispatch_invoke_context_t dic, dispatch_invoke_flags_t flags)
{
	dispatch_queue_t old_rq = _dispatch_queue_get_current();
	dispatch_queue_t assumed_rq = dc->dc_other;
	dispatch_priority_t old_dp;
	voucher_t ov = DISPATCH_NO_VOUCHER;
	dispatch_object_t dou;

	dou._do = dc->dc_data;
	old_dp = _dispatch_root_queue_identity_assume(assumed_rq);
	if (dc_type(dc) == DISPATCH_CONTINUATION_TYPE(OVERRIDE_STEALING)) {
		flags |= DISPATCH_INVOKE_STEALING;
	} else {
		// balance the fake continuation push in
		// _dispatch_root_queue_push_override
		_dispatch_trace_continuation_pop(assumed_rq, dou._do);
	}
	_dispatch_continuation_pop_forwarded(dc, ov, DISPATCH_OBJ_CONSUME_BIT, {
		if (_dispatch_object_has_vtable(dou._do)) {
			dx_invoke(dou._do, dic, flags);
		} else {
			_dispatch_continuation_invoke_inline(dou, ov, flags);
		}
	});
	_dispatch_reset_basepri(old_dp);
	_dispatch_queue_set_current(old_rq);
}

DISPATCH_ALWAYS_INLINE
static inline bool
_dispatch_root_queue_push_needs_override(dispatch_queue_t rq,
		dispatch_qos_t qos)
{
	dispatch_qos_t rqos = _dispatch_priority_qos(rq->dq_priority);
	bool defaultqueue = rq->dq_priority & DISPATCH_PRIORITY_FLAG_DEFAULTQUEUE;

	if (unlikely(!rqos)) return false;

	return defaultqueue ? qos && qos != rqos : qos > rqos;
}

DISPATCH_ALWAYS_INLINE
static inline bool
_dispatch_root_queue_push_queue_override_needed(dispatch_queue_t rq,
		dispatch_qos_t qos)
{
	// for root queues, the override is the guaranteed minimum override level
	return qos > _dispatch_priority_override_qos(rq->dq_priority);
}

DISPATCH_NOINLINE
static void
_dispatch_root_queue_push_override(dispatch_queue_t orig_rq,
		dispatch_object_t dou, dispatch_qos_t qos)
{
	bool overcommit = orig_rq->dq_priority & DISPATCH_PRIORITY_FLAG_OVERCOMMIT;
	dispatch_queue_t rq = _dispatch_get_root_queue(qos, overcommit);
	dispatch_continuation_t dc = dou._dc;

	if (_dispatch_object_is_redirection(dc)) {
		// no double-wrap is needed, _dispatch_async_redirect_invoke will do
		// the right thing
		dc->dc_func = (void *)orig_rq;
	} else {
		dc = _dispatch_continuation_alloc();
		dc->do_vtable = DC_VTABLE(OVERRIDE_OWNING);
		// fake that we queued `dou` on `orig_rq` for introspection purposes
		_dispatch_trace_continuation_push(orig_rq, dou);
		dc->dc_ctxt = dc;
		dc->dc_other = orig_rq;
		dc->dc_data = dou._do;
		dc->dc_priority = DISPATCH_NO_PRIORITY;
		dc->dc_voucher = DISPATCH_NO_VOUCHER;
	}
	_dispatch_root_queue_push_inline(rq, dc, dc, 1);
}

DISPATCH_NOINLINE
static void
_dispatch_root_queue_push_override_stealer(dispatch_queue_t orig_rq,
		dispatch_queue_t dq, dispatch_qos_t qos)
{
	bool overcommit = orig_rq->dq_priority & DISPATCH_PRIORITY_FLAG_OVERCOMMIT;
	dispatch_queue_t rq = _dispatch_get_root_queue(qos, overcommit);
	dispatch_continuation_t dc = _dispatch_continuation_alloc();

	dc->do_vtable = DC_VTABLE(OVERRIDE_STEALING);
	_dispatch_retain_2(dq);
	dc->dc_func = NULL;
	dc->dc_ctxt = dc;
	dc->dc_other = orig_rq;
	dc->dc_data = dq;
	dc->dc_priority = DISPATCH_NO_PRIORITY;
	dc->dc_voucher = DISPATCH_NO_VOUCHER;
	_dispatch_root_queue_push_inline(rq, dc, dc, 1);
}

DISPATCH_NOINLINE
static void
_dispatch_queue_class_wakeup_with_override_slow(dispatch_queue_t dq,
		uint64_t dq_state, dispatch_wakeup_flags_t flags)
{
	dispatch_qos_t oqos, qos = _dq_state_max_qos(dq_state);
	dispatch_queue_t tq;
	bool locked;

	if (_dq_state_is_base_anon(dq_state)) {
		mach_port_t owner = _dq_state_drain_owner(dq_state);
		if (owner) {
			(void)_dispatch_wqthread_override_start_check_owner(owner, qos,
				&dq->dq_state_lock);
			goto out;
		}
	}

	tq = dq->do_targetq;

	if (likely(!_dispatch_queue_is_legacy(dq))) {
		locked = false;
	} else if (_dispatch_is_in_root_queues_array(tq)) {
		// avoid locking when we recognize the target queue as a global root
		// queue it is gross, but is a very common case. The locking isn't
		// needed because these target queues cannot go away.
		locked = false;
	} else if (_dispatch_queue_sidelock_trylock(dq, qos)) {
		// <rdar://problem/17735825> to traverse the tq chain safely we must
		// lock it to ensure it cannot change
		locked = true;
		tq = dq->do_targetq;
		_dispatch_ktrace1(DISPATCH_PERF_mutable_target, dq);
	} else {
		//
		// Leading to being there, the current thread has:
		// 1. enqueued an object on `dq`
		// 2. raised the max_qos value, set RECEIVED_OVERRIDE on `dq`
		//    and didn't see an owner
		// 3. tried and failed to acquire the side lock
		//
		// The side lock owner can only be one of three things:
		//
		// - The suspend/resume side count code. Besides being unlikely,
		//   it means that at this moment the queue is actually suspended,
		//   which transfers the responsibility of applying the override to
		//   the eventual dispatch_resume().
		//
		// - A dispatch_set_target_queue() call. The fact that we saw no `owner`
		//   means that the trysync it does wasn't being drained when (2)
		//   happened which can only be explained by one of these interleavings:
		//
		//    o `dq` became idle between when the object queued in (1) ran and
		//      the set_target_queue call and we were unlucky enough that our
		//      step (2) happened while this queue was idle. There is no reason
		//		to override anything anymore, the queue drained to completion
		//      while we were preempted, our job is done.
		//
		//    o `dq` is queued but not draining during (1-2), then when we try
		//      to lock at (3) the queue is now draining a set_target_queue.
		//      This drainer must have seen the effects of (2) and that guy has
		//      applied our override. Our job is done.
		//
		// - Another instance of _dispatch_queue_class_wakeup_with_override(),
		//   which is fine because trylock leaves a hint that we failed our
		//   trylock, causing the tryunlock below to fail and reassess whether
		//   a better override needs to be applied.
		//
		_dispatch_ktrace1(DISPATCH_PERF_mutable_target, dq);
		goto out;
	}

apply_again:
	if (dx_hastypeflag(tq, QUEUE_ROOT)) {
		if (_dispatch_root_queue_push_queue_override_needed(tq, qos)) {
			_dispatch_root_queue_push_override_stealer(tq, dq, qos);
		}
	} else if (_dispatch_queue_need_override(tq, qos)) {
		dx_wakeup(tq, qos, 0);
	}
	while (unlikely(locked && !_dispatch_queue_sidelock_tryunlock(dq))) {
		// rdar://problem/24081326
		//
		// Another instance of _dispatch_queue_class_wakeup_with_override()
		// tried to acquire the side lock while we were running, and could have
		// had a better override than ours to apply.
		//
		oqos = _dq_state_max_qos(os_atomic_load2o(dq, dq_state, relaxed));
		if (oqos > qos) {
			qos = oqos;
			// The other instance had a better priority than ours, override
			// our thread, and apply the override that wasn't applied to `dq`
			// because of us.
			goto apply_again;
		}
	}

out:
	if (flags & DISPATCH_WAKEUP_CONSUME_2) {
		return _dispatch_release_2_tailcall(dq);
	}
}


DISPATCH_ALWAYS_INLINE
static inline void
_dispatch_queue_class_wakeup_with_override(dispatch_queue_t dq,
		uint64_t dq_state, dispatch_wakeup_flags_t flags)
{
	dispatch_assert(_dq_state_should_override(dq_state));

	return _dispatch_queue_class_wakeup_with_override_slow(dq, dq_state, flags);
}
#endif // HAVE_PTHREAD_WORKQUEUE_QOS

DISPATCH_NOINLINE
void
_dispatch_root_queue_push(dispatch_queue_t rq, dispatch_object_t dou,
		dispatch_qos_t qos)
{
#if DISPATCH_USE_KEVENT_WORKQUEUE
	dispatch_deferred_items_t ddi = _dispatch_deferred_items_get();
	if (unlikely(ddi && ddi->ddi_can_stash)) {
		dispatch_object_t old_dou = ddi->ddi_stashed_dou;
		dispatch_priority_t rq_overcommit;
		rq_overcommit = rq->dq_priority & DISPATCH_PRIORITY_FLAG_OVERCOMMIT;

		if (likely(!old_dou._do || rq_overcommit)) {
			dispatch_queue_t old_rq = ddi->ddi_stashed_rq;
			dispatch_qos_t old_qos = ddi->ddi_stashed_qos;
			ddi->ddi_stashed_rq = rq;
			ddi->ddi_stashed_dou = dou;
			ddi->ddi_stashed_qos = qos;
			_dispatch_debug("deferring item %p, rq %p, qos %d",
					dou._do, rq, qos);
			if (rq_overcommit) {
				ddi->ddi_can_stash = false;
			}
			if (likely(!old_dou._do)) {
				return;
			}
			// push the previously stashed item
			qos = old_qos;
			rq = old_rq;
			dou = old_dou;
		}
	}
#endif
#if HAVE_PTHREAD_WORKQUEUE_QOS
	if (_dispatch_root_queue_push_needs_override(rq, qos)) {
		return _dispatch_root_queue_push_override(rq, dou, qos);
	}
#else
	(void)qos;
#endif
	_dispatch_root_queue_push_inline(rq, dou, dou, 1);
}

void
_dispatch_root_queue_wakeup(dispatch_queue_t dq,
		DISPATCH_UNUSED dispatch_qos_t qos, dispatch_wakeup_flags_t flags)
{
	if (!(flags & DISPATCH_WAKEUP_BLOCK_WAIT)) {
		DISPATCH_INTERNAL_CRASH(dq->dq_priority,
				"Don't try to wake up or override a root queue");
	}
	if (flags & DISPATCH_WAKEUP_CONSUME_2) {
		return _dispatch_release_2_tailcall(dq);
	}
}

DISPATCH_NOINLINE
void
_dispatch_queue_push(dispatch_queue_t dq, dispatch_object_t dou,
		dispatch_qos_t qos)
{
	_dispatch_queue_push_inline(dq, dou, qos);
}

DISPATCH_NOINLINE
void
_dispatch_queue_class_wakeup(dispatch_queue_t dq, dispatch_qos_t qos,
		dispatch_wakeup_flags_t flags, dispatch_queue_wakeup_target_t target)
{
	dispatch_assert(target != DISPATCH_QUEUE_WAKEUP_WAIT_FOR_EVENT);

	if (target && !(flags & DISPATCH_WAKEUP_CONSUME_2)) {
		_dispatch_retain_2(dq);
		flags |= DISPATCH_WAKEUP_CONSUME_2;
	}

	if (unlikely(flags & DISPATCH_WAKEUP_BARRIER_COMPLETE)) {
		//
		// _dispatch_queue_class_barrier_complete() is about what both regular
		// queues and sources needs to evaluate, but the former can have sync
		// handoffs to perform which _dispatch_queue_class_barrier_complete()
		// doesn't handle, only _dispatch_queue_barrier_complete() does.
		//
		// _dispatch_queue_wakeup() is the one for plain queues that calls
		// _dispatch_queue_barrier_complete(), and this is only taken for non
		// queue types.
		//
		dispatch_assert(dx_metatype(dq) != _DISPATCH_QUEUE_TYPE);
		return _dispatch_queue_class_barrier_complete(dq, qos, flags, target,
				DISPATCH_QUEUE_SERIAL_DRAIN_OWNED);
	}

	if (target) {
		uint64_t old_state, new_state, enqueue = DISPATCH_QUEUE_ENQUEUED;
		if (target == DISPATCH_QUEUE_WAKEUP_MGR) {
			enqueue = DISPATCH_QUEUE_ENQUEUED_ON_MGR;
		}
		qos = _dispatch_queue_override_qos(dq, qos);
		os_atomic_rmw_loop2o(dq, dq_state, old_state, new_state, release, {
			new_state = _dq_state_merge_qos(old_state, qos);
			if (likely(!_dq_state_is_suspended(old_state) &&
					!_dq_state_is_enqueued(old_state) &&
					(!_dq_state_drain_locked(old_state) ||
					(enqueue != DISPATCH_QUEUE_ENQUEUED_ON_MGR &&
					_dq_state_is_base_wlh(old_state))))) {
				new_state |= enqueue;
			}
			if (flags & DISPATCH_WAKEUP_MAKE_DIRTY) {
				new_state |= DISPATCH_QUEUE_DIRTY;
			} else if (new_state == old_state) {
				os_atomic_rmw_loop_give_up(goto done);
			}
		});

		if (likely((old_state ^ new_state) & enqueue)) {
			dispatch_queue_t tq;
			if (target == DISPATCH_QUEUE_WAKEUP_TARGET) {
				// the rmw_loop above has no acquire barrier, as the last block
				// of a queue asyncing to that queue is not an uncommon pattern
				// and in that case the acquire would be completely useless
				//
				// so instead use depdendency ordering to read
				// the targetq pointer.
				os_atomic_thread_fence(dependency);
				tq = os_atomic_load_with_dependency_on2o(dq, do_targetq,
						(long)new_state);
			} else {
				tq = target;
			}
			dispatch_assert(_dq_state_is_enqueued(new_state));
			return _dispatch_queue_push_queue(tq, dq, new_state);
		}
#if HAVE_PTHREAD_WORKQUEUE_QOS
		if (unlikely((old_state ^ new_state) & DISPATCH_QUEUE_MAX_QOS_MASK)) {
			if (_dq_state_should_override(new_state)) {
				return _dispatch_queue_class_wakeup_with_override(dq, new_state,
						flags);
			}
		}
	} else if (qos) {
		//
		// Someone is trying to override the last work item of the queue.
		//
		uint64_t old_state, new_state;
		os_atomic_rmw_loop2o(dq, dq_state, old_state, new_state, relaxed, {
			if (!_dq_state_drain_locked(old_state) ||
					!_dq_state_is_enqueued(old_state)) {
				os_atomic_rmw_loop_give_up(goto done);
			}
			new_state = _dq_state_merge_qos(old_state, qos);
			if (new_state == old_state) {
				os_atomic_rmw_loop_give_up(goto done);
			}
		});
		if (_dq_state_should_override(new_state)) {
			return _dispatch_queue_class_wakeup_with_override(dq, new_state,
					flags);
		}
#endif // HAVE_PTHREAD_WORKQUEUE_QOS
	}
done:
	if (likely(flags & DISPATCH_WAKEUP_CONSUME_2)) {
		return _dispatch_release_2_tailcall(dq);
	}
}

DISPATCH_NOINLINE
static void
_dispatch_queue_push_sync_waiter(dispatch_queue_t dq,
		dispatch_sync_context_t dsc, dispatch_qos_t qos)
{
	uint64_t old_state, new_state;

	if (unlikely(dx_type(dq) == DISPATCH_QUEUE_NETWORK_EVENT_TYPE)) {
		DISPATCH_CLIENT_CRASH(0,
				"dispatch_sync onto a network event queue");
	}

	_dispatch_trace_continuation_push(dq, dsc->_as_dc);

	if (unlikely(_dispatch_queue_push_update_tail(dq, dsc->_as_do))) {
		// for slow waiters, we borrow the reference of the caller
		// so we don't need to protect the wakeup with a temporary retain
		_dispatch_queue_push_update_head(dq, dsc->_as_do);
		if (unlikely(_dispatch_queue_is_thread_bound(dq))) {
			return dx_wakeup(dq, qos, DISPATCH_WAKEUP_MAKE_DIRTY);
		}

		uint64_t pending_barrier_width =
				(dq->dq_width - 1) * DISPATCH_QUEUE_WIDTH_INTERVAL;
		uint64_t set_owner_and_set_full_width_and_in_barrier =
				_dispatch_lock_value_for_self() |
				DISPATCH_QUEUE_WIDTH_FULL_BIT | DISPATCH_QUEUE_IN_BARRIER;
		// similar to _dispatch_queue_drain_try_unlock()
		os_atomic_rmw_loop2o(dq, dq_state, old_state, new_state, release, {
			new_state  = _dq_state_merge_qos(old_state, qos);
			new_state |= DISPATCH_QUEUE_DIRTY;
			if (unlikely(_dq_state_drain_locked(old_state) ||
					!_dq_state_is_runnable(old_state))) {
				// not runnable, so we should just handle overrides
			} else if (_dq_state_is_base_wlh(old_state) &&
					_dq_state_is_enqueued(old_state)) {
				// 32123779 let the event thread redrive since it's out already
			} else if (_dq_state_has_pending_barrier(old_state) ||
					new_state + pending_barrier_width <
					DISPATCH_QUEUE_WIDTH_FULL_BIT) {
				// see _dispatch_queue_drain_try_lock
				new_state &= DISPATCH_QUEUE_DRAIN_PRESERVED_BITS_MASK;
				new_state |= set_owner_and_set_full_width_and_in_barrier;
			}
		});

		if (_dq_state_is_base_wlh(old_state) &&
				(dsc->dsc_waiter == _dispatch_tid_self())) {
			dsc->dsc_wlh_was_first = true;
		}

		if ((old_state ^ new_state) & DISPATCH_QUEUE_IN_BARRIER) {
			return _dispatch_queue_barrier_complete(dq, qos, 0);
		}
#if HAVE_PTHREAD_WORKQUEUE_QOS
		if (unlikely((old_state ^ new_state) & DISPATCH_QUEUE_MAX_QOS_MASK)) {
			if (_dq_state_should_override(new_state)) {
				return _dispatch_queue_class_wakeup_with_override(dq,
						new_state, 0);
			}
		}
	} else if (unlikely(qos)) {
		os_atomic_rmw_loop2o(dq, dq_state, old_state, new_state, relaxed, {
			new_state = _dq_state_merge_qos(old_state, qos);
			if (old_state == new_state) {
				os_atomic_rmw_loop_give_up(return);
			}
		});
		if (_dq_state_should_override(new_state)) {
			return _dispatch_queue_class_wakeup_with_override(dq, new_state, 0);
		}
#endif // HAVE_PTHREAD_WORKQUEUE_QOS
	}
}

#pragma mark -
#pragma mark dispatch_root_queue_drain

DISPATCH_NOINLINE
static bool
_dispatch_root_queue_drain_one_slow(dispatch_queue_t dq)
{
	dispatch_root_queue_context_t qc = dq->do_ctxt;
	struct dispatch_object_s *const mediator = (void *)~0ul;
	bool pending = false, available = true;
	unsigned int sleep_time = DISPATCH_CONTENTION_USLEEP_START;

	do {
		// Spin for a short while in case the contention is temporary -- e.g.
		// when starting up after dispatch_apply, or when executing a few
		// short continuations in a row.
		if (_dispatch_contention_wait_until(dq->dq_items_head != mediator)) {
			goto out;
		}
		// Since we have serious contention, we need to back off.
		if (!pending) {
			// Mark this queue as pending to avoid requests for further threads
			(void)os_atomic_inc2o(qc, dgq_pending, relaxed);
			pending = true;
		}
		_dispatch_contention_usleep(sleep_time);
		if (fastpath(dq->dq_items_head != mediator)) goto out;
		sleep_time *= 2;
	} while (sleep_time < DISPATCH_CONTENTION_USLEEP_MAX);

	// The ratio of work to libdispatch overhead must be bad. This
	// scenario implies that there are too many threads in the pool.
	// Create a new pending thread and then exit this thread.
	// The kernel will grant a new thread when the load subsides.
	_dispatch_debug("contention on global queue: %p", dq);
	available = false;
out:
	if (pending) {
		(void)os_atomic_dec2o(qc, dgq_pending, relaxed);
	}
	if (!available) {
		_dispatch_global_queue_poke(dq, 1, 0);
	}
	return available;
}

DISPATCH_ALWAYS_INLINE
static inline bool
_dispatch_root_queue_drain_one2(dispatch_queue_t dq)
{
	// Wait for queue head and tail to be both non-empty or both empty
	bool available; // <rdar://problem/15917893>
	_dispatch_wait_until((dq->dq_items_head != NULL) ==
			(available = (dq->dq_items_tail != NULL)));
	return available;
}

DISPATCH_ALWAYS_INLINE_NDEBUG
static inline struct dispatch_object_s *
_dispatch_root_queue_drain_one(dispatch_queue_t dq)
{
	struct dispatch_object_s *head, *next, *const mediator = (void *)~0ul;

start:
	// The mediator value acts both as a "lock" and a signal
	head = os_atomic_xchg2o(dq, dq_items_head, mediator, relaxed);

	if (slowpath(head == NULL)) {
		// The first xchg on the tail will tell the enqueueing thread that it
		// is safe to blindly write out to the head pointer. A cmpxchg honors
		// the algorithm.
		if (slowpath(!os_atomic_cmpxchg2o(dq, dq_items_head, mediator,
				NULL, relaxed))) {
			goto start;
		}
		if (slowpath(dq->dq_items_tail) && // <rdar://problem/14416349>
				_dispatch_root_queue_drain_one2(dq)) {
			goto start;
		}
		_dispatch_root_queue_debug("no work on global queue: %p", dq);
		return NULL;
	}

	if (slowpath(head == mediator)) {
		// This thread lost the race for ownership of the queue.
		if (fastpath(_dispatch_root_queue_drain_one_slow(dq))) {
			goto start;
		}
		return NULL;
	}

	// Restore the head pointer to a sane value before returning.
	// If 'next' is NULL, then this item _might_ be the last item.
	next = fastpath(head->do_next);

	if (slowpath(!next)) {
		os_atomic_store2o(dq, dq_items_head, NULL, relaxed);
		// 22708742: set tail to NULL with release, so that NULL write to head
		//           above doesn't clobber head from concurrent enqueuer
		if (os_atomic_cmpxchg2o(dq, dq_items_tail, head, NULL, release)) {
			// both head and tail are NULL now
			goto out;
		}
		// There must be a next item now.
		next = os_mpsc_get_next(head, do_next);
	}

	os_atomic_store2o(dq, dq_items_head, next, relaxed);
	_dispatch_global_queue_poke(dq, 1, 0);
out:
	return head;
}

#if DISPATCH_USE_KEVENT_WORKQUEUE
void
_dispatch_root_queue_drain_deferred_wlh(dispatch_deferred_items_t ddi
		DISPATCH_PERF_MON_ARGS_PROTO)
{
	dispatch_queue_t rq = ddi->ddi_stashed_rq;
	dispatch_queue_t dq = ddi->ddi_stashed_dou._dq;
	_dispatch_queue_set_current(rq);
	dispatch_priority_t old_pri = _dispatch_set_basepri_wlh(rq->dq_priority);
	dispatch_invoke_context_s dic = { };
	dispatch_invoke_flags_t flags = DISPATCH_INVOKE_WORKER_DRAIN |
			DISPATCH_INVOKE_REDIRECTING_DRAIN | DISPATCH_INVOKE_WLH;
	_dispatch_queue_drain_init_narrowing_check_deadline(&dic, rq->dq_priority);
	uint64_t dq_state;

	ddi->ddi_wlh_servicing = true;
	if (unlikely(_dispatch_needs_to_return_to_kernel())) {
		_dispatch_return_to_kernel();
	}
retry:
	dispatch_assert(ddi->ddi_wlh_needs_delete);
	_dispatch_trace_continuation_pop(rq, dq);

	if (_dispatch_queue_drain_try_lock_wlh(dq, &dq_state)) {
		dx_invoke(dq, &dic, flags);
		if (!ddi->ddi_wlh_needs_delete) {
			goto park;
		}
		dq_state = os_atomic_load2o(dq, dq_state, relaxed);
		if (unlikely(!_dq_state_is_base_wlh(dq_state))) { // rdar://32671286
			goto park;
		}
		if (unlikely(_dq_state_is_enqueued_on_target(dq_state))) {
			_dispatch_retain(dq);
			_dispatch_trace_continuation_push(dq->do_targetq, dq);
			goto retry;
		}
	} else {
		_dispatch_release_no_dispose(dq);
	}

	_dispatch_event_loop_leave_deferred((dispatch_wlh_t)dq, dq_state);

park:
	// event thread that could steal
	_dispatch_perfmon_end(perfmon_thread_event_steal);
	_dispatch_reset_basepri(old_pri);
	_dispatch_reset_basepri_override();
	_dispatch_queue_set_current(NULL);

	_dispatch_voucher_debug("root queue clear", NULL);
	_dispatch_reset_voucher(NULL, DISPATCH_THREAD_PARK);
}

void
_dispatch_root_queue_drain_deferred_item(dispatch_deferred_items_t ddi
		DISPATCH_PERF_MON_ARGS_PROTO)
{
	dispatch_queue_t rq = ddi->ddi_stashed_rq;
	_dispatch_queue_set_current(rq);
	dispatch_priority_t old_pri = _dispatch_set_basepri(rq->dq_priority);

	dispatch_invoke_context_s dic = { };
	dispatch_invoke_flags_t flags = DISPATCH_INVOKE_WORKER_DRAIN |
			DISPATCH_INVOKE_REDIRECTING_DRAIN;
#if DISPATCH_COCOA_COMPAT
	_dispatch_last_resort_autorelease_pool_push(&dic);
#endif // DISPATCH_COCOA_COMPAT
	_dispatch_queue_drain_init_narrowing_check_deadline(&dic, rq->dq_priority);
	_dispatch_continuation_pop_inline(ddi->ddi_stashed_dou, &dic, flags, rq);

	// event thread that could steal
	_dispatch_perfmon_end(perfmon_thread_event_steal);
#if DISPATCH_COCOA_COMPAT
	_dispatch_last_resort_autorelease_pool_pop(&dic);
#endif // DISPATCH_COCOA_COMPAT
	_dispatch_reset_basepri(old_pri);
	_dispatch_reset_basepri_override();
	_dispatch_queue_set_current(NULL);

	_dispatch_voucher_debug("root queue clear", NULL);
	_dispatch_reset_voucher(NULL, DISPATCH_THREAD_PARK);
}
#endif

DISPATCH_NOT_TAIL_CALLED // prevent tailcall (for Instrument DTrace probe)
static void
_dispatch_root_queue_drain(dispatch_queue_t dq, pthread_priority_t pp)
{
#if DISPATCH_DEBUG
	dispatch_queue_t cq;
	if (slowpath(cq = _dispatch_queue_get_current())) {
		DISPATCH_INTERNAL_CRASH(cq, "Premature thread recycling");
	}
#endif
	_dispatch_queue_set_current(dq);
	dispatch_priority_t pri = dq->dq_priority;
	if (!pri) pri = _dispatch_priority_from_pp(pp);
	dispatch_priority_t old_dbp = _dispatch_set_basepri(pri);
	_dispatch_adopt_wlh_anon();

	struct dispatch_object_s *item;
	bool reset = false;
	dispatch_invoke_context_s dic = { };
#if DISPATCH_COCOA_COMPAT
	_dispatch_last_resort_autorelease_pool_push(&dic);
#endif // DISPATCH_COCOA_COMPAT
	dispatch_invoke_flags_t flags = DISPATCH_INVOKE_WORKER_DRAIN |
			DISPATCH_INVOKE_REDIRECTING_DRAIN;
	_dispatch_queue_drain_init_narrowing_check_deadline(&dic, pri);
	_dispatch_perfmon_start();
	while ((item = fastpath(_dispatch_root_queue_drain_one(dq)))) {
		if (reset) _dispatch_wqthread_override_reset();
		_dispatch_continuation_pop_inline(item, &dic, flags, dq);
		reset = _dispatch_reset_basepri_override();
		if (unlikely(_dispatch_queue_drain_should_narrow(&dic))) {
			break;
		}
	}

	// overcommit or not. worker thread
	if (pri & _PTHREAD_PRIORITY_OVERCOMMIT_FLAG) {
		_dispatch_perfmon_end(perfmon_thread_worker_oc);
	} else {
		_dispatch_perfmon_end(perfmon_thread_worker_non_oc);
	}

#if DISPATCH_COCOA_COMPAT
	_dispatch_last_resort_autorelease_pool_pop(&dic);
#endif // DISPATCH_COCOA_COMPAT
	_dispatch_reset_wlh();
	_dispatch_reset_basepri(old_dbp);
	_dispatch_reset_basepri_override();
	_dispatch_queue_set_current(NULL);
}

#pragma mark -
#pragma mark dispatch_worker_thread

#if HAVE_PTHREAD_WORKQUEUES
static void
_dispatch_worker_thread4(void *context)
{
	dispatch_queue_t dq = context;
	dispatch_root_queue_context_t qc = dq->do_ctxt;

	_dispatch_introspection_thread_add();
	int pending = os_atomic_dec2o(qc, dgq_pending, relaxed);
	dispatch_assert(pending >= 0);
	_dispatch_root_queue_drain(dq, _dispatch_get_priority());
	_dispatch_voucher_debug("root queue clear", NULL);
	_dispatch_reset_voucher(NULL, DISPATCH_THREAD_PARK);
}

#if HAVE_PTHREAD_WORKQUEUE_QOS
static void
_dispatch_worker_thread3(pthread_priority_t pp)
{
	bool overcommit = pp & _PTHREAD_PRIORITY_OVERCOMMIT_FLAG;
	dispatch_queue_t dq;
	pp &= _PTHREAD_PRIORITY_OVERCOMMIT_FLAG | ~_PTHREAD_PRIORITY_FLAGS_MASK;
	_dispatch_thread_setspecific(dispatch_priority_key, (void *)(uintptr_t)pp);
	dq = _dispatch_get_root_queue(_dispatch_qos_from_pp(pp), overcommit);
	return _dispatch_worker_thread4(dq);
}
#endif // HAVE_PTHREAD_WORKQUEUE_QOS

#if DISPATCH_USE_PTHREAD_WORKQUEUE_SETDISPATCH_NP
// 6618342 Contact the team that owns the Instrument DTrace probe before
//         renaming this symbol
static void
_dispatch_worker_thread2(int priority, int options,
		void *context DISPATCH_UNUSED)
{
	dispatch_assert(priority >= 0 && priority < WORKQ_NUM_PRIOQUEUE);
	dispatch_assert(!(options & ~WORKQ_ADDTHREADS_OPTION_OVERCOMMIT));
	dispatch_queue_t dq = _dispatch_wq2root_queues[priority][options];

	return _dispatch_worker_thread4(dq);
}
#endif // DISPATCH_USE_PTHREAD_WORKQUEUE_SETDISPATCH_NP
#endif // HAVE_PTHREAD_WORKQUEUES

#if DISPATCH_USE_PTHREAD_POOL
// 6618342 Contact the team that owns the Instrument DTrace probe before
//         renaming this symbol
#if defined(_WIN32)
static unsigned WINAPI
_dispatch_worker_thread_thunk(LPVOID lpParameter)
{
  _dispatch_worker_thread(lpParameter);
  return 0;
}
#endif

static void *
_dispatch_worker_thread(void *context)
{
	dispatch_queue_t dq = context;
	dispatch_root_queue_context_t qc = dq->do_ctxt;
	dispatch_pthread_root_queue_context_t pqc = qc->dgq_ctxt;

	int pending = os_atomic_dec2o(qc, dgq_pending, relaxed);
	if (unlikely(pending < 0)) {
		DISPATCH_INTERNAL_CRASH(pending, "Pending thread request underflow");
	}

	if (pqc->dpq_observer_hooks.queue_will_execute) {
		_dispatch_set_pthread_root_queue_observer_hooks(
				&pqc->dpq_observer_hooks);
	}
	if (pqc->dpq_thread_configure) {
		pqc->dpq_thread_configure();
	}

	// workaround tweaks the kernel workqueue does for us
#if !defined(_WIN32)
	_dispatch_sigmask();
#endif
	_dispatch_introspection_thread_add();

#if DISPATCH_USE_INTERNAL_WORKQUEUE
	bool overcommit = (qc->dgq_wq_options & WORKQ_ADDTHREADS_OPTION_OVERCOMMIT);
	bool manager = (dq == &_dispatch_mgr_root_queue);
	bool monitored = !(overcommit || manager);
	if (monitored) {
		_dispatch_workq_worker_register(dq, qc->dgq_qos);
	}
#endif

	const int64_t timeout = 5ull * NSEC_PER_SEC;
	pthread_priority_t old_pri = _dispatch_get_priority();
	do {
		_dispatch_root_queue_drain(dq, old_pri);
		_dispatch_reset_priority_and_voucher(old_pri, NULL);
	} while (dispatch_semaphore_wait(&pqc->dpq_thread_mediator,
			dispatch_time(0, timeout)) == 0);

#if DISPATCH_USE_INTERNAL_WORKQUEUE
	if (monitored) {
		_dispatch_workq_worker_unregister(dq, qc->dgq_qos);
	}
#endif
	(void)os_atomic_inc2o(qc, dgq_thread_pool_size, release);
	_dispatch_global_queue_poke(dq, 1, 0);
	_dispatch_release(dq); // retained in _dispatch_global_queue_poke_slow
	return NULL;
}
#endif // DISPATCH_USE_PTHREAD_POOL

#pragma mark -
#pragma mark dispatch_network_root_queue
#if TARGET_OS_MAC

dispatch_queue_t
_dispatch_network_root_queue_create_4NW(const char *label,
		const pthread_attr_t *attrs, dispatch_block_t configure)
{
	unsigned long flags = dispatch_pthread_root_queue_flags_pool_size(1);
	return dispatch_pthread_root_queue_create(label, flags, attrs, configure);
}

#endif // TARGET_OS_MAC
#pragma mark -
#pragma mark dispatch_runloop_queue

static bool _dispatch_program_is_probably_callback_driven;

#if DISPATCH_COCOA_COMPAT

dispatch_queue_t
_dispatch_runloop_root_queue_create_4CF(const char *label, unsigned long flags)
{
	dispatch_queue_t dq;
	size_t dqs;

	if (slowpath(flags)) {
		return DISPATCH_BAD_INPUT;
	}
	dqs = sizeof(struct dispatch_queue_s) - DISPATCH_QUEUE_CACHELINE_PAD;
	dq = _dispatch_object_alloc(DISPATCH_VTABLE(queue_runloop), dqs);
	_dispatch_queue_init(dq, DQF_THREAD_BOUND | DQF_CANNOT_TRYSYNC, 1,
			DISPATCH_QUEUE_ROLE_BASE_ANON);
	dq->do_targetq = _dispatch_get_root_queue(DISPATCH_QOS_DEFAULT, true);
	dq->dq_label = label ? label : "runloop-queue"; // no-copy contract
	_dispatch_runloop_queue_handle_init(dq);
	_dispatch_queue_set_bound_thread(dq);
	_dispatch_object_debug(dq, "%s", __func__);
	return _dispatch_introspection_queue_create(dq);
}

void
_dispatch_runloop_queue_xref_dispose(dispatch_queue_t dq)
{
	_dispatch_object_debug(dq, "%s", __func__);

	dispatch_qos_t qos = _dispatch_runloop_queue_reset_max_qos(dq);
	_dispatch_queue_clear_bound_thread(dq);
	dx_wakeup(dq, qos, DISPATCH_WAKEUP_MAKE_DIRTY);
	if (qos) _dispatch_thread_override_end(DISPATCH_QUEUE_DRAIN_OWNER(dq), dq);
}

void
_dispatch_runloop_queue_dispose(dispatch_queue_t dq, bool *allow_free)
{
	_dispatch_object_debug(dq, "%s", __func__);
	_dispatch_introspection_queue_dispose(dq);
	_dispatch_runloop_queue_handle_dispose(dq);
	_dispatch_queue_destroy(dq, allow_free);
}

bool
_dispatch_runloop_root_queue_perform_4CF(dispatch_queue_t dq)
{
	if (slowpath(dq->do_vtable != DISPATCH_VTABLE(queue_runloop))) {
		DISPATCH_CLIENT_CRASH(dq->do_vtable, "Not a runloop queue");
	}
	dispatch_retain(dq);
	bool r = _dispatch_runloop_queue_drain_one(dq);
	dispatch_release(dq);
	return r;
}

void
_dispatch_runloop_root_queue_wakeup_4CF(dispatch_queue_t dq)
{
	if (slowpath(dq->do_vtable != DISPATCH_VTABLE(queue_runloop))) {
		DISPATCH_CLIENT_CRASH(dq->do_vtable, "Not a runloop queue");
	}
	_dispatch_runloop_queue_wakeup(dq, 0, false);
}

#if TARGET_OS_MAC
dispatch_runloop_handle_t
_dispatch_runloop_root_queue_get_port_4CF(dispatch_queue_t dq)
{
	if (slowpath(dq->do_vtable != DISPATCH_VTABLE(queue_runloop))) {
		DISPATCH_CLIENT_CRASH(dq->do_vtable, "Not a runloop queue");
	}
	return _dispatch_runloop_queue_get_handle(dq);
}
#endif

static void
_dispatch_runloop_queue_handle_init(void *ctxt)
{
	dispatch_queue_t dq = (dispatch_queue_t)ctxt;
	dispatch_runloop_handle_t handle;

	_dispatch_fork_becomes_unsafe();

#if TARGET_OS_MAC
	mach_port_t mp;
	kern_return_t kr;
	kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &mp);
	DISPATCH_VERIFY_MIG(kr);
	(void)dispatch_assume_zero(kr);
	kr = mach_port_insert_right(mach_task_self(), mp, mp,
			MACH_MSG_TYPE_MAKE_SEND);
	DISPATCH_VERIFY_MIG(kr);
	(void)dispatch_assume_zero(kr);
	if (dq != &_dispatch_main_q) {
		struct mach_port_limits limits = {
			.mpl_qlimit = 1,
		};
		kr = mach_port_set_attributes(mach_task_self(), mp,
				MACH_PORT_LIMITS_INFO, (mach_port_info_t)&limits,
				sizeof(limits));
		DISPATCH_VERIFY_MIG(kr);
		(void)dispatch_assume_zero(kr);
	}
	handle = mp;
#elif defined(__linux__)
	int fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	if (fd == -1) {
		int err = errno;
		switch (err) {
		case EMFILE:
			DISPATCH_CLIENT_CRASH(err, "eventfd() failure: "
					"process is out of file descriptors");
			break;
		case ENFILE:
			DISPATCH_CLIENT_CRASH(err, "eventfd() failure: "
					"system is out of file descriptors");
			break;
		case ENOMEM:
			DISPATCH_CLIENT_CRASH(err, "eventfd() failure: "
					"kernel is out of memory");
			break;
		default:
			DISPATCH_INTERNAL_CRASH(err, "eventfd() failure");
			break;
		}
	}
	handle = fd;
#else
#error "runloop support not implemented on this platform"
#endif
	_dispatch_runloop_queue_set_handle(dq, handle);

	_dispatch_program_is_probably_callback_driven = true;
}

static void
_dispatch_runloop_queue_handle_dispose(dispatch_queue_t dq)
{
	dispatch_runloop_handle_t handle = _dispatch_runloop_queue_get_handle(dq);
	if (!_dispatch_runloop_handle_is_valid(handle)) {
		return;
	}
	dq->do_ctxt = NULL;
#if TARGET_OS_MAC
	mach_port_t mp = handle;
	kern_return_t kr = mach_port_deallocate(mach_task_self(), mp);
	DISPATCH_VERIFY_MIG(kr);
	(void)dispatch_assume_zero(kr);
	kr = mach_port_mod_refs(mach_task_self(), mp, MACH_PORT_RIGHT_RECEIVE, -1);
	DISPATCH_VERIFY_MIG(kr);
	(void)dispatch_assume_zero(kr);
#elif defined(__linux__)
	int rc = close(handle);
	(void)dispatch_assume_zero(rc);
#else
#error "runloop support not implemented on this platform"
#endif
}

#pragma mark -
#pragma mark dispatch_main_queue

dispatch_runloop_handle_t
_dispatch_get_main_queue_handle_4CF(void)
{
	dispatch_queue_t dq = &_dispatch_main_q;
	dispatch_once_f(&_dispatch_main_q_handle_pred, dq,
			_dispatch_runloop_queue_handle_init);
	return _dispatch_runloop_queue_get_handle(dq);
}

#if TARGET_OS_MAC
dispatch_runloop_handle_t
_dispatch_get_main_queue_port_4CF(void)
{
	return _dispatch_get_main_queue_handle_4CF();
}
#endif

static bool main_q_is_draining;

// 6618342 Contact the team that owns the Instrument DTrace probe before
//         renaming this symbol
DISPATCH_NOINLINE
static void
_dispatch_queue_set_mainq_drain_state(bool arg)
{
	main_q_is_draining = arg;
}

void
_dispatch_main_queue_callback_4CF(
		void *ignored DISPATCH_UNUSED)
{
	if (main_q_is_draining) {
		return;
	}
	_dispatch_queue_set_mainq_drain_state(true);
	_dispatch_main_queue_drain();
	_dispatch_queue_set_mainq_drain_state(false);
}

#endif

void
dispatch_main(void)
{
	_dispatch_root_queues_init();
#if HAVE_PTHREAD_MAIN_NP
	if (pthread_main_np()) {
#endif
		_dispatch_object_debug(&_dispatch_main_q, "%s", __func__);
		_dispatch_program_is_probably_callback_driven = true;
		_dispatch_ktrace0(ARIADNE_ENTER_DISPATCH_MAIN_CODE);
#ifdef __linux__
		// On Linux, if the main thread calls pthread_exit, the process becomes a zombie.
		// To avoid that, just before calling pthread_exit we register a TSD destructor
		// that will call _dispatch_sig_thread -- thus capturing the main thread in sigsuspend.
		// This relies on an implementation detail (currently true in glibc) that TSD destructors
		// will be called in the order of creation to cause all the TSD cleanup functions to
		// run before the thread becomes trapped in sigsuspend.
		pthread_key_t dispatch_main_key;
		pthread_key_create(&dispatch_main_key, _dispatch_sig_thread);
		pthread_setspecific(dispatch_main_key, &dispatch_main_key);
		_dispatch_sigmask();
#endif
#if defined(_WIN32)
		_endthreadex(0);
#else
		pthread_exit(NULL);
#endif
		DISPATCH_INTERNAL_CRASH(errno, "pthread_exit() returned");
#if HAVE_PTHREAD_MAIN_NP
	}
	DISPATCH_CLIENT_CRASH(0, "dispatch_main() must be called on the main thread");
#endif
}

#if !defined(_WIN32)
DISPATCH_NOINLINE DISPATCH_NORETURN
static void
_dispatch_sigsuspend(void)
{
	static const sigset_t mask;

	for (;;) {
		sigsuspend(&mask);
	}
}
#endif

DISPATCH_NORETURN
static void
_dispatch_sig_thread(void *ctxt DISPATCH_UNUSED)
{
	// never returns, so burn bridges behind us
	_dispatch_clear_stack(0);
#if !defined(_WIN32)
	_dispatch_sigsuspend();
#endif
}

DISPATCH_NOINLINE
static void
_dispatch_queue_cleanup2(void)
{
	dispatch_queue_t dq = &_dispatch_main_q;
	uint64_t old_state, new_state;

	// Turning the main queue from a runloop queue into an ordinary serial queue
	// is a 3 steps operation:
	// 1. finish taking the main queue lock the usual way
	// 2. clear the THREAD_BOUND flag
	// 3. do a handoff
	//
	// If an enqueuer executes concurrently, he may do the wakeup the runloop
	// way, because he still believes the queue to be thread-bound, but the
	// dirty bit will force this codepath to notice the enqueue, and the usual
	// lock transfer will do the proper wakeup.
	os_atomic_rmw_loop2o(dq, dq_state, old_state, new_state, acquire, {
		new_state = old_state & ~DISPATCH_QUEUE_DIRTY;
		new_state += DISPATCH_QUEUE_WIDTH_INTERVAL;
		new_state += DISPATCH_QUEUE_IN_BARRIER;
	});
	_dispatch_queue_atomic_flags_clear(dq, DQF_THREAD_BOUND|DQF_CANNOT_TRYSYNC);
	_dispatch_queue_barrier_complete(dq, 0, 0);

	// overload the "probably" variable to mean that dispatch_main() or
	// similar non-POSIX API was called
	// this has to run before the DISPATCH_COCOA_COMPAT below
	// See dispatch_main for call to _dispatch_sig_thread on linux.
#ifndef __linux__
	if (_dispatch_program_is_probably_callback_driven) {
		_dispatch_barrier_async_detached_f(_dispatch_get_root_queue(
				DISPATCH_QOS_DEFAULT, true), NULL, _dispatch_sig_thread);
		sleep(1); // workaround 6778970
	}
#endif

#if DISPATCH_COCOA_COMPAT
	dispatch_once_f(&_dispatch_main_q_handle_pred, dq,
			_dispatch_runloop_queue_handle_init);
	_dispatch_runloop_queue_handle_dispose(dq);
#endif
}

static void DISPATCH_TSD_DTOR_CC
_dispatch_queue_cleanup(void *ctxt)
{
	if (ctxt == &_dispatch_main_q) {
		return _dispatch_queue_cleanup2();
	}
	// POSIX defines that destructors are only called if 'ctxt' is non-null
	DISPATCH_INTERNAL_CRASH(ctxt,
			"Premature thread exit while a dispatch queue is running");
}

static void DISPATCH_TSD_DTOR_CC
_dispatch_wlh_cleanup(void *ctxt)
{
	// POSIX defines that destructors are only called if 'ctxt' is non-null
	dispatch_queue_t wlh;
	wlh = (dispatch_queue_t)((uintptr_t)ctxt & ~DISPATCH_WLH_STORAGE_REF);
	_dispatch_queue_release_storage(wlh);
}

DISPATCH_NORETURN
static void DISPATCH_TSD_DTOR_CC
_dispatch_deferred_items_cleanup(void *ctxt)
{
	// POSIX defines that destructors are only called if 'ctxt' is non-null
	DISPATCH_INTERNAL_CRASH(ctxt,
			"Premature thread exit with unhandled deferred items");
}

DISPATCH_NORETURN
static DISPATCH_TSD_DTOR_CC void
_dispatch_frame_cleanup(void *ctxt)
{
	// POSIX defines that destructors are only called if 'ctxt' is non-null
	DISPATCH_INTERNAL_CRASH(ctxt,
			"Premature thread exit while a dispatch frame is active");
}

DISPATCH_NORETURN
static void DISPATCH_TSD_DTOR_CC
_dispatch_context_cleanup(void *ctxt)
{
	// POSIX defines that destructors are only called if 'ctxt' is non-null
	DISPATCH_INTERNAL_CRASH(ctxt,
			"Premature thread exit while a dispatch context is set");
}
