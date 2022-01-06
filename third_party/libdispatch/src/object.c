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

#pragma mark -
#pragma mark _os_object_t

unsigned long
_os_object_retain_count(_os_object_t obj)
{
	int xref_cnt = obj->os_obj_xref_cnt;
	if (slowpath(xref_cnt == _OS_OBJECT_GLOBAL_REFCNT)) {
		return ULONG_MAX; // global object
	}
	return (unsigned long)(xref_cnt + 1);
}

DISPATCH_NOINLINE
_os_object_t
_os_object_retain_internal(_os_object_t obj)
{
	return _os_object_retain_internal_n_inline(obj, 1);
}

DISPATCH_NOINLINE
_os_object_t
_os_object_retain_internal_n(_os_object_t obj, uint16_t n)
{
	return _os_object_retain_internal_n_inline(obj, n);
}

DISPATCH_NOINLINE
void
_os_object_release_internal(_os_object_t obj)
{
	return _os_object_release_internal_n_inline(obj, 1);
}

DISPATCH_NOINLINE
void
_os_object_release_internal_n(_os_object_t obj, uint16_t n)
{
	return _os_object_release_internal_n_inline(obj, n);
}

DISPATCH_NOINLINE
_os_object_t
_os_object_retain(_os_object_t obj)
{
	int xref_cnt = _os_object_xrefcnt_inc(obj);
	if (slowpath(xref_cnt <= 0)) {
		_OS_OBJECT_CLIENT_CRASH("Resurrection of an object");
	}
	return obj;
}

DISPATCH_NOINLINE
_os_object_t
_os_object_retain_with_resurrect(_os_object_t obj)
{
	int xref_cnt = _os_object_xrefcnt_inc(obj);
	if (slowpath(xref_cnt < 0)) {
		_OS_OBJECT_CLIENT_CRASH("Resurrection of an over-released object");
	}
	if (slowpath(xref_cnt == 0)) {
		_os_object_retain_internal(obj);
	}
	return obj;
}

DISPATCH_NOINLINE
void
_os_object_release(_os_object_t obj)
{
	int xref_cnt = _os_object_xrefcnt_dec(obj);
	if (fastpath(xref_cnt >= 0)) {
		return;
	}
	if (slowpath(xref_cnt < -1)) {
		_OS_OBJECT_CLIENT_CRASH("Over-release of an object");
	}
	return _os_object_xref_dispose(obj);
}

bool
_os_object_retain_weak(_os_object_t obj)
{
	int xref_cnt, nxref_cnt;
	os_atomic_rmw_loop2o(obj, os_obj_xref_cnt, xref_cnt, nxref_cnt, relaxed, {
		if (slowpath(xref_cnt == _OS_OBJECT_GLOBAL_REFCNT)) {
			os_atomic_rmw_loop_give_up(return true); // global object
		}
		if (slowpath(xref_cnt == -1)) {
			os_atomic_rmw_loop_give_up(return false);
		}
		if (slowpath(xref_cnt < -1)) {
			os_atomic_rmw_loop_give_up(goto overrelease);
		}
		nxref_cnt = xref_cnt + 1;
	});
	return true;
overrelease:
	_OS_OBJECT_CLIENT_CRASH("Over-release of an object");
}

bool
_os_object_allows_weak_reference(_os_object_t obj)
{
	int xref_cnt = obj->os_obj_xref_cnt;
	if (slowpath(xref_cnt == -1)) {
		return false;
	}
	if (slowpath(xref_cnt < -1)) {
		_OS_OBJECT_CLIENT_CRASH("Over-release of an object");
	}
	return true;
}

#pragma mark -
#pragma mark dispatch_object_t

void *
_dispatch_object_alloc(const void *vtable, size_t size)
{
#if OS_OBJECT_HAVE_OBJC1
	const struct dispatch_object_vtable_s *_vtable = vtable;
	dispatch_object_t dou;
	dou._os_obj = _os_object_alloc_realized(_vtable->_os_obj_objc_isa, size);
	dou._do->do_vtable = vtable;
	return dou._do;
#else
	return _os_object_alloc_realized(vtable, size);
#endif
}

void
_dispatch_object_finalize(dispatch_object_t dou)
{
#if USE_OBJC
	objc_destructInstance((id)dou._do);
#else
	(void)dou;
#endif
}

void
_dispatch_object_dealloc(dispatch_object_t dou)
{
	// so that ddt doesn't pick up bad objects when malloc reuses this memory
	dou._os_obj->os_obj_isa = NULL;
#if OS_OBJECT_HAVE_OBJC1
	dou._do->do_vtable = NULL;
#endif
	free(dou._os_obj);
}

void
dispatch_retain(dispatch_object_t dou)
{
	DISPATCH_OBJECT_TFB(_dispatch_objc_retain, dou);
	(void)_os_object_retain(dou._os_obj);
}

void
dispatch_release(dispatch_object_t dou)
{
	DISPATCH_OBJECT_TFB(_dispatch_objc_release, dou);
	_os_object_release(dou._os_obj);
}

#if !USE_OBJC
void
_dispatch_xref_dispose(dispatch_object_t dou)
{
	unsigned long metatype = dx_metatype(dou._do);
	if (metatype == _DISPATCH_QUEUE_TYPE || metatype == _DISPATCH_SOURCE_TYPE) {
		_dispatch_queue_xref_dispose(dou._dq);
	}
	if (dx_type(dou._do) == DISPATCH_SOURCE_KEVENT_TYPE) {
		_dispatch_source_xref_dispose(dou._ds);
#if HAVE_MACH
	} else if (dx_type(dou._do) == DISPATCH_MACH_CHANNEL_TYPE) {
		_dispatch_mach_xref_dispose(dou._dm);
#endif
	} else if (dx_type(dou._do) == DISPATCH_QUEUE_RUNLOOP_TYPE) {
		_dispatch_runloop_queue_xref_dispose(dou._dq);
	}
	return _dispatch_release_tailcall(dou._os_obj);
}
#endif

void
_dispatch_dispose(dispatch_object_t dou)
{
	dispatch_queue_t tq = dou._do->do_targetq;
	dispatch_function_t func = dou._do->do_finalizer;
	void *ctxt = dou._do->do_ctxt;
	bool allow_free = true;

	if (slowpath(dou._do->do_next != DISPATCH_OBJECT_LISTLESS)) {
		DISPATCH_INTERNAL_CRASH(dou._do->do_next, "Release while enqueued");
	}

	dx_dispose(dou._do, &allow_free);

	// Past this point, the only thing left of the object is its memory
	if (likely(allow_free)) {
		_dispatch_object_finalize(dou);
		_dispatch_object_dealloc(dou);
	}
	if (func && ctxt) {
		dispatch_async_f(tq, ctxt, func);
	}
	if (tq) _dispatch_release_tailcall(tq);
}

void *
dispatch_get_context(dispatch_object_t dou)
{
	DISPATCH_OBJECT_TFB(_dispatch_objc_get_context, dou);
	if (unlikely(dou._do->do_ref_cnt == DISPATCH_OBJECT_GLOBAL_REFCNT ||
			dx_hastypeflag(dou._do, QUEUE_ROOT) ||
			dx_hastypeflag(dou._do, QUEUE_BASE))) {
		return NULL;
	}
	return dou._do->do_ctxt;
}

void
dispatch_set_context(dispatch_object_t dou, void *context)
{
	DISPATCH_OBJECT_TFB(_dispatch_objc_set_context, dou, context);
	if (unlikely(dou._do->do_ref_cnt == DISPATCH_OBJECT_GLOBAL_REFCNT ||
			dx_hastypeflag(dou._do, QUEUE_ROOT) ||
			dx_hastypeflag(dou._do, QUEUE_BASE))) {
		return;
	}
	dou._do->do_ctxt = context;
}

void
dispatch_set_finalizer_f(dispatch_object_t dou, dispatch_function_t finalizer)
{
	DISPATCH_OBJECT_TFB(_dispatch_objc_set_finalizer_f, dou, finalizer);
	if (unlikely(dou._do->do_ref_cnt == DISPATCH_OBJECT_GLOBAL_REFCNT ||
			dx_hastypeflag(dou._do, QUEUE_ROOT) ||
			dx_hastypeflag(dou._do, QUEUE_BASE))) {
		return;
	}
	dou._do->do_finalizer = finalizer;
}

void
dispatch_set_target_queue(dispatch_object_t dou, dispatch_queue_t tq)
{
	DISPATCH_OBJECT_TFB(_dispatch_objc_set_target_queue, dou, tq);
	if (dx_vtable(dou._do)->do_set_targetq) {
		dx_vtable(dou._do)->do_set_targetq(dou._do, tq);
	} else if (likely(dou._do->do_ref_cnt != DISPATCH_OBJECT_GLOBAL_REFCNT &&
			!dx_hastypeflag(dou._do, QUEUE_ROOT) &&
			!dx_hastypeflag(dou._do, QUEUE_BASE))) {
		if (slowpath(!tq)) {
			tq = _dispatch_get_root_queue(DISPATCH_QOS_DEFAULT, false);
		}
		_dispatch_object_set_target_queue_inline(dou._do, tq);
	}
}

void
dispatch_activate(dispatch_object_t dou)
{
	DISPATCH_OBJECT_TFB(_dispatch_objc_activate, dou);
	if (dx_vtable(dou._do)->do_resume) {
		dx_vtable(dou._do)->do_resume(dou._do, true);
	}
}

void
dispatch_suspend(dispatch_object_t dou)
{
	DISPATCH_OBJECT_TFB(_dispatch_objc_suspend, dou);
	if (dx_vtable(dou._do)->do_suspend) {
		dx_vtable(dou._do)->do_suspend(dou._do);
	}
}

void
dispatch_resume(dispatch_object_t dou)
{
	DISPATCH_OBJECT_TFB(_dispatch_objc_resume, dou);
	// the do_suspend below is not a typo. Having a do_resume but no do_suspend
	// allows for objects to support activate, but have no-ops suspend/resume
	if (dx_vtable(dou._do)->do_suspend) {
		dx_vtable(dou._do)->do_resume(dou._do, false);
	}
}

size_t
_dispatch_object_debug_attr(dispatch_object_t dou, char* buf, size_t bufsiz)
{
	return dsnprintf(buf, bufsiz, "xref = %d, ref = %d, ",
			dou._do->do_xref_cnt + 1, dou._do->do_ref_cnt + 1);
}
