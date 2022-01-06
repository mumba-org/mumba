// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_KIT_LIBEVENT_SHIMS_H_
#define MUMBA_KIT_LIBEVENT_SHIMS_H_

#include "globals.h"
//#include <stdint.h>

typedef void* CEvent;
typedef void* CEventBase;
typedef void (*CEventSetCallback)(int, short, void *);

const int EV_TIMEOUT = 0x01;
const int EV_READ = 0x02;
const int EV_WRITE = 0x04;
const int EV_SIGNAL = 0x08;
const int EV_PERSIST = 0x10;

const int EVLOOP_ONCE	= 0x01;	/**< Block at most once. */
const int EVLOOP_NONBLOCK =	0x02;

EXPORT CEventBase _LibeventInit();
EXPORT void _LibeventDispatch();
EXPORT CEventBase _LibeventEventBaseAlloc();
EXPORT void _LibeventEventBaseDestroy(CEventBase event_base);
EXPORT int _LibeventEventBaseDispatch(CEventBase event_base);
EXPORT int _LibeventEventBaseLoop(CEventBase event_base, int flags);
EXPORT int _LibeventEventBaseSet(CEventBase event_base, CEvent event);
EXPORT void _LibeventEventBaseLoopbreak(CEventBase event_base);

EXPORT CEvent  _LibeventEventAlloc(); 
EXPORT void _LibeventEventDestroy(CEvent event);
EXPORT int _LibeventEventAdd(CEvent event);
EXPORT int _LibeventEventAddWithTimeout(CEvent event, long long sec, long long usec);///int64_t sec, int64_t usec);
EXPORT void _LibeventEventSet(CEvent event, int fd, short flags, CEventSetCallback cb, void* ptr);
EXPORT int _LibeventEventDel(CEvent event);
EXPORT int _LibeventEventGetFD(CEvent event);
EXPORT int _LibeventEventGetEvents(CEvent event);

#endif
