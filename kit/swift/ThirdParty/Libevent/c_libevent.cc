// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libevent.h"

#include <stdlib.h>

#include "base/third_party/libevent/event.h"

CEventBase _LibeventInit() {
  return event_init();
}

void _LibeventDispatch() {
  event_dispatch();
}

CEventBase _LibeventEventBaseAlloc() {
  return event_base_new();
}

void _LibeventEventBaseDestroy(CEventBase event_base) {
  event_base_free((struct event_base *)event_base);
}

int _LibeventEventBaseDispatch(CEventBase event_base) {
  return event_base_dispatch((struct event_base *)event_base);
}

int _LibeventEventBaseLoop(CEventBase event_base, int flags) {
  return event_base_loop((struct event_base *)event_base, flags);
}

int _LibeventEventBaseSet(CEventBase event_base, CEvent event) {
  return event_base_set((struct event_base *)event_base, (struct event *)event);
}

void _LibeventEventBaseLoopbreak(CEventBase event_base) {
  event_base_loopbreak((struct event_base *)event_base);
}

CEvent _LibeventEventAlloc() {
  return malloc(sizeof(struct event));
}

void _LibeventEventDestroy(CEvent event) {
  free((struct event *)event);
}

int _LibeventEventAdd(CEvent event) {
  return event_add((struct event *) event, NULL);
}

int _LibeventEventAddWithTimeout(CEvent event, long long sec, long long usec) {
  struct timeval poll_tv;
  poll_tv.tv_sec = sec;
  poll_tv.tv_usec = usec;
  return event_add((struct event *) event, &poll_tv);
}

void _LibeventEventSet(CEvent event, int fd, short flags, CEventSetCallback cb, void* ptr) {
  event_set((struct event *) event, fd, flags, cb, ptr);
}

int _LibeventEventDel(CEvent event) {
  return event_del((struct event *)event);
}

int _LibeventEventGetFD(CEvent event) {
  return EVENT_FD((struct event *)event);
}

int _LibeventEventGetEvents(CEvent event) {
  return ((struct event *)event)->ev_events;
}