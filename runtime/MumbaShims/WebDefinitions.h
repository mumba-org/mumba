// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_RUNTIME_MUMBA_SHIMS_WEB_DEFINITIONS_H_
#define MUMBA_RUNTIME_MUMBA_SHIMS_WEB_DEFINITIONS_H_

typedef struct {
 void(*OnInit)(void*, void*);
 void(*OnTerminate)(void*);
 void(*OnMessage)(void*, void*, void**, int, void**, int);
} WorkerNativeClientCallbacks;

typedef struct {
  void* (*GetWorkerNativeClientState)(void*);
  WorkerNativeClientCallbacks (*GetWorkerNativeClientCallbacks)(void*);
} ServiceWorkerContextClientCallbacks;

#endif
