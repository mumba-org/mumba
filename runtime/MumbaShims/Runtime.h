// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_RUNTIME_MUMBA_SHIMS_RUNTIME_H_
#define MUMBA_RUNTIME_MUMBA_SHIMS_RUNTIME_H_

#include "Globals.h"
#include "base/macros.h"

class WebPlatform;
struct RuntimeGlobals;

class Runtime {
public:
  static bool Init();
  // should be a temporary hack
  static void RunMainLoop();
  static void Shutdown();
  
private:
 Runtime();
 ~Runtime();
 
 #if defined(USE_TCMALLOC)
 static bool GetAllocatorWasteSizeThunk(size_t* size);
 static void GetStatsThunk(char* buffer, int buffer_length);
 static void ReleaseFreeMemoryThunk();
#endif
 
 DISALLOW_COPY_AND_ASSIGN(Runtime);  
};

extern WebPlatform* g_webplatform;
extern RuntimeGlobals* g_runtime;

#endif