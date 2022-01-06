// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_RUNTIME_MUMBA_SHIMS_ORE_SHIMS_H_
#define MUMBA_RUNTIME_MUMBA_SHIMS_ORE_SHIMS_H_

#include "Globals.h"

// Runtime
EXPORT int _RuntimeInit();
EXPORT int _SandboxEnter(void);
EXPORT void _RuntimeMainLoopRun();
EXPORT void _RuntimeShutdown();

EXPORT char* Base64UrlDecode(const char* input, int len, int* out_len);

#endif
