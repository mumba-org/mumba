// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_RUNTIME_MUMBA_SHIMS_SQLITE_HELPER_H_
#define MUMBA_RUNTIME_MUMBA_SHIMS_SQLITE_HELPER_H_

#include "Globals.h"

EXPORT int csqlitePutVarint(unsigned char*, uint64_t);
EXPORT uint8_t csqliteGetVarint(const unsigned char *, uint64_t *);
EXPORT uint8_t csqliteGetVarint32(const unsigned char *, uint32_t *);
EXPORT int csqliteVarintLen(uint64_t v);

#endif
