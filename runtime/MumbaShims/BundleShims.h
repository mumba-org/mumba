// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_RUNTIME_MUMBA_SHIMS_BUNDLE_SHIMS_H_
#define MUMBA_RUNTIME_MUMBA_SHIMS_BUNDLE_SHIMS_H_

#include "Globals.h"

typedef void* ImageRef;

//EXPORT void _ResourceBundleInitInstance();
//EXPORT ResourceBundleRef _ResourceBundleGetInstance();
EXPORT int _ResourceBundleAddDataPackFromPath(const char* relative_path, int scale_factor);
EXPORT ImageRef _ResourceBundleGetImageSkiaNamed(int resource_id);
EXPORT int _ResourceBundleLoadDataResourceBytes(int resource_id, const uint8_t** bytes, size_t* bytes_size);
EXPORT int _ResourceBundleLoadDataResourceBytesForScale(int resource_id, int scale_factor, const uint8_t** bytes, size_t* bytes_size);
EXPORT int _ResourceBundleGetRawDataResource(int message_id, const uint8_t** bytes, size_t* bytes_size);
EXPORT int _ResourceBundleGetRawDataResourceForScale(int message_id, int scale_factor, const uint8_t** bytes, size_t* bytes_size);

#endif
