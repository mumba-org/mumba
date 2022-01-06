// Copyright (c) 2014 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef COMMON_CONSTANTS_H_
#define COMMON_CONSTANTS_H_

#include "base/files/file_path.h"
#include "core/shared/common/content_export.h"

namespace constants {

CONTENT_EXPORT extern const base::FilePath::CharType kLocalStorePoolName[];
CONTENT_EXPORT extern const base::FilePath::CharType kHostProcessExecutableName[];
CONTENT_EXPORT extern const base::FilePath::CharType kSingletonCookieFilename[];
CONTENT_EXPORT extern const base::FilePath::CharType kSingletonSocketFilename[];
CONTENT_EXPORT extern const base::FilePath::CharType kSingletonLockFilename[];
CONTENT_EXPORT extern const base::FilePath::CharType kPreferencesFilename[];
//extern const base::FilePath::CharType kSelfScheme[];
CONTENT_EXPORT extern const base::FilePath::CharType kDefaultWorkspaceName[];

CONTENT_EXPORT extern const int kTraceEventGpuProcessSortIndex;

#if defined(OS_WIN)
extern const base::FilePath::CharType kBrowserResourcesDll[];
//extern const base::FilePath::CharType kChildDll[];
extern const base::FilePath::CharType kElfDll[];
extern const base::FilePath::CharType kStatusTrayWindowClass[];
#endif  // defined(OS_WIN)

}

#endif
