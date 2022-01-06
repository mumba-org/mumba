// Copyright (c) 2014 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/common/constants.h"
#include "base/files/file_path.h"

#define FPL FILE_PATH_LITERAL

namespace constants {


#if defined(OS_WIN)
const base::FilePath::CharType kHostProcessExecutableName[] = FPL("mumba.exe");
#elif defined(OS_POSIX)
const base::FilePath::CharType kHostProcessExecutableName[] = FPL("mumba");
#endif

const base::FilePath::CharType kLocalStorePoolName[] = FPL("local_store_pool");
const base::FilePath::CharType kSingletonCookieFilename[] = FPL("singleton_cookie");
const base::FilePath::CharType kSingletonSocketFilename[] = FPL("singleton_socket");
const base::FilePath::CharType kSingletonLockFilename[] = FPL("singleton_lock");
const base::FilePath::CharType kPreferencesFilename[] = FPL("prefs");
//const base::FilePath::CharType kSelfScheme[] = "self://";
const base::FilePath::CharType kDefaultWorkspaceName[] = FPL("default");

const int kTraceEventGpuProcessSortIndex = -1;

#if defined(OS_WIN)
const base::FilePath::CharType kBrowserResourcesDll[] = FPL("mumba.dll");
// Only relevant if building with is_multi_dll_chrome=true.
//const base::FilePath::CharType kChildDll[] = FPL("chrome_child.dll");
const base::FilePath::CharType kElfDll[] = FPL("mumba_elf.dll");
const base::FilePath::CharType kStatusTrayWindowClass[] =
    FPL("Mumba_StatusTrayWindow");
#endif  // defined(OS_WIN)

}

