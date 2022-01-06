// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_LIB_STORAGE_STORAGE_CONSTANTS_H_
#define MUMBA_LIB_STORAGE_STORAGE_CONSTANTS_H_

#include <string>

#include "base/macros.h"
#include "base/files/file_path.h"
#include "storage/proto/storage.pb.h"

namespace storage {

constexpr char kStorageStateFileName[] = "storage.state";

constexpr char kStorageFileHeaderMagic[] = "STORAGE";
constexpr int kStorageFileHeaderMagicSize = arraysize(kStorageFileHeaderMagic);
constexpr int kStorageFileHeaderVersion = 1;

constexpr char kStorageFileExtension[] = "storage";
#if defined (OS_WIN)
constexpr wchar_t kStorageFileExtensionWithDot[] = L".storage";
#else
constexpr char kStorageFileExtensionWithDot[] = ".storage";
#endif
constexpr char kApplicationFileHeaderKey[] = "HEADER";

constexpr char kMetadataDir[] = ".storage";

}

#endif
