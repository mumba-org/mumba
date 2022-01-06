// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_LIB_STORAGE_STORAGE_UTILS_H_
#define MUMBA_LIB_STORAGE_STORAGE_UTILS_H_

#include <string>

#include "base/macros.h"
#include "base/files/file_path.h"
#include "storage/proto/storage.pb.h"
#include "storage/storage_export.h"

namespace storage {

//bool IsStorageDir(storage_proto::StorageProfile disk_type, const base::FilePath& path);

std::string STORAGE_EXPORT GetIdentifierForArchitecture(storage_proto::ExecutableArchitecture arch);

base::FilePath STORAGE_EXPORT GetPathForArchitecture(const std::string& db_identifier, storage_proto::ExecutableArchitecture arch);

base::FilePath STORAGE_EXPORT GetPathForArchitecture(const std::string& db_identifier, storage_proto::ExecutableArchitecture arch, storage_proto::ExecutableFormat format);

base::FilePath STORAGE_EXPORT GetFilePathForArchitecture(const std::string& db_identifier, storage_proto::ExecutableArchitecture arch, storage_proto::ExecutableFormat format);

storage_proto::ExecutableArchitecture STORAGE_EXPORT GetHostArchitecture();

std::string STORAGE_EXPORT GetIdentifierForHostOS();

base::FilePath STORAGE_EXPORT GetPackPathFromInputDir(const base::FilePath& input_dir);

}

#endif
