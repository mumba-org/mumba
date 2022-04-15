// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Filesystem-related utility functions.

#ifndef LIBBRILLO_BRILLO_FILES_FILE_UTIL_H_
#define LIBBRILLO_BRILLO_FILES_FILE_UTIL_H_

#include <string>

#include <brillo/files/safe_fd.h>

namespace brillo {

SafeFD::Error IsValidFilename(const std::string& filename);

// Obtain the canonical path of the file descriptor or base::FilePath() on
// failure.
BRILLO_EXPORT base::FilePath GetFDPath(int fd);

// Open or create a child directory named |name| as a child of |parent| with
// the specified permissions and ownership. Custom open flags can be set with
// |flags|. The directory will be re-created if:
// * The open operation fails (e.g. if |name| is not a directory).
// * The permissions do not match.
// * The ownership is different.
//
// Parameters
//  parent - An open SafeFD to the parent directory.
//  name - the name of the directory being created. It cannot have more than one
//    path component.
BRILLO_EXPORT SafeFD::SafeFDResult OpenOrRemakeDir(
    SafeFD* parent,
    const std::string& name,
    int permissions = SafeFD::kDefaultDirPermissions,
    uid_t uid = getuid(),
    gid_t gid = getgid(),
    int flags = O_RDONLY | O_CLOEXEC);

// Open or create a file named |name| under the directory |parent| with
// the specified permissions and ownership. Custom open flags can be set with
// |flags|. The file will be re-created if:
// * The open operation fails (e.g. |name| is a directory).
// * The permissions do not match.
// * The ownership is different.
//
// Parameters
//  parent - An open SafeFD to the parent directory.
//  name - the name of the file being created. It cannot have more than one
//    path component.
BRILLO_EXPORT SafeFD::SafeFDResult OpenOrRemakeFile(
    SafeFD* parent,
    const std::string& name,
    int permissions = SafeFD::kDefaultFilePermissions,
    uid_t uid = getuid(),
    gid_t gid = getgid(),
    int flags = O_RDWR | O_CLOEXEC);

}  // namespace brillo

#endif  // LIBBRILLO_BRILLO_FILES_FILE_UTIL_H_
