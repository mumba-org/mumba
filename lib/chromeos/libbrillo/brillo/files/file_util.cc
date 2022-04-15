// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "brillo/files/file_util.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <utility>

#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/stringprintf.h>
#include <brillo/syslog_logging.h>

namespace brillo {

namespace {

enum class FSObjectType {
  RegularFile = 0,
  Directory,
};

SafeFD::SafeFDResult OpenOrRemake(SafeFD* parent,
                                  const std::string& name,
                                  FSObjectType type,
                                  int permissions,
                                  uid_t uid,
                                  gid_t gid,
                                  int flags) {
  SafeFD::Error err = IsValidFilename(name);
  if (SafeFD::IsError(err)) {
    return std::make_pair(SafeFD(), err);
  }

  SafeFD::SafeFDResult (SafeFD::*maker)(const base::FilePath&, mode_t, uid_t,
                                        gid_t, int);
  if (type == FSObjectType::Directory) {
    maker = &SafeFD::MakeDir;
  } else {
    maker = &SafeFD::MakeFile;
  }

  SafeFD child;
  std::tie(child, err) =
      (parent->*maker)(base::FilePath(name), permissions, uid, gid, flags);
  if (child.is_valid()) {
    return std::make_pair(std::move(child), err);
  }

  // Rmdir should be used on directories. However, kWrongType indicates when
  // a directory was expected and a non-directory was found or when a
  // directory was found but not expected, so XOR was used.
  if ((type == FSObjectType::Directory) ^ (err == SafeFD::Error::kWrongType)) {
    err = parent->Rmdir(name, true /*recursive*/);
  } else {
    err = parent->Unlink(name);
  }
  if (SafeFD::IsError(err)) {
    PLOG(ERROR) << "Failed to clean up \"" << name << "\"";
    return std::make_pair(SafeFD(), err);
  }

  std::tie(child, err) =
      (parent->*maker)(base::FilePath(name), permissions, uid, gid, flags);
  return std::make_pair(std::move(child), err);
}

}  // namespace

SafeFD::Error IsValidFilename(const std::string& filename) {
  if (filename == "." || filename == ".." ||
      filename.find("/") != std::string::npos) {
    return SafeFD::Error::kBadArgument;
  }
  return SafeFD::Error::kNoError;
}

base::FilePath GetFDPath(int fd) {
  const base::FilePath proc_fd(base::StringPrintf("/proc/self/fd/%d", fd));
  base::FilePath resolved;
  if (!base::ReadSymbolicLink(proc_fd, &resolved)) {
    LOG(ERROR) << "Failed to read " << proc_fd.value();
    return base::FilePath();
  }
  return resolved;
}

SafeFD::SafeFDResult OpenOrRemakeDir(SafeFD* parent,
                                     const std::string& name,
                                     int permissions,
                                     uid_t uid,
                                     gid_t gid,
                                     int flags) {
  return OpenOrRemake(parent, name, FSObjectType::Directory, permissions, uid,
                      gid, flags);
}

SafeFD::SafeFDResult OpenOrRemakeFile(SafeFD* parent,
                                      const std::string& name,
                                      int permissions,
                                      uid_t uid,
                                      gid_t gid,
                                      int flags) {
  return OpenOrRemake(parent, name, FSObjectType::RegularFile, permissions, uid,
                      gid, flags);
}

}  // namespace brillo
