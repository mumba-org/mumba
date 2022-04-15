// Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBBRILLO_BRILLO_CRYPTOHOME_H_
#define LIBBRILLO_BRILLO_CRYPTOHOME_H_

#include <string>

#include <base/files/file_path.h>
#include <brillo/brillo_export.h>
#include <brillo/secure_blob.h>

namespace brillo {
namespace cryptohome {
namespace home {

BRILLO_EXPORT extern const char kGuestUserName[];

// Returns the common prefix under which the mount points for user homes are
// created.
BRILLO_EXPORT base::FilePath GetUserPathPrefix();

// Returns the common prefix under which the mount points for root homes are
// created.
BRILLO_EXPORT base::FilePath GetRootPathPrefix();

// Returns the path at which the user home for |username| will be mounted.
// Returns "" for failures.
BRILLO_EXPORT base::FilePath GetUserPath(const std::string& username);

// Returns the path at which the user home for |hashed_username| will be
// mounted. Useful when you already have the username hashed.
// Returns "" for failures.
BRILLO_EXPORT base::FilePath GetHashedUserPath(
    const std::string& hashed_username);

// Returns the path at which the root home for |username| will be mounted.
// Returns "" for failures.
BRILLO_EXPORT base::FilePath GetRootPath(const std::string& username);

// Returns the path at which the daemon |daemon| should store per-user data.
// This function returns '/run/daemon-stores/<daemon-name>/<hash>' which is
// the preferred place to store per-user data.
// See https://chromium.googlesource.com/chromiumos/docs/+/HEAD/sandboxing.md
// for more details.
BRILLO_EXPORT base::FilePath GetDaemonStorePath(const std::string& username,
                                                const std::string& daemon);

// Returns the path at which the daemon |daemon| should store per-user data
// when the user's home was mounted with mount_hidden.
BRILLO_EXPORT base::FilePath GetDaemonPathForHiddenUserHome(
    const std::string& username, const std::string& daemon);

// Checks whether |sanitized| has the format of a sanitized username.
BRILLO_EXPORT bool IsSanitizedUserName(const std::string& sanitized);

// Returns a sanitized form of |username|. For x != y, SanitizeUserName(x) !=
// SanitizeUserName(y).
BRILLO_EXPORT std::string SanitizeUserName(const std::string& username);

// Returns a sanitized form of |username| with the salt provided. For x != y,
// SanitizeUserName(x) != SanitizeUserName(y).
BRILLO_EXPORT std::string SanitizeUserNameWithSalt(const std::string& username,
                                                   const SecureBlob& salt);

// Overrides the common prefix under which the mount points for user homes are
// created. This is used for testing only.
BRILLO_EXPORT void SetUserHomePrefix(const std::string& prefix);

// Overrides the common prefix under which the mount points for root homes are
// created. This is used for testing only.
BRILLO_EXPORT void SetRootHomePrefix(const std::string& prefix);

// Overrides the contents of the system salt.
// salt should be non-NULL and non-empty when attempting to avoid filesystem
// usage in tests.
// Note:
// (1) Never mix usage with SetSystemSaltPath().
// (2) Ownership of the pointer stays with the caller.
BRILLO_EXPORT void SetSystemSalt(std::string* salt);

// Returns the system salt.
BRILLO_EXPORT std::string* GetSystemSalt();

// Ensures the system salt is loaded in the memory.
BRILLO_EXPORT bool EnsureSystemSaltIsLoaded();

}  // namespace home
}  // namespace cryptohome
}  // namespace brillo

#endif  // LIBBRILLO_BRILLO_CRYPTOHOME_H_
