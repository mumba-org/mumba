// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ARC_DATA_SNAPSHOTD_FILE_UTILS_H_
#define ARC_DATA_SNAPSHOTD_FILE_UTILS_H_

#include <string>
#include <vector>

#include <base/files/file_path.h>

#include "proto/directory.pb.h"

namespace crypto {

class RSAPrivateKey;

}  // namespace crypto

namespace arc {
namespace data_snapshotd {

// Extracts all files and file info for all files from |dir| and fills in
// |snapshot_directory| object, that should be non-nullptr.
// Set |inode_verification_enabled| to false only for testing to disable the
// inode integrity check for snapshot directories.
// Returns true in case of success and false in case of any error.
bool ReadSnapshotDirectory(const base::FilePath& dir,
                           SnapshotDirectory* snapshot_directory,
                           bool inode_verification_enabled = true);

// Calculates SHA256 hash for serialized |dir|.
// In case of any error returns empty hash.
std::vector<uint8_t> CalculateDirectoryCryptographicHash(
    const SnapshotDirectory& dir);

// Stores base64-encoded |encoded_public_key| on disk in |dir|/public_key_info
// file.
// |dir| is an existing directory, where a prospective snapshot signed with
// a corresponding private key will be stored.
// Returns false in case of any error.
bool StorePublicKey(const base::FilePath& dir,
                    const std::string& encoded_public_key);

// Stores |userhash| on disk in |dir|/userhash file.
// |dir| is an existing directory, where a prospective snapshot signed with
// a corresponding private key will be stored.
// Returns false in case of any error.
bool StoreUserhash(const base::FilePath& dir, const std::string& userhash);

// Calculates SHA256 hash for |dir| (excluding |dir|/hash file), signs it with
// |private_key| and stores in |dir|/hash file.
// Set |inode_verification_enabled| to false only for testing to disable the
// inode integrity check for snapshot directories.
// Returns false in case of any error.
bool SignAndStoreHash(const base::FilePath& dir,
                      crypto::RSAPrivateKey* private_key,
                      bool inode_verification_enabled);

// Verifies signed hash stored in a |dir|/hash file by public key stored in a
// |dir|/public_key_info.
// Verifies |expected_userhash| is equal to the userhash stored in
// |dir|/userhash.
// Verifies integrity of |dir|/public_key_info by sha256 hash
// |expected_public_key_digest|.
// Set |inode_verification_enabled| to false only for testing to disable the
// inode integrity check for snapshot directories.
// Returns false in case of any error.
bool VerifyHash(const base::FilePath& dir,
                const std::string& expected_userhash,
                const std::string& expected_public_key_digest,
                bool inode_verification_enabled);

// Calculates SHA256 hash of |value| and encodes it.
// Returns an empty string in case of any error.
std::string CalculateEncodedSha256Digest(const std::vector<uint8_t>& value);

// Copies the given path, all subdirectories and their contents as well.
//
// If there are files existing under |to| path, always overwrite. Returns true
// if successful, false otherwise. Wildcards on the names are not supported.
//
// This function uses 'cp --preserve=all -r'.
bool CopySnapshotDirectory(const base::FilePath& from,
                           const base::FilePath& to);
}  // namespace data_snapshotd
}  // namespace arc

#endif  // ARC_DATA_SNAPSHOTD_FILE_UTILS_H_
