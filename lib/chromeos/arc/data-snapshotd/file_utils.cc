// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/data-snapshotd/file_utils.h"

#include <algorithm>
#include <memory>
#include <utility>

#if USE_SELINUX
#include <selinux/selinux.h>
#endif

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <utime.h>

#include <base/files/file_enumerator.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/threading/scoped_blocking_call.h>
#include <brillo/data_encoding.h>
#include <crypto/rsa_private_key.h>
#include <crypto/signature_creator.h>
#include <crypto/signature_verifier.h>
#include "crypto/sha2.h"
#include <openssl/sha.h>

#include <base/command_line.h>
#include <base/process/launch.h>
#include <brillo/process/process.h>

namespace arc {
namespace data_snapshotd {

namespace {

constexpr char kHashFile[] = "hash";
constexpr char kPublicKeyFile[] = "public_key_info";
constexpr char kUserhashFile[] = "userhash";

}  // namespace

bool ReadSnapshotDirectory(const base::FilePath& dir,
                           SnapshotDirectory* snapshot_directory,
                           bool inode_verification_enabled) {
  if (!snapshot_directory) {
    LOG(ERROR) << "snapshot_directory is nullptr";
    return false;
  }
  base::FileEnumerator dir_enumerator(
      dir, true /* recursive */,
      base::FileEnumerator::FileType::DIRECTORIES |
          base::FileEnumerator::FileType::FILES |
          base::FileEnumerator::FileType::SHOW_SYM_LINKS);
  std::vector<SnapshotFile> snapshot_files;
  for (auto file = dir_enumerator.Next(); !file.empty();
       file = dir_enumerator.Next()) {
    base::FilePath relative_path;
    if (!dir.IsParent(file) || !dir.AppendRelativePath(file, &relative_path)) {
      LOG(ERROR) << dir.value() << " is not a parent of " << file.value();
      return false;
    }
    SnapshotFile snapshot_file;
    snapshot_file.set_name(relative_path.value());
    std::string contents;
    if (!dir_enumerator.GetInfo().IsDirectory() && !base::IsLink(file) &&
        dir_enumerator.GetInfo().GetSize() != 0 &&
        !base::ReadFileToString(file, &contents)) {
      LOG(ERROR) << "Failed to read file " << file.value();
      return false;
    }
    {
      std::vector<uint8_t> digest;
      digest.resize(SHA256_DIGEST_LENGTH);
      if (!SHA256((const unsigned char*)contents.data(), contents.size(),
                  digest.data())) {
        LOG(ERROR) << "Failed to calculate digest of file contents.";
        return false;
      }
      snapshot_file.set_content_hash(digest.data(), digest.size());
    }

#if USE_SELINUX
    char* con = nullptr;
    if (lgetfilecon(file.value().c_str(), &con) < 0) {
      PLOG(ERROR) << "Failed to getfilecon of file " << file.value();
      return false;
    }
    snapshot_file.set_selinux_context(con, strlen(con));
    if (con != nullptr) {
      free(con);
    }
#endif  // USE_SELINUX

    struct stat stat_buf;
    if (lstat(file.value().c_str(), &stat_buf)) {
      PLOG(ERROR) << "Failed to get stat of file " << file.value();
      return false;
    }
    Stat* stat_value = snapshot_file.mutable_stat();
    if (inode_verification_enabled)
      stat_value->set_ino(stat_buf.st_ino);
    stat_value->set_mode(stat_buf.st_mode);
    stat_value->set_uid(stat_buf.st_uid);
    stat_value->set_gid(stat_buf.st_gid);
    stat_value->set_size(stat_buf.st_size);
    stat_value->set_modification_time(stat_buf.st_mtime);
    snapshot_files.emplace_back(snapshot_file);
  }
  std::sort(snapshot_files.begin(), snapshot_files.end(),
            [](const SnapshotFile& a, const SnapshotFile& b) {
              // Sort lexicographically by name.
              return a.name() < b.name();
            });
  for (auto file : snapshot_files) {
    if (file.name() == kHashFile)
      continue;
    if (file.name() == kPublicKeyFile)
      continue;
    *snapshot_directory->mutable_files()->Add() = file;
  }
  return true;
}

std::vector<uint8_t> CalculateDirectoryCryptographicHash(
    const SnapshotDirectory& dir) {
  std::string serialized;
  if (!dir.SerializeToString(&serialized)) {
    LOG(ERROR) << "Failed to serialize to string snapshot directory info.";
    return {};
  }
  std::string hash = crypto::SHA256HashString(serialized);
  return std::vector<uint8_t>(hash.begin(), hash.end());
}

bool StorePublicKey(const base::FilePath& dir,
                    const std::string& encoded_public_key) {
  if (encoded_public_key.empty()) {
    LOG(ERROR) << "Empty public key info";
    return false;
  }
  if (!base::DirectoryExists(dir)) {
    LOG(ERROR) << "Directory " << dir.value() << " does not exist.";
    return false;
  }
  auto public_key_file = dir.Append(kPublicKeyFile);
  if (!base::WriteFile(public_key_file, encoded_public_key.data(),
                       encoded_public_key.length())) {
    LOG(ERROR) << "Failed to write public key info to file "
               << public_key_file.value();
    return false;
  }
  return true;
}

bool StoreUserhash(const base::FilePath& dir, const std::string& userhash) {
  if (userhash.empty()) {
    LOG(ERROR) << "Empty user hash";
    return false;
  }
  if (!base::DirectoryExists(dir)) {
    LOG(ERROR) << "Directory " << dir.value() << " does not exist.";
    return false;
  }
  if (!base::WriteFile(dir.Append(kUserhashFile), userhash.c_str(),
                       userhash.size())) {
    LOG(ERROR) << "Failed to write userhash to file "
               << dir.Append(kUserhashFile);
    return false;
  }
  return true;
}

bool SignAndStoreHash(const base::FilePath& dir,
                      crypto::RSAPrivateKey* private_key,
                      bool inode_verification_enabled) {
  if (!private_key) {
    LOG(ERROR) << "nullptr private key";
    return false;
  }
  if (!base::DirectoryExists(dir)) {
    LOG(ERROR) << "Directory " << dir.value() << " does not exist.";
    return false;
  }
  SnapshotDirectory snapshot_dir;
  if (!ReadSnapshotDirectory(dir, &snapshot_dir, inode_verification_enabled)) {
    return false;
  }
  std::vector<uint8_t> hash = CalculateDirectoryCryptographicHash(snapshot_dir);
  if (hash.empty()) {
    return false;
  }
  std::vector<uint8_t> signature;
  std::unique_ptr<crypto::SignatureCreator> signer(
      crypto::SignatureCreator::Create(private_key,
                                       crypto::SignatureCreator::SHA256));
  if (!signer->Update(hash.data(), hash.size())) {
    LOG(ERROR) << "Failed to update signing data of directory contents: "
               << dir.value();
    return false;
  }
  if (!signer->Final(&signature)) {
    LOG(ERROR) << "Failed to sign directory contents: " << dir.value();
    return false;
  }

  std::string encoded_signature =
      brillo::data_encoding::Base64Encode(signature.data(), signature.size());
  if (!base::WriteFile(dir.Append(kHashFile), encoded_signature.data(),
                       encoded_signature.length())) {
    LOG(ERROR) << "Failed to write a signature to file "
               << dir.Append(kHashFile);
    return false;
  }
  return true;
}

bool VerifyHash(const base::FilePath& dir,
                const std::string& expected_userhash,
                const std::string& expected_public_key_digest,
                bool inode_verification_enabled) {
  if (!base::DirectoryExists(dir)) {
    LOG(ERROR) << "Directory " << dir.value() << " does not exist.";
    return false;
  }
  if (expected_public_key_digest.empty()) {
    LOG(ERROR) << "Public key digest is empty.";
    return false;
  }
  std::string userhash;
  if (!base::ReadFileToString(dir.Append(kUserhashFile), &userhash)) {
    LOG(ERROR) << "Failed to read userhash for file "
               << dir.Append(kUserhashFile);
    return false;
  }
  if (userhash != expected_userhash) {
    LOG(ERROR) << "Requested to load snapshot for unsupported account.";
    return false;
  }
  std::string encoded_public_key;
  if (!base::ReadFileToString(dir.Append(kPublicKeyFile),
                              &encoded_public_key)) {
    LOG(ERROR) << "Failed to read public key info from file "
               << dir.Append(kPublicKeyFile);
    return false;
  }
  std::vector<uint8_t> public_key;
  if (!brillo::data_encoding::Base64Decode(encoded_public_key, &public_key)) {
    LOG(ERROR) << "Failed to decode public key.";
    return false;
  }
  std::string encoded_public_key_digest =
      CalculateEncodedSha256Digest(public_key);
  if (encoded_public_key_digest.empty()) {
    LOG(ERROR) << "Calculated encoded sha256 digest failed";
    return false;
  }
  if (encoded_public_key_digest.compare(expected_public_key_digest)) {
    LOG(ERROR) << "Public key has been modified.";
    return false;
  }

  std::string contents;
  if (!base::ReadFileToString(dir.Append(kHashFile), &contents)) {
    LOG(ERROR) << "Failed to read signed hash from file "
               << dir.Append(kHashFile);
    return false;
  }
  std::vector<uint8_t> signature;
  if (!brillo::data_encoding::Base64Decode(contents, &signature)) {
    LOG(ERROR) << "Failed to decode signature.";
    return false;
  }
  crypto::SignatureVerifier verifier;
  if (!verifier.VerifyInit(crypto::SignatureVerifier::RSA_PKCS1_SHA256,
                           reinterpret_cast<const uint8_t*>(signature.data()),
                           signature.size(),
                           reinterpret_cast<const uint8_t*>(public_key.data()),
                           public_key.size())) {
    LOG(ERROR) << "Failed to initilize signature verifier.";
    return false;
  }

  SnapshotDirectory snapshot_dir;
  if (!ReadSnapshotDirectory(dir, &snapshot_dir, inode_verification_enabled)) {
    LOG(ERROR) << "Read snapshot directory failed";
    return false;
  }
  std::vector<uint8_t> hash = CalculateDirectoryCryptographicHash(snapshot_dir);
  verifier.VerifyUpdate(hash.data(), hash.size());
  return verifier.VerifyFinal();
}

std::string CalculateEncodedSha256Digest(const std::vector<uint8_t>& value) {
  // Store a new public key digest.
  std::vector<uint8_t> digest;
  digest.resize(SHA256_DIGEST_LENGTH);
  if (!SHA256((const unsigned char*)value.data(), value.size(),
              digest.data()) ||
      digest.empty()) {
    LOG(ERROR) << "Failed to calculate digest of public key.";
    return "";
  }
  return brillo::data_encoding::Base64Encode(digest.data(), digest.size());
}

bool CopySnapshotDirectory(const base::FilePath& from,
                           const base::FilePath& to) {
  base::ScopedBlockingCall scoped_blocking_call(FROM_HERE,
                                                base::BlockingType::MAY_BLOCK);

  base::CommandLine cmd{base::FilePath("/bin/cp")};
  cmd.AppendArg("-r");
  cmd.AppendArg("--preserve=all");
  cmd.AppendArg(from.value().c_str());
  cmd.AppendArg(to.value().c_str());
  int exit_code;
  auto p = base::LaunchProcess(cmd, base::LaunchOptions());
  if (!p.WaitForExitWithTimeout(base::Seconds(30), &exit_code) ||
      exit_code != EXIT_SUCCESS) {
    LOG(ERROR) << "Copy snapshot directory failed: from " << from.value()
               << " to " << to.value();
    return false;
  }
  return true;
}
}  // namespace data_snapshotd
}  // namespace arc
