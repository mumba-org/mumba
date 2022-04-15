// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/data-snapshotd/worker/dbus_adaptor.h"

#include <utility>
#include <vector>

#include <base/bind.h>
#include <base/callback_helpers.h>
#include <base/check.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/memory/ptr_util.h>
#include <base/strings/string_number_conversions.h>
#include <brillo/data_encoding.h>
#include <brillo/cryptohome.h>
#include <brillo/secure_blob.h>
#include <crypto/scoped_openssl_types.h>
#include <crypto/rsa_private_key.h>

#include "arc/data-snapshotd/file_utils.h"
#include "bootlockbox-client/bootlockbox/boot_lockbox_client.h"

namespace arc {
namespace data_snapshotd {

namespace {

// Snapshot paths:
constexpr char kCommonSnapshotPath[] = "/var/cache/arc-data-snapshot";
constexpr char kPreviousSnapshotPath[] = "previous";
constexpr char kLastSnapshotPath[] = "last";
constexpr char kHomeRootDirectory[] = "/home/root";

// System salt local path should match the one in init/arc-data-snapshotd.conf.
constexpr char kSystemSaltPath[] = "/run/arc-data-snapshotd/salt";

}  // namespace

// BootLockbox snapshot keys:
const char kLastSnapshotPublicKey[] = "snapshot_public_key_last";
const char kPreviousSnapshotPublicKey[] = "snapshot_public_key_previous";

// Android data directory name:
const char kAndroidDataDirectory[] = "android-data";
const char kDataDirectory[] = "data";

DBusAdaptor::DBusAdaptor()
    : DBusAdaptor(base::FilePath(kCommonSnapshotPath),
                  base::FilePath(kHomeRootDirectory),
                  cryptohome::BootLockboxClient::CreateBootLockboxClient(),
                  "" /* system_salt */) {}

DBusAdaptor::~DBusAdaptor() = default;

// static
std::unique_ptr<DBusAdaptor> DBusAdaptor::CreateForTesting(
    const base::FilePath& snapshot_directory,
    const base::FilePath& home_root_directory,
    std::unique_ptr<cryptohome::BootLockboxClient> boot_lockbox_client,
    const std::string& system_salt) {
  return base::WrapUnique(
      new DBusAdaptor(snapshot_directory, home_root_directory,
                      std::move(boot_lockbox_client), system_salt));
}

void DBusAdaptor::RegisterAsync(
    const scoped_refptr<dbus::Bus>& bus,
    brillo::dbus_utils::AsyncEventSequencer* sequencer) {
  dbus_object_ = std::make_unique<brillo::dbus_utils::DBusObject>(
      nullptr /* object_manager */, bus, GetObjectPath());
  RegisterWithDBusObject(dbus_object_.get());
  dbus_object_->RegisterAsync(sequencer->GetHandler(
      "Failed to register D-Bus object" /* descriptive_message */,
      true /* failure_is_fatal */));
}

bool DBusAdaptor::TakeSnapshot(const std::string& account_id,
                               const std::string& encoded_private_key,
                               const std::string& encoded_public_key) {
  if (encoded_private_key.empty() || encoded_public_key.empty()) {
    LOG(ERROR) << "Private or public key is empty.";
    return false;
  }

  std::vector<uint8_t> private_key_info;
  if (!brillo::data_encoding::Base64Decode(encoded_private_key,
                                           &private_key_info)) {
    LOG(ERROR) << "Failed to decode private key.";
    return false;
  }
  std::unique_ptr<crypto::RSAPrivateKey> private_key(
      crypto::RSAPrivateKey::CreateFromPrivateKeyInfo(private_key_info));
  if (!private_key) {
    LOG(ERROR) << "Failed to create private key object from decoded bytes.";
    return false;
  }
  if (base::DirectoryExists(last_snapshot_directory_)) {
    LOG(ERROR) << "Snapshot directory already exists. Should be cleared first.";
    return false;
  }

  std::string userhash = brillo::cryptohome::home::SanitizeUserNameWithSalt(
      account_id, brillo::SecureBlob(system_salt_));
  auto user_dir = home_root_directory_.Append(userhash);
  if (!base::DirectoryExists(user_dir)) {
    LOG(ERROR) << "The user directory does not exist " << user_dir.value();
    return false;
  }

  auto android_data_dir = user_dir.Append(kAndroidDataDirectory);
  if (!base::DirectoryExists(android_data_dir)) {
    LOG(ERROR) << "The snapshotting directory does not exist "
               << android_data_dir.value();
    return false;
  }

  if (!base::CreateDirectory(last_snapshot_directory_)) {
    LOG(ERROR) << "Failed to create last snapshot directory "
               << last_snapshot_directory_.value();
    return false;
  }

  if (!CopySnapshotDirectory(android_data_dir, last_snapshot_directory_)) {
    LOG(ERROR) << "Failed to copy snapshot directory from "
               << android_data_dir.value() << " to "
               << last_snapshot_directory_.value();
    return false;
  }

  if (!base::DirectoryExists(last_snapshot_directory_)) {
    LOG(ERROR) << "The snapshot directory was not copied";
    return false;
  }

  // This callback will be executed or released before the end of this function.
  base::ScopedClosureRunner snapshot_clearer(
      base::BindOnce(base::IgnoreResult(&base::DeletePathRecursively),
                     last_snapshot_directory_));
  std::vector<uint8_t> public_key_info;
  if (!brillo::data_encoding::Base64Decode(encoded_public_key,
                                           &public_key_info)) {
    LOG(ERROR) << "Failed to decode public key.";
    return false;
  }
  std::string expected_digest;
  std::string encoded_digest = CalculateEncodedSha256Digest(public_key_info);
  if (!boot_lockbox_client_->Read(kLastSnapshotPublicKey, &expected_digest)) {
    LOG(ERROR) << "Failed to read a public key digest from BootLockbox.";
    return false;
  }
  if (encoded_digest != expected_digest) {
    LOG(ERROR) << "Passed incorrect public key.";
    return false;
  }

  if (!StorePublicKey(last_snapshot_directory_, encoded_public_key))
    return false;
  if (!StoreUserhash(last_snapshot_directory_, userhash))
    return false;
  if (!SignAndStoreHash(last_snapshot_directory_, private_key.get(),
                        inode_verification_enabled_)) {
    return false;
  }
  // Snapshot saved correctly, release closure without running it.
  snapshot_clearer.ReplaceClosure(base::DoNothing());
  return true;
}

void DBusAdaptor::LoadSnapshot(const std::string& account_id,
                               bool* success,
                               bool* last) {
  std::string userhash = brillo::cryptohome::home::SanitizeUserNameWithSalt(
      account_id, brillo::SecureBlob(system_salt_));
  if (!base::DirectoryExists(home_root_directory_.Append(userhash))) {
    LOG(ERROR) << "User directory does not exist for user " << account_id;
    *success = false;
    return;
  }

  base::FilePath android_data_dir =
      home_root_directory_.Append(userhash).Append(kAndroidDataDirectory);
  if (!base::DirectoryExists(android_data_dir)) {
    LOG(ERROR) << "android-data directory does not exist for user "
               << account_id;
    *success = false;
    return;
  }

  auto data_dir = android_data_dir.Append(kDataDirectory);
  if (TryToLoadSnapshot(userhash, last_snapshot_directory_, data_dir,
                        kLastSnapshotPublicKey)) {
    *last = true;
    *success = true;
    return;
  }
  if (TryToLoadSnapshot(userhash, previous_snapshot_directory_, data_dir,
                        kPreviousSnapshotPublicKey)) {
    *last = false;
    *success = true;
    return;
  }
  *success = false;
}

DBusAdaptor::DBusAdaptor(
    const base::FilePath& snapshot_directory,
    const base::FilePath& home_root_directory,
    std::unique_ptr<cryptohome::BootLockboxClient> boot_lockbox_client,
    const std::string& system_salt)
    : org::chromium::ArcDataSnapshotdWorkerAdaptor(this),
      previous_snapshot_directory_(
          snapshot_directory.Append(kPreviousSnapshotPath)),
      last_snapshot_directory_(snapshot_directory.Append(kLastSnapshotPath)),
      home_root_directory_(home_root_directory),
      boot_lockbox_client_(std::move(boot_lockbox_client)),
      system_salt_(system_salt) {
  DCHECK(boot_lockbox_client_);
  if (system_salt_.empty() &&
      !base::ReadFileToString(base::FilePath(kSystemSaltPath), &system_salt_)) {
    LOG(ERROR) << "No available system salt.";
  }
}

bool DBusAdaptor::TryToLoadSnapshot(const std::string& userhash,
                                    const base::FilePath& snapshot_dir,
                                    const base::FilePath& android_data_dir,
                                    const std::string& boot_lockbox_key) {
  if (!base::DirectoryExists(snapshot_dir)) {
    LOG(ERROR) << "Snapshot directory " << snapshot_dir.value()
               << " does not exist.";
    return false;
  }

  std::string expected_public_key_digest;
  if (!boot_lockbox_client_->Read(boot_lockbox_key,
                                  &expected_public_key_digest) ||
      expected_public_key_digest.empty()) {
    LOG(ERROR) << "Failed to read a public key digest " << boot_lockbox_key
               << " from BootLockbox.";
    return false;
  }

  if (!VerifyHash(snapshot_dir, userhash, expected_public_key_digest,
                  inode_verification_enabled_)) {
    LOG(ERROR) << "Hash verification failed.";
    return false;
  }

  // TODO(b/188753815): remove once the second path deletion is no longer
  // needed with --profile=minimalistc-mountns
  if (!base::DeletePathRecursively(android_data_dir) &&
      !base::DeletePathRecursively(android_data_dir)) {
    LOG(ERROR) << "Failed to remove android-data directory.";
    return false;
  }

  if (!CopySnapshotDirectory(
          snapshot_dir.Append(kAndroidDataDirectory).Append(kDataDirectory),
          android_data_dir)) {
    LOG(ERROR) << "Failed to copy a snapshot directory.";
    return false;
  }
  return true;
}

}  // namespace data_snapshotd
}  // namespace arc
