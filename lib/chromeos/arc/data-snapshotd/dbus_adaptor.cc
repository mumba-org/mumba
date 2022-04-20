// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/data-snapshotd/dbus_adaptor.h"

#include <utility>
#include <vector>

#include <base/bind.h>
#include <base/callback_helpers.h>
//#include <base/check.h>
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
constexpr char kLastSnapshotPath[] = "last";
constexpr char kPreviousSnapshotPath[] = "previous";

}  // namespace

// BootLockbox snapshot keys:
const char kLastSnapshotPublicKey[] = "snapshot_public_key_last";
const char kPreviousSnapshotPublicKey[] = "snapshot_public_key_previous";

DBusAdaptor::DBusAdaptor()
    : DBusAdaptor(base::FilePath(kCommonSnapshotPath),
                  cryptohome::BootLockboxClient::CreateBootLockboxClient(),
                  nullptr) {}

DBusAdaptor::~DBusAdaptor() = default;

// static
std::unique_ptr<DBusAdaptor> DBusAdaptor::CreateForTesting(
    const base::FilePath& snapshot_directory,
    std::unique_ptr<cryptohome::BootLockboxClient> boot_lockbox_client,
    std::unique_ptr<BlockUiController> block_ui_controller) {
  return base::WrapUnique(new DBusAdaptor(snapshot_directory,
                                          std::move(boot_lockbox_client),
                                          std::move(block_ui_controller)));
}

void DBusAdaptor::RegisterAsync(
    const scoped_refptr<dbus::Bus>& bus,
    brillo::dbus_utils::AsyncEventSequencer* sequencer) {
  bus_ = bus;
  dbus_object_ = std::make_unique<brillo::dbus_utils::DBusObject>(
      nullptr /* object_manager */, bus, GetObjectPath());
  RegisterWithDBusObject(dbus_object_.get());
  dbus_object_->RegisterAsync(sequencer->GetHandler(
      "Failed to register D-Bus object" /* descriptive_message */,
      true /* failure_is_fatal */));
}

bool DBusAdaptor::GenerateKeyPair() {
  std::string last_public_key_digest;
  // Try to move last snapshot to previous for consistency.
  if (base::PathExists(last_snapshot_directory_) &&
      boot_lockbox_client_->Read(kLastSnapshotPublicKey,
                                 &last_public_key_digest) &&
      !last_public_key_digest.empty()) {
    if (boot_lockbox_client_->Store(kPreviousSnapshotPublicKey,
                                    last_public_key_digest) &&
        ClearSnapshot(false /* last */) &&
        base::Move(last_snapshot_directory_, previous_snapshot_directory_)) {
      boot_lockbox_client_->Store(kLastSnapshotPublicKey, "");
    } else {
      LOG(ERROR) << "Failed to move last to previous snapshot.";
    }
  }
  // Clear last snapshot - a new one will be created soon.
  if (!ClearSnapshot(true /* last */))
    return false;

  // Generate a key pair.
  public_key_info_.clear();
  std::unique_ptr<crypto::RSAPrivateKey> generated_private_key(
      crypto::RSAPrivateKey::Create(4096));
  if (!generated_private_key) {
    LOG(ERROR) << "Failed to generate a key pair.";
    return false;
  }
  if (!generated_private_key->ExportPublicKey(&public_key_info_)) {
    LOG(ERROR) << "Failed to export public key";
    return false;
  }

  // Store a new public key digest.
  std::string encoded_digest = CalculateEncodedSha256Digest(public_key_info_);
  if (!boot_lockbox_client_->Store(kLastSnapshotPublicKey, encoded_digest)) {
    LOG(ERROR) << "Failed to store a public key in BootLockbox.";
    return false;
  }
  // Save private key for later usage.
  private_key_ = std::move(generated_private_key);

  // block_ui_controller_ is pre-initialized for tests or if already present.
  if (!block_ui_controller_) {
    block_ui_controller_ = std::make_unique<BlockUiController>(
        std::make_unique<EscKeyWatcher>(this),
        base::FilePath(kCommonSnapshotPath));
  }

  if (!block_ui_controller_->ShowScreen()) {
    LOG(ERROR) << "update_arc_data_snapshot failed to be shown";
    block_ui_controller_.reset();
    return false;
  }
  return true;
}

void DBusAdaptor::TakeSnapshot(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<bool>> response,
    const std::string& account_id) {
  std::vector<uint8_t> private_key_info;
  if (!private_key_ || !private_key_->ExportPrivateKey(&private_key_info)) {
    LOG(ERROR) << "Failed to export private key info.";
    response->Return(false);
    return;
  }

  worker_dbus_bridge_ = WorkerBridge::Create(bus_);
  std::string encoded_private_key = brillo::data_encoding::Base64Encode(
      private_key_info.data(), private_key_info.size());

  std::string encoded_public_key = brillo::data_encoding::Base64Encode(
      public_key_info_.data(), public_key_info_.size());

  worker_dbus_bridge_->Init(
      account_id, base::BindOnce(&DBusAdaptor::DelegateTakingSnapshot,
                                 weak_ptr_factory_.GetWeakPtr(), account_id,
                                 encoded_private_key, encoded_public_key,
                                 std::move(response)));
  // Dispose keys.
  private_key_.reset();
  public_key_info_.clear();
}

bool DBusAdaptor::ClearSnapshot(bool last) {
  base::FilePath dir(last ? last_snapshot_directory_
                          : previous_snapshot_directory_);
  if (!base::DirectoryExists(dir)) {
    LOG(WARNING) << "Snapshot directory is already empty: " << dir.value();
    return true;
  }
  if (!base::DeletePathRecursively(dir)) {
    LOG(ERROR) << "Failed to delete snapshot directory: " << dir.value();
    return false;
  }
  return true;
}

void DBusAdaptor::LoadSnapshot(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<bool, bool>>
        response,
    const std::string& account_id) {
  worker_dbus_bridge_ = WorkerBridge::Create(bus_);
  worker_dbus_bridge_->Init(
      account_id, base::BindOnce(&DBusAdaptor::DelegateLoadingSnapshot,
                                 weak_ptr_factory_.GetWeakPtr(), account_id,
                                 std::move(response)));
}

bool DBusAdaptor::Update(int percent) {
  if (!block_ui_controller_) {
    LOG(ERROR)
        << "Failed to update a progress bar on the UI screen, not shown.";
    return false;
  }
  if (percent < 0 || percent > 100) {
    LOG(ERROR) << "Percentage must be in [0..100], but passed " << percent;
    return false;
  }
  return block_ui_controller_->UpdateProgress(percent);
}

void DBusAdaptor::SendCancelSignal() {
  SendUiCancelledSignal();
}

DBusAdaptor::DBusAdaptor(
    const base::FilePath& snapshot_directory,
    std::unique_ptr<cryptohome::BootLockboxClient> boot_lockbox_client,
    std::unique_ptr<BlockUiController> block_ui_controller)
    : org::chromium::ArcDataSnapshotdAdaptor(this),
      last_snapshot_directory_(snapshot_directory.Append(kLastSnapshotPath)),
      previous_snapshot_directory_(
          snapshot_directory.Append(kPreviousSnapshotPath)),
      boot_lockbox_client_(std::move(boot_lockbox_client)),
      block_ui_controller_(std::move(block_ui_controller)) {
  DCHECK(boot_lockbox_client_);
}

void DBusAdaptor::DelegateTakingSnapshot(
    const std::string& account_id,
    const std::string& encoded_private_key,
    const std::string& encoded_public_key,
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<bool>> response,
    bool is_initialized) {
  DCHECK(worker_dbus_bridge_);
  if (!is_initialized) {
    LOG(ERROR) << "Failed to initialize arc-data-snapshotd-worker DBus daemon.";
    response->Return(false);
    return;
  }
  worker_dbus_bridge_->TakeSnapshot(account_id, encoded_private_key,
                                    encoded_public_key, std::move(response));
}

void DBusAdaptor::DelegateLoadingSnapshot(
    const std::string& account_id,
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<bool, bool>>
        response,
    bool is_initialized) {
  DCHECK(worker_dbus_bridge_);
  if (!is_initialized) {
    LOG(ERROR) << "Failed to initialize arc-data-snapshotd-worker DBus daemon.";
    response->Return(false, false);
    return;
  }
  worker_dbus_bridge_->LoadSnapshot(account_id, std::move(response));
}

}  // namespace data_snapshotd
}  // namespace arc
