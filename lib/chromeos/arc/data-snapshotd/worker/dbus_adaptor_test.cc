// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string>
#include <utility>
#include <vector>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <brillo/cryptohome.h>
#include <brillo/data_encoding.h>
#include <brillo/secure_blob.h>
#include <crypto/rsa_private_key.h>
#include <dbus/bus.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "arc/data-snapshotd/file_utils.h"
#include "arc/data-snapshotd/worker/dbus_adaptor.h"
#include "bootlockbox-client/bootlockbox/boot_lockbox_client.h"
// Note that boot_lockbox_rpc.pb.h have to be included before
// dbus_adaptors/org.chromium.BootLockboxInterface.h because it is used in
// there.
#include "bootlockbox/proto_bindings/boot_lockbox_rpc.pb.h"

#include "bootlockbox-client/bootlockbox/dbus-proxies.h"

using testing::_;
using testing::Eq;
using testing::Invoke;
using testing::Return;

namespace arc {
namespace data_snapshotd {

namespace {

constexpr char kRandomDir[] = "data";
constexpr char kRandomFile[] = "random file";
constexpr char kContent[] = "content";
constexpr char kFakeLastSnapshotPublicKey[] = "fake_public_key";
constexpr char kFakeAccountID[] = "fake_account_id";
constexpr char kFakeAccountID2[] = "fake_aacount_id_2";

}  // namespace

class MockBootLockboxClient : public cryptohome::BootLockboxClient {
 public:
  explicit MockBootLockboxClient(scoped_refptr<dbus::Bus> bus)
      : BootLockboxClient(
            std::make_unique<org::chromium::BootLockboxInterfaceProxy>(bus),
            bus) {}
  ~MockBootLockboxClient() override = default;

  MOCK_METHOD(bool,
              Store,
              (const std::string&, const std::string&),
              (override));
  MOCK_METHOD(bool, Read, (const std::string&, std::string*), (override));
  MOCK_METHOD(bool, Finalize, (), (override));
};

class DBusAdaptorTest : public testing::Test {
 public:
  DBusAdaptorTest() : bus_(new dbus::Bus{dbus::Bus::Options{}}) {
    brillo::cryptohome::home::SetSystemSalt(&salt_);
  }

  void SetUp() override {
    EXPECT_TRUE(root_tempdir_.CreateUniqueTempDir());
    user_directory_ = root_tempdir_.GetPath().Append(hash(kFakeAccountID));
    EXPECT_TRUE(base::CreateDirectory(user_directory_));
    auto boot_lockbox_client =
        std::make_unique<testing::StrictMock<MockBootLockboxClient>>(bus_);
    boot_lockbox_client_ = boot_lockbox_client.get();

    dbus_adaptor_ = DBusAdaptor::CreateForTesting(
        root_tempdir_.GetPath(), root_tempdir_.GetPath(),
        std::move(boot_lockbox_client), salt_);
  }

  void TearDown() override {
    dbus_adaptor_.reset();
    EXPECT_TRUE(base::DeletePathRecursively(root_tempdir_.GetPath()));
  }

  DBusAdaptor* dbus_adaptor() { return dbus_adaptor_.get(); }
  const base::FilePath& last_snapshot_dir() const {
    return dbus_adaptor_->get_last_snapshot_directory();
  }
  const base::FilePath& previous_snapshot_dir() const {
    return dbus_adaptor_->get_previous_snapshot_directory();
  }
  base::FilePath android_data_dir() const {
    return user_directory_.Append(kAndroidDataDirectory);
  }
  base::FilePath random_dir() const {
    return root_tempdir_.GetPath().Append(kRandomDir);
  }
  std::string hash(const std::string& account_id) const {
    return brillo::cryptohome::home::SanitizeUserNameWithSalt(
        account_id, brillo::SecureBlob(salt_));
  }
  base::FilePath user_directory() const { return user_directory_; }

  // Creates |dir| and fills in with random content.
  void CreateDir(const base::FilePath& dir) {
    EXPECT_TRUE(base::CreateDirectory(dir));

    auto data_dir = dir.Append(kDataDirectory);
    EXPECT_TRUE(base::CreateDirectory(data_dir));

    EXPECT_TRUE(base::CreateDirectory(data_dir.Append(kRandomDir)));
    EXPECT_TRUE(base::WriteFile(data_dir.Append(kRandomFile), kContent,
                                strlen(kContent)));
  }

  bool GenerateKeys(std::string* encoded_private_key,
                    std::string* encoded_public_key,
                    std::string* expected_public_key_digest = nullptr) {
    std::unique_ptr<crypto::RSAPrivateKey> generated_private_key(
        crypto::RSAPrivateKey::Create(4096));

    std::vector<uint8_t> public_key_info;
    if (!generated_private_key->ExportPublicKey(&public_key_info)) {
      return false;
    }
    std::vector<uint8_t> private_key_info;
    if (!generated_private_key->ExportPrivateKey(&private_key_info)) {
      return false;
    }
    *encoded_private_key = brillo::data_encoding::Base64Encode(
        private_key_info.data(), private_key_info.size());

    *encoded_public_key = brillo::data_encoding::Base64Encode(
        public_key_info.data(), public_key_info.size());

    if (expected_public_key_digest)
      *expected_public_key_digest =
          CalculateEncodedSha256Digest(public_key_info);
    return true;
  }

  MockBootLockboxClient* boot_lockbox_client() { return boot_lockbox_client_; }

 private:
  std::string salt_ = "salt";
  scoped_refptr<dbus::Bus> bus_;
  MockBootLockboxClient* boot_lockbox_client_;
  std::unique_ptr<DBusAdaptor> dbus_adaptor_;
  base::ScopedTempDir root_tempdir_;
  base::FilePath user_directory_;
};

// Test failure flow when the keys were not generated.
TEST_F(DBusAdaptorTest, TakeSnapshotNoKeyFailure) {
  EXPECT_FALSE(dbus_adaptor()->TakeSnapshot(kFakeAccountID, "", ""));
}

// Test failure flow when the last snapshot directory already exists.
TEST_F(DBusAdaptorTest, TakeSnapshotLastSnapshotExistFailure) {
  CreateDir(last_snapshot_dir().Append(kAndroidDataDirectory));
  EXPECT_TRUE(base::DirectoryExists(last_snapshot_dir()));

  std::string encoded_private_key;
  std::string encoded_public_key;
  ASSERT_TRUE(GenerateKeys(&encoded_private_key, &encoded_public_key));

  EXPECT_FALSE(dbus_adaptor()->TakeSnapshot(kFakeAccountID, encoded_private_key,
                                            encoded_public_key));
}

// Test failure flow when android-data directory does not exist.
TEST_F(DBusAdaptorTest, TakeSnapshotAndroidDataDirNotExist) {
  std::string encoded_private_key;
  std::string encoded_public_key;
  ASSERT_TRUE(GenerateKeys(&encoded_private_key, &encoded_public_key));

  EXPECT_FALSE(base::DirectoryExists(android_data_dir()));

  EXPECT_FALSE(dbus_adaptor()->TakeSnapshot(kFakeAccountID, encoded_private_key,
                                            encoded_public_key));
}

// Test failure flow when android-data is file.
TEST_F(DBusAdaptorTest, TakeSnapshotAndroidDataNotDirFile) {
  std::string encoded_private_key;
  std::string encoded_public_key;
  ASSERT_TRUE(GenerateKeys(&encoded_private_key, &encoded_public_key));

  // Create a file instead of android-data directory.
  EXPECT_TRUE(base::WriteFile(android_data_dir(), kContent, strlen(kContent)));
  EXPECT_TRUE(base::PathExists(android_data_dir()));
  EXPECT_FALSE(base::DirectoryExists(android_data_dir()));

  EXPECT_FALSE(dbus_adaptor()->TakeSnapshot(kFakeAccountID, encoded_private_key,
                                            encoded_public_key));
}

// Test failure flow when android-data is a fifo.
TEST_F(DBusAdaptorTest, TakeSnapshotAndroidDataFiFo) {
  std::string encoded_private_key;
  std::string encoded_public_key;
  ASSERT_TRUE(GenerateKeys(&encoded_private_key, &encoded_public_key));

  // Create a fifo android-data.
  mkfifo(android_data_dir().value().c_str(), 0666);
  EXPECT_TRUE(base::PathExists(android_data_dir()));
  EXPECT_FALSE(base::DirectoryExists(android_data_dir()));

  EXPECT_FALSE(dbus_adaptor()->TakeSnapshot(kFakeAccountID, encoded_private_key,
                                            encoded_public_key));
}

// TODO(crbug.com/1149744) Enable test once bug is fixed.
// Test basic TakeSnapshot success flow.
TEST_F(DBusAdaptorTest, DISABLED_TakeSnapshotSuccess) {
  // In this test the copied snapshot directory is verified against the origin
  // android data directory. Inodes verification must be disabled, because the
  // inode values are changed after copying.
  // In production, it is not the case, because the directorys' integrity is
  // verified against itself and inode values should persist.
  dbus_adaptor()->set_inode_verification_enabled_for_testing(
      false /* enabled */);
  std::string encoded_private_key;
  std::string encoded_public_key;
  std::string expected_public_key_digest;
  ASSERT_TRUE(GenerateKeys(&encoded_private_key, &encoded_public_key,
                           &expected_public_key_digest));

  CreateDir(android_data_dir());
  EXPECT_TRUE(base::DirectoryExists(android_data_dir()));
  // Store userhash to ensure that userhash stays the same.
  EXPECT_TRUE(StoreUserhash(android_data_dir(), hash(kFakeAccountID)));
  SnapshotDirectory android_dir;
  EXPECT_TRUE(ReadSnapshotDirectory(android_data_dir(), &android_dir,
                                    false /* inode_verification_enabled */));
  std::vector<uint8_t> android_data_hash =
      CalculateDirectoryCryptographicHash(android_dir);
  EXPECT_FALSE(android_data_hash.empty());

  EXPECT_CALL(*boot_lockbox_client(), Read(Eq(kLastSnapshotPublicKey), _))
      .WillOnce(Invoke([expected_public_key_digest](const std::string& key,
                                                    std::string* value) {
        *value = expected_public_key_digest;
        return true;
      }));

  EXPECT_TRUE(dbus_adaptor()->TakeSnapshot(kFakeAccountID, encoded_private_key,
                                           encoded_public_key));
  EXPECT_TRUE(base::DirectoryExists(last_snapshot_dir()));
  SnapshotDirectory last_dir;
  EXPECT_TRUE(
      ReadSnapshotDirectory(last_snapshot_dir().Append(kAndroidDataDirectory),
                            &last_dir, false /* inode_verification_enabled */));
  std::vector<uint8_t> last_snapshot_hash =
      CalculateDirectoryCryptographicHash(last_dir);
  EXPECT_FALSE(last_snapshot_hash.empty());
  EXPECT_EQ(android_dir.DebugString(), last_dir.DebugString());
  EXPECT_EQ(android_data_hash, last_snapshot_hash);

  // Verification for another account ID should fail.
  EXPECT_FALSE(VerifyHash(last_snapshot_dir(), hash(kFakeAccountID2),
                          expected_public_key_digest,
                          false /* inode_verification_enabled */));
  EXPECT_TRUE(VerifyHash(last_snapshot_dir(), hash(kFakeAccountID),
                         expected_public_key_digest,
                         false /* inode_verification_enabled */));
  dbus_adaptor()->set_inode_verification_enabled_for_testing(
      true /* enabled */);
}

// Test failure flow if TakeSnapshot is invoked twice.
TEST_F(DBusAdaptorTest, TakeSnapshotDouble) {
  std::string encoded_private_key;
  std::string encoded_public_key;
  std::string expected_public_key_digest;
  ASSERT_TRUE(GenerateKeys(&encoded_private_key, &encoded_public_key,
                           &expected_public_key_digest));

  EXPECT_CALL(*boot_lockbox_client(), Read(Eq(kLastSnapshotPublicKey), _))
      .WillOnce(Invoke([expected_public_key_digest](const std::string& key,
                                                    std::string* value) {
        *value = expected_public_key_digest;
        return true;
      }));

  CreateDir(android_data_dir());
  EXPECT_TRUE(dbus_adaptor()->TakeSnapshot(kFakeAccountID, encoded_private_key,
                                           encoded_public_key));

  CreateDir(android_data_dir());
  EXPECT_FALSE(dbus_adaptor()->TakeSnapshot(kFakeAccountID, encoded_private_key,
                                            encoded_public_key));
}

// Test failure flow when user directory does not exist.
TEST_F(DBusAdaptorTest, LoadSnapshotNoAndroidDataDir) {
  CreateDir(last_snapshot_dir().Append(kAndroidDataDirectory));
  CreateDir(previous_snapshot_dir().Append(kAndroidDataDirectory));
  EXPECT_TRUE(base::DeletePathRecursively(user_directory()));
  EXPECT_FALSE(base::DirectoryExists(user_directory()));

  bool last, success;
  dbus_adaptor()->LoadSnapshot(kFakeAccountID, &success, &last);
  EXPECT_FALSE(success);
}

// Test failure when snapshot directory does not exist.
TEST_F(DBusAdaptorTest, LoadSnapshotNoSnapshot) {
  CreateDir(android_data_dir());
  EXPECT_TRUE(base::DirectoryExists(android_data_dir()));

  EXPECT_FALSE(base::DirectoryExists(last_snapshot_dir()));
  EXPECT_FALSE(base::DirectoryExists(previous_snapshot_dir()));
  bool last, success;
  dbus_adaptor()->LoadSnapshot(kFakeAccountID, &success, &last);
  EXPECT_FALSE(success);
}

// Test failure when public key is not stored in BootLockbox.
TEST_F(DBusAdaptorTest, LoadSnapshotNoPublicKey) {
  CreateDir(android_data_dir());
  EXPECT_TRUE(base::DirectoryExists(android_data_dir()));

  CreateDir(last_snapshot_dir().Append(kAndroidDataDirectory));
  EXPECT_TRUE(base::DirectoryExists(last_snapshot_dir()));
  EXPECT_FALSE(base::DirectoryExists(previous_snapshot_dir()));

  EXPECT_CALL(*boot_lockbox_client(), Read(Eq(kLastSnapshotPublicKey), _))
      .WillOnce(Return(false));

  bool last, success;
  dbus_adaptor()->LoadSnapshot(kFakeAccountID, &success, &last);
  EXPECT_FALSE(success);
}

// Test failure when empty public key is stored in BootLockbox.
TEST_F(DBusAdaptorTest, LoadSnapshotEmptyPublicKey) {
  CreateDir(android_data_dir());
  EXPECT_TRUE(base::DirectoryExists(android_data_dir()));

  CreateDir(last_snapshot_dir().Append(kAndroidDataDirectory));
  EXPECT_TRUE(base::DirectoryExists(last_snapshot_dir()));
  EXPECT_FALSE(base::DirectoryExists(previous_snapshot_dir()));

  EXPECT_CALL(*boot_lockbox_client(), Read(Eq(kLastSnapshotPublicKey), _))
      .WillOnce(Invoke([](const std::string& key, std::string* value) {
        *value = "";
        return true;
      }));
  bool last, success;
  dbus_adaptor()->LoadSnapshot(kFakeAccountID, &success, &last);
  EXPECT_FALSE(success);
}

// Test failure when snapshot verification fails.
TEST_F(DBusAdaptorTest, LoadSnapshotVerificationFailure) {
  CreateDir(android_data_dir());
  EXPECT_TRUE(base::DirectoryExists(android_data_dir()));

  CreateDir(last_snapshot_dir().Append(kAndroidDataDirectory));
  EXPECT_TRUE(base::DirectoryExists(last_snapshot_dir()));
  EXPECT_FALSE(base::DirectoryExists(previous_snapshot_dir()));

  EXPECT_CALL(*boot_lockbox_client(), Read(Eq(kLastSnapshotPublicKey), _))
      .WillOnce(Invoke([](const std::string& key, std::string* value) {
        *value = kFakeLastSnapshotPublicKey;
        return true;
      }));
  bool last, success;
  dbus_adaptor()->LoadSnapshot(kFakeAccountID, &success, &last);
  EXPECT_FALSE(success);
}

// Test failure when snapshot is loaded for unknown user.
TEST_F(DBusAdaptorTest, LoadSnapshotUnknownUser) {
  // In this test the copied snapshot directory is verified against the origin
  // snapshot directory. Inodes verification must be disabled, because the
  // inode values are changed after copying.
  // In production, it is not the case, because the directorys' integrity is
  // verified against itself and inode values should persist.
  dbus_adaptor()->set_inode_verification_enabled_for_testing(
      false /* enabled */);
  std::string encoded_private_key;
  std::string encoded_public_key;
  std::string expected_public_key_digest;
  ASSERT_TRUE(GenerateKeys(&encoded_private_key, &encoded_public_key,
                           &expected_public_key_digest));

  // Create android-data directory.
  CreateDir(android_data_dir());
  EXPECT_TRUE(base::DirectoryExists(android_data_dir()));

  EXPECT_CALL(*boot_lockbox_client(), Read(Eq(kLastSnapshotPublicKey), _))
      .WillOnce(Invoke([expected_public_key_digest](const std::string& key,
                                                    std::string* value) {
        *value = expected_public_key_digest;
        return true;
      }));

  // Take a snapshot.
  EXPECT_TRUE(dbus_adaptor()->TakeSnapshot(kFakeAccountID, encoded_private_key,
                                           encoded_public_key));
  EXPECT_TRUE(base::DirectoryExists(last_snapshot_dir()));
  // Verify taken snapshot with disabled inode verification.
  EXPECT_TRUE(VerifyHash(last_snapshot_dir(), hash(kFakeAccountID),
                         expected_public_key_digest,
                         false /* inode_verification_enabled */));

  // Load a snapshot directory to android-data for unknown user.
  bool last, success;
  dbus_adaptor()->LoadSnapshot(kFakeAccountID2, &success, &last);
  EXPECT_FALSE(success);

  dbus_adaptor()->set_inode_verification_enabled_for_testing(
      true /* enabled */);
}

// Test basic success flow.
TEST_F(DBusAdaptorTest, LoadSnapshotSuccess) {
  // In this test the copied snapshot directory is verified against the origin
  // snapshot directory. Inodes verification must be disabled, because the
  // inode values are changed after copying.
  // In production, it is not the case, because the directorys' integrity is
  // verified against itself and inode values should persist.
  dbus_adaptor()->set_inode_verification_enabled_for_testing(
      false /* enabled */);
  std::string encoded_private_key;
  std::string encoded_public_key;
  std::string expected_public_key_digest;
  ASSERT_TRUE(GenerateKeys(&encoded_private_key, &encoded_public_key,
                           &expected_public_key_digest));

  // Create android-data directory.
  CreateDir(android_data_dir());
  EXPECT_TRUE(base::DirectoryExists(android_data_dir()));

  EXPECT_CALL(*boot_lockbox_client(), Read(Eq(kLastSnapshotPublicKey), _))
      .WillOnce(Invoke([expected_public_key_digest](const std::string& key,
                                                    std::string* value) {
        *value = expected_public_key_digest;
        return true;
      }));

  // Take a snapshot.
  EXPECT_TRUE(dbus_adaptor()->TakeSnapshot(kFakeAccountID, encoded_private_key,
                                           encoded_public_key));
  EXPECT_TRUE(base::DirectoryExists(last_snapshot_dir()));
  // Verify taken snapshot with disabled inode verification.
  EXPECT_TRUE(VerifyHash(last_snapshot_dir(), hash(kFakeAccountID),
                         expected_public_key_digest,
                         false /* inode_verification_enabled */));

  EXPECT_CALL(*boot_lockbox_client(), Read(Eq(kLastSnapshotPublicKey), _))
      .WillOnce(Invoke([expected_public_key_digest](const std::string& key,
                                                    std::string* value) {
        *value = expected_public_key_digest;
        return true;
      }));
  // Load a snapshot directory to android-data.
  bool last, success;
  dbus_adaptor()->LoadSnapshot(kFakeAccountID, &success, &last);
  EXPECT_TRUE(success);

  // Verify the integrity of the last snapshot with disabld inode verification.
  EXPECT_TRUE(last);

  dbus_adaptor()->set_inode_verification_enabled_for_testing(
      true /* enabled */);
}

// Test success flow when loading of last snapshot fails, but loading of
// previous snapshot succeeds.
TEST_F(DBusAdaptorTest, LoadSnapshotPreviousSuccess) {
  // In this test the copied snapshot directory is verified against the origin
  // snapshot directory. Inodes verification must be disabled, because the
  // inode values are changed after copying.
  // In production, it is not the case, because the directorys' integrity is
  // verified against itself and inode values should persist.
  dbus_adaptor()->set_inode_verification_enabled_for_testing(
      false /* enabled */);
  std::string encoded_private_key;
  std::string encoded_public_key;
  std::string expected_public_key_digest;
  ASSERT_TRUE(GenerateKeys(&encoded_private_key, &encoded_public_key,
                           &expected_public_key_digest));

  CreateDir(android_data_dir());
  EXPECT_TRUE(base::DirectoryExists(android_data_dir()));

  EXPECT_CALL(*boot_lockbox_client(), Read(Eq(kLastSnapshotPublicKey), _))
      .WillOnce(Invoke([expected_public_key_digest](const std::string& key,
                                                    std::string* value) {
        *value = expected_public_key_digest;
        return true;
      }));

  // Take android-data snapshot and name it as a last snapshot.
  EXPECT_TRUE(dbus_adaptor()->TakeSnapshot(kFakeAccountID, encoded_private_key,
                                           encoded_public_key));
  EXPECT_TRUE(base::DirectoryExists(last_snapshot_dir()));
  EXPECT_TRUE(VerifyHash(last_snapshot_dir(), hash(kFakeAccountID),
                         expected_public_key_digest,
                         false /* inode_verification_enabled */));

  EXPECT_CALL(*boot_lockbox_client(), Read(Eq(kPreviousSnapshotPublicKey), _))
      .WillOnce(Invoke([expected_public_key_digest](const std::string& key,
                                                    std::string* value) {
        *value = expected_public_key_digest;
        return true;
      }));

  EXPECT_TRUE(base::Move(last_snapshot_dir(), previous_snapshot_dir()));

  // Load the previous snapshot, because the last one is invalid.
  bool last, success;
  dbus_adaptor()->LoadSnapshot(kFakeAccountID, &success, &last);
  EXPECT_TRUE(success);
  EXPECT_FALSE(last);

  dbus_adaptor()->set_inode_verification_enabled_for_testing(
      true /* enabled */);
}

}  // namespace data_snapshotd
}  // namespace arc
