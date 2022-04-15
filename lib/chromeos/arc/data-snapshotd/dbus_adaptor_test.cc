// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string>
#include <utility>
#include <vector>

#include <base/bind.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/run_loop.h>
#include <base/test/task_environment.h>
#include <base/threading/thread_task_runner_handle.h>
#include <brillo/cryptohome.h>
#include <brillo/data_encoding.h>
#include <brillo/secure_blob.h>
#include <brillo/dbus/mock_dbus_method_response.h>
#include <dbus/bus.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "arc/data-snapshotd/block_ui_controller.h"
#include "arc/data-snapshotd/dbus_adaptor.h"
#include "arc/data-snapshotd/fake_process_launcher.h"
#include "arc/data-snapshotd/file_utils.h"
#include "arc/data-snapshotd/mock_esc_key_watcher.h"
#include "arc/data-snapshotd/worker_bridge.h"
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

MATCHER_P(nEq, expected, "") {
  return expected != arg;
}

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

class FakeWorkerBridge : public WorkerBridge {
 public:
  FakeWorkerBridge() = default;

  // WorkerBridge overrides:
  void Init(const std::string& account_id,
            base::OnceCallback<void(bool)> on_initialized) override {
    EXPECT_EQ(account_id, account_id_);
    base::SequencedTaskRunnerHandle::Get()->PostTask(
        FROM_HERE, base::BindOnce(std::move(on_initialized), init_result_));
  }

  void TakeSnapshot(
      const std::string& account_id,
      const std::string& private_key,
      const std::string& public_key,
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<bool>> response)
      override {
    EXPECT_EQ(account_id, account_id);
    EXPECT_FALSE(private_key.empty());
    EXPECT_FALSE(public_key.empty());
    response->Return(result_);
  }

  void LoadSnapshot(
      const std::string& account_id,
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<bool, bool>>
          response) override {
    EXPECT_EQ(account_id, account_id);
    response->Return(result_, last_);
  }

  bool is_available_for_testing() const override { return init_result_; }

  void set_init_result(bool init_result) { init_result_ = init_result; }

  void set_result(bool result) { result_ = result; }

  void set_account_id(const std::string& account_id) {
    account_id_ = account_id;
  }

  void set_last(bool last) { last_ = last; }

 private:
  bool init_result_ = false;
  bool result_ = false;
  bool last_ = false;
  std::string account_id_;
};

class DBusAdaptorTest : public testing::Test {
 public:
  DBusAdaptorTest() : bus_(new dbus::Bus{dbus::Bus::Options{}}) {}

  void SetUp() override {
    EXPECT_TRUE(root_tempdir_.CreateUniqueTempDir());
    auto boot_lockbox_client =
        std::make_unique<testing::StrictMock<MockBootLockboxClient>>(bus_);
    boot_lockbox_client_ = boot_lockbox_client.get();

    process_launcher_ = std::make_unique<FakeProcessLauncher>();
    dbus_adaptor_ = DBusAdaptor::CreateForTesting(
        root_tempdir_.GetPath(), std::move(boot_lockbox_client),
        BlockUiController::CreateForTesting(
            std::make_unique<FakeEscKeyWatcher>(&delegate_),
            root_tempdir_.GetPath(),
            process_launcher_->GetLaunchProcessCallback()));
  }

  void TearDown() override {
    dbus_adaptor_.reset();
    EXPECT_TRUE(base::DeletePathRecursively(root_tempdir_.GetPath()));
    process_launcher_.reset();
  }

  FakeWorkerBridge* CreateWorkerBridge() {
    auto worker_bridge = std::make_unique<FakeWorkerBridge>();
    auto* worker_bridge_ptr = worker_bridge.get();
    WorkerBridge::SetFakeInstanceForTesting(std::move(worker_bridge));
    return worker_bridge_ptr;
  }

  DBusAdaptor* dbus_adaptor() { return dbus_adaptor_.get(); }
  const base::FilePath& last_snapshot_dir() const {
    return dbus_adaptor_->get_last_snapshot_directory();
  }
  const base::FilePath& previous_snapshot_dir() const {
    return dbus_adaptor_->get_previous_snapshot_directory();
  }
  base::FilePath random_dir() const {
    return root_tempdir_.GetPath().Append(kRandomDir);
  }

  // Creates |dir| and fills in with random content.
  void CreateDir(const base::FilePath& dir) {
    EXPECT_TRUE(base::CreateDirectory(dir));
    EXPECT_TRUE(base::CreateDirectory(dir.Append(kRandomDir)));
    EXPECT_TRUE(
        base::WriteFile(dir.Append(kRandomFile), kContent, strlen(kContent)));
  }

  void ExpectUiScreenShown(bool shown = true) {
    process_launcher_->ExpectUiScreenShown(root_tempdir_.GetPath(), shown);
  }

  void ExpectProgressUpdated(int percent, bool result = true) {
    process_launcher_->ExpectProgressUpdated(percent, result);
  }

  void GenerateKeyPairBasic() {
    EXPECT_CALL(*boot_lockbox_client(), Store(Eq(kLastSnapshotPublicKey), _))
        .WillOnce(Return(true));
    ExpectUiScreenShown();
    EXPECT_TRUE(dbus_adaptor()->GenerateKeyPair());
  }

  void TakeSnapshotBasic(bool init_result, bool result, bool expected_result) {
    auto* worker_bridge = CreateWorkerBridge();
    std::unique_ptr<brillo::dbus_utils::MockDBusMethodResponse<bool>> response(
        new brillo::dbus_utils::MockDBusMethodResponse<bool>(nullptr));
    response->set_return_callback(base::Bind(
        [](bool expected_result, const bool& success) {
          EXPECT_EQ(expected_result, success);
        },
        expected_result));
    worker_bridge->set_init_result(init_result);
    worker_bridge->set_result(result);
    worker_bridge->set_account_id(kFakeAccountID);
    dbus_adaptor()->TakeSnapshot(std::move(response), kFakeAccountID);
  }

  void LoadSnapshotBasic(bool init_result, bool result, bool last) {
    auto* worker_bridge = CreateWorkerBridge();
    std::unique_ptr<brillo::dbus_utils::MockDBusMethodResponse<bool, bool>>
        response(new brillo::dbus_utils::MockDBusMethodResponse<bool, bool>(
            nullptr));
    response->set_return_callback(base::Bind(
        [](bool expected_result, bool expected_last, const bool& success,
           const bool& last) {
          EXPECT_EQ(expected_result, success);
          EXPECT_EQ(expected_last, last);
        },
        result, last));
    worker_bridge->set_init_result(init_result);
    worker_bridge->set_result(result);
    worker_bridge->set_last(last);
    worker_bridge->set_account_id(kFakeAccountID);
    dbus_adaptor()->LoadSnapshot(std::move(response), kFakeAccountID);
  }

  MockBootLockboxClient* boot_lockbox_client() { return boot_lockbox_client_; }

 private:
  base::test::TaskEnvironment task_environment_;
  MockEscKeyWatcherDelegate delegate_;
  scoped_refptr<dbus::Bus> bus_;
  MockBootLockboxClient* boot_lockbox_client_;
  std::unique_ptr<FakeProcessLauncher> process_launcher_;
  std::unique_ptr<DBusAdaptor> dbus_adaptor_;
  base::ScopedTempDir root_tempdir_;
};

TEST_F(DBusAdaptorTest, ClearSnapshotBasic) {
  CreateDir(last_snapshot_dir());
  EXPECT_TRUE(base::DirectoryExists(last_snapshot_dir()));

  CreateDir(previous_snapshot_dir());
  EXPECT_TRUE(base::DirectoryExists(previous_snapshot_dir()));

  EXPECT_TRUE(dbus_adaptor()->ClearSnapshot(false /* last */));
  EXPECT_FALSE(base::DirectoryExists(previous_snapshot_dir()));

  EXPECT_TRUE(dbus_adaptor()->ClearSnapshot(false /* last */));

  EXPECT_TRUE(dbus_adaptor()->ClearSnapshot(true /* last */));
  EXPECT_FALSE(base::DirectoryExists(last_snapshot_dir()));

  EXPECT_TRUE(dbus_adaptor()->ClearSnapshot(true /* last */));
}

// Test successful basic flow with no pre-existing snapshots.
TEST_F(DBusAdaptorTest, GenerateKeyPairBasic) {
  GenerateKeyPairBasic();
}

// Test successful basic flow with pre-existing snapshots.
TEST_F(DBusAdaptorTest, GenerateKeyPairExisting) {
  CreateDir(last_snapshot_dir());
  CreateDir(previous_snapshot_dir());

  SnapshotDirectory last_dir;
  EXPECT_TRUE(ReadSnapshotDirectory(last_snapshot_dir(), &last_dir));
  std::vector<uint8_t> last_hash =
      CalculateDirectoryCryptographicHash(last_dir);
  EXPECT_FALSE(last_hash.empty());

  {
    SnapshotDirectory previous_dir;
    EXPECT_TRUE(ReadSnapshotDirectory(previous_snapshot_dir(), &previous_dir));
    std::vector<uint8_t> previous_hash =
        CalculateDirectoryCryptographicHash(previous_dir);
    EXPECT_FALSE(previous_hash.empty());

    EXPECT_NE(last_hash, previous_hash);
  }

  // Last snapshot dir => previous snapshot dir.
  EXPECT_CALL(*boot_lockbox_client(), Read(Eq(kLastSnapshotPublicKey), _))
      .WillOnce(Invoke([](const std::string& key, std::string* value) {
        *value = kFakeLastSnapshotPublicKey;
        return true;
      }));
  EXPECT_CALL(*boot_lockbox_client(), Store(Eq(kPreviousSnapshotPublicKey),
                                            Eq(kFakeLastSnapshotPublicKey)))
      .WillOnce(Return(true));
  EXPECT_CALL(*boot_lockbox_client(), Store(Eq(kLastSnapshotPublicKey), Eq("")))
      .WillOnce(Return(true));
  EXPECT_CALL(*boot_lockbox_client(),
              Store(Eq(kLastSnapshotPublicKey), nEq("")))
      .WillOnce(Return(true));

  ExpectUiScreenShown();
  EXPECT_TRUE(dbus_adaptor()->GenerateKeyPair());
  {
    SnapshotDirectory previous_dir;
    EXPECT_TRUE(ReadSnapshotDirectory(previous_snapshot_dir(), &previous_dir));
    std::vector<uint8_t> previous_hash =
        CalculateDirectoryCryptographicHash(previous_dir);
    EXPECT_FALSE(previous_hash.empty());
    // Check that the last snapshot has been moved to previous snapshot dir.
    EXPECT_EQ(previous_hash, last_hash);
  }
}

// Test successful flow with last snapshot key reading failure.
TEST_F(DBusAdaptorTest, GenerateKeyPairReadFailure) {
  CreateDir(last_snapshot_dir());

  // Attempt failure: last snapshot dir => previous snapshot dir.
  EXPECT_CALL(*boot_lockbox_client(), Read(Eq(kLastSnapshotPublicKey), _))
      .WillOnce(Return(false));
  EXPECT_CALL(*boot_lockbox_client(),
              Store(Eq(kLastSnapshotPublicKey), nEq("")))
      .WillOnce(Return(true));

  ExpectUiScreenShown();
  // Generating key pair should be still successful.
  EXPECT_TRUE(dbus_adaptor()->GenerateKeyPair());
}

// Test successful flow with pre-existing last snapshot empty key.
TEST_F(DBusAdaptorTest, GenerateKeyPairReadEmpty) {
  CreateDir(last_snapshot_dir());

  // Attempt failure: last snapshot dir => previous snapshot dir.
  EXPECT_CALL(*boot_lockbox_client(), Read(Eq(kLastSnapshotPublicKey), _))
      .WillOnce(Invoke([](const std::string& key, std::string* value) {
        *value = "";
        return true;
      }));
  EXPECT_CALL(*boot_lockbox_client(),
              Store(Eq(kLastSnapshotPublicKey), nEq("")))
      .WillOnce(Return(true));

  ExpectUiScreenShown();
  // Generating key pair should be still successful.
  EXPECT_TRUE(dbus_adaptor()->GenerateKeyPair());
}

// Test success flow with pre-existing snapshots and moving error.
TEST_F(DBusAdaptorTest, GenerateKeyPairMoveError) {
  CreateDir(last_snapshot_dir());

  // Last snapshot dir => previous snapshot dir.
  EXPECT_CALL(*boot_lockbox_client(), Read(Eq(kLastSnapshotPublicKey), _))
      .WillOnce(Invoke([](const std::string& key, std::string* value) {
        *value = kFakeLastSnapshotPublicKey;
        return true;
      }));
  // Fail to move last snapshot public key to previous.
  EXPECT_CALL(*boot_lockbox_client(), Store(Eq(kPreviousSnapshotPublicKey),
                                            Eq(kFakeLastSnapshotPublicKey)))
      .WillOnce(Return(false));
  EXPECT_CALL(*boot_lockbox_client(),
              Store(Eq(kLastSnapshotPublicKey), nEq("")))
      .WillOnce(Return(true));

  ExpectUiScreenShown();
  // Generating key pair should be still successful, because the last snapshot
  // will be re-generated anyway.
  EXPECT_TRUE(dbus_adaptor()->GenerateKeyPair());
}

// Test failure flow when showing a UI screen is failed.
TEST_F(DBusAdaptorTest, GenerateKeyPairUiFailure) {
  EXPECT_CALL(*boot_lockbox_client(), Store(Eq(kLastSnapshotPublicKey), _))
      .WillOnce(Return(true));

  ExpectUiScreenShown(false /* shown */);
  // Since the screen is not shown, do not dismiss it.
  EXPECT_FALSE(dbus_adaptor()->GenerateKeyPair());
}

// Test failure flow when storing freshly generated public key is failed.
TEST_F(DBusAdaptorTest, GenerateKeyPairStoreFailure) {
  // Fail once freshly generated public key storage is attempted.
  EXPECT_CALL(*boot_lockbox_client(),
              Store(Eq(kLastSnapshotPublicKey), nEq("")))
      .WillOnce(Return(false));

  EXPECT_FALSE(dbus_adaptor()->GenerateKeyPair());
}

// Test failure flow when the keys were not generated.
TEST_F(DBusAdaptorTest, TakeSnapshotNoPrivateKeyFailure) {
  TakeSnapshotBasic(true /* init_result */, true /* result */,
                    false /* expected_result */);
}

// Test failure flow when worker's initialization failed.
TEST_F(DBusAdaptorTest, TakeSnapshotInitializationFailed) {
  GenerateKeyPairBasic();

  TakeSnapshotBasic(false /* init_result */, false /* result */,
                    false /* expected_result */);
}

// Test failure flow when snapshot taking failed.
TEST_F(DBusAdaptorTest, TakeSnapshotFailure) {
  GenerateKeyPairBasic();

  TakeSnapshotBasic(true /* init_result */, false /* result */,
                    false /* expected_result */);
}

// Test basic TakeSnapshot success flow.
TEST_F(DBusAdaptorTest, TakeSnapshotSuccess) {
  GenerateKeyPairBasic();

  TakeSnapshotBasic(true /* init_result */, true /* result */,
                    false /* expected_result */);
}

// Test failure flow if TakeSnapshot is invoked twice.
TEST_F(DBusAdaptorTest, TakeSnapshotDouble) {
  GenerateKeyPairBasic();

  TakeSnapshotBasic(true /* init_result */, true /* result */,
                    true /* expected_result */);

  TakeSnapshotBasic(true /* init_result */, true /* result */,
                    false /* expected_result */);
}

// Test failure flow when worker's initialization failed..
TEST_F(DBusAdaptorTest, LoadSnapshotInitializationFailed) {
  LoadSnapshotBasic(false /* init_result */, false /* result */,
                    false /* last */);
}

// Test failure when snapshot loading failed.
TEST_F(DBusAdaptorTest, LoadSnapshotFailure) {
  LoadSnapshotBasic(true /* init_result */, false /* result */,
                    false /* last */);
}

// Test basic success flow.
TEST_F(DBusAdaptorTest, LoadSnapshotSuccess) {
  LoadSnapshotBasic(true /* init_result */, true /* result */, true /* last */);
}

// Test failure flow when UI screen is not shown.
TEST_F(DBusAdaptorTest, UpdateNoUIScreen) {
  ExpectUiScreenShown(false /* result */);
  EXPECT_FALSE(dbus_adaptor()->Update(0 /* percent */));
}

// Test failure flow with invalid percent number.
TEST_F(DBusAdaptorTest, UpdateInvalidPercent) {
  EXPECT_CALL(*boot_lockbox_client(), Store(Eq(kLastSnapshotPublicKey), _))
      .WillOnce(Return(true));
  ExpectUiScreenShown();
  EXPECT_TRUE(dbus_adaptor()->GenerateKeyPair());

  EXPECT_FALSE(dbus_adaptor()->Update(-1 /* percent */));
  EXPECT_FALSE(dbus_adaptor()->Update(101 /* percent */));
}

// Test failure flow with the progress update command failure.
TEST_F(DBusAdaptorTest, UpdateFailure) {
  EXPECT_CALL(*boot_lockbox_client(), Store(Eq(kLastSnapshotPublicKey), _))
      .WillOnce(Return(true));
  ExpectUiScreenShown();
  EXPECT_TRUE(dbus_adaptor()->GenerateKeyPair());

  ExpectProgressUpdated(0 /* percent */, false /* result */);
  EXPECT_FALSE(dbus_adaptor()->Update(0 /* percent */));
}

// Test success basic UI update flow.
TEST_F(DBusAdaptorTest, UpdateSuccess) {
  EXPECT_CALL(*boot_lockbox_client(), Store(Eq(kLastSnapshotPublicKey), _))
      .WillOnce(Return(true));
  ExpectUiScreenShown();
  EXPECT_TRUE(dbus_adaptor()->GenerateKeyPair());

  ExpectProgressUpdated(0 /* percent */);
  EXPECT_TRUE(dbus_adaptor()->Update(0 /* percent */));
  ExpectProgressUpdated(10 /* percent */);
  EXPECT_TRUE(dbus_adaptor()->Update(10 /* percent */));
  ExpectProgressUpdated(100 /* percent */);
  EXPECT_TRUE(dbus_adaptor()->Update(100 /* percent */));
}

}  // namespace data_snapshotd
}  // namespace arc
