// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/vpn/l2tp_ipsec_driver.h"

#include <utility>

#include <base/containers/contains.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/memory/ptr_util.h>
#include <base/memory/weak_ptr.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <gtest/gtest.h>
#include <libpasswordprovider/fake_password_provider.h>
#include <libpasswordprovider/password.h>
#include <libpasswordprovider/password_provider.h>
#include <vpn-manager/service_error.h>

#include "shill/ipconfig.h"
#include "shill/mock_adaptors.h"
#include "shill/mock_certificate_file.h"
#include "shill/mock_control.h"
#include "shill/mock_device_info.h"
#include "shill/mock_external_task.h"
#include "shill/mock_manager.h"
#include "shill/mock_metrics.h"
#include "shill/mock_process_manager.h"
#include "shill/ppp_device.h"
#include "shill/test_event_dispatcher.h"
#include "shill/vpn/fake_vpn_util.h"
#include "shill/vpn/mock_vpn_driver.h"
#include "shill/vpn/mock_vpn_provider.h"

using testing::_;
using testing::Mock;
using testing::NiceMock;
using testing::Return;
using testing::ReturnRef;
using testing::WithArg;

namespace shill {

namespace {

// Output of `stroke statusall` used in
// L2TPIPsecDriverTest::ExpectCipherMetricsReported().
constexpr char kStrokeStatusAllOutput[] =
    R"(Status of IKE charon daemon (strongSwan 5.7.2, Linux 4.4.289-21012-gca997499d4ea, x86_64):
  uptime: 3 minutes, since Oct 28 12:34:20 2021
  malloc: sbrk 1622016, mmap 1196032, used 613040, free 1008976
  worker threads: 10 of 16 idle, 6/0/0/0 working, job queue: 0/0/0/0, scheduled: 3
  loaded plugins: charon pkcs11 aes des rc2 sha2 sha1 md5 mgf1 random nonce x509 revocation constraints pubkey pkcs1 pkcs7 pkcs8 pkcs12 pgp dnskey sshkey pem openssl fips-prf gmp curve25519 xcbc cmac hmac attr kernel-netlink resolve socket-default socket-dynamic stroke vici updown xauth-generic lookip led counters
Listening IP addresses:
  1.2.3.4
  1.2.3.5
  192.168.0.1
  192.168.1.2
Connections:
     managed:  %any...10.0.0.1  IKEv1
     managed:   local:  [100.86.195.191] uses pre-shared key authentication
     managed:   remote: uses pre-shared key authentication
     managed:   child:  dynamic[udp/l2tp] === dynamic[udp/l2tp] TRANSPORT
Security Associations (1 up, 0 connecting):
     managed[1]: ESTABLISHED 3 minutes ago, 1.2.3.4[1.2.3.4]...10.0.0.1[10.0.0.1]
     managed[1]: IKEv1 SPIs: a8936495c1cbbca4_i* f8b549a4234245e7_r, pre-shared key reauthentication in 2 hours
     managed[1]: IKE proposal: AES_CBC_128/HMAC_SHA2_256_128/PRF_HMAC_SHA2_256/MODP_3072
     managed{1}:  INSTALLED, TRANSPORT, reqid 1, ESP in UDP SPIs: c422affe_i c5ff79b3_o
     managed{1}:  AES_CBC_128/HMAC_SHA2_256_128, 4034 bytes_i (57 pkts, 19s ago), 42409 bytes_o (569 pkts, 1s ago), rekeying in 41 minutes
     managed{1}:   1.2.3.4/32[udp/l2tp] === 10.0.0.1/32[udp/l2tp])";

}  // namespace

class L2TPIPsecDriverTest : public testing::Test, public RpcTaskDelegate {
 public:
  L2TPIPsecDriverTest()
      : manager_(&control_, &dispatcher_, &metrics_),
        device_info_(&manager_),
        driver_(new L2TPIPsecDriver(&manager_, &process_manager_)),
        certificate_file_(new MockCertificateFile()),
        weak_factory_(this) {
    manager_.set_mock_device_info(&device_info_);
    driver_->certificate_file_.reset(certificate_file_);  // Passes ownership.
    driver_->vpn_util_ = std::make_unique<FakeVPNUtil>();
  }

  ~L2TPIPsecDriverTest() override = default;

  void SetUp() override {
    manager_.vpn_provider_ = std::make_unique<MockVPNProvider>();
    manager_.vpn_provider_->manager_ = &manager_;
    manager_.user_traffic_uids_.push_back(1000);
    manager_.UpdateProviderMapping();

    ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());
  }

  void TearDown() override {
    SetEventHandler(nullptr);
    ASSERT_TRUE(temp_dir_.Delete());

    // The ExternalTask instance initially held by |driver_->external_task_|
    // could be scheduled to be destroyed after |driver_| is destroyed. To avoid
    // leaking any ExternalTask instance when the test finishes, we explicitly
    // destroy |driver_| here and in turn schedules the destruction of
    // |driver_->external_task_| in the message loop. Then we run until the
    // message loop becomes idle to exercise the destruction task of
    // ExternalTask.
    driver_ = nullptr;
    dispatcher_.PostTask(
        FROM_HERE,
        base::BindOnce(&EventDispatcherForTest::QuitDispatchForever,
                       // dispatcher_ will not be deleted before RunLoop quits.
                       base::Unretained(&dispatcher_)));
    dispatcher_.DispatchForever();
  }

 protected:
  static const char kInterfaceName[];
  static const int kInterfaceIndex;

  void SetArg(const std::string& arg, const std::string& value) {
    driver_->args()->Set<std::string>(arg, value);
  }

  void SetArgArray(const std::string& arg,
                   const std::vector<std::string>& value) {
    driver_->args()->Set<Strings>(arg, value);
  }

  KeyValueStore* GetArgs() { return driver_->args(); }

  std::string GetProviderType() { return driver_->GetProviderType(); }

  void SetEventHandler(VPNDriver::EventHandler* handler) {
    driver_->event_handler_ = handler;
  }

  bool IsPSKFileCleared(const base::FilePath& psk_file_path) const {
    return !base::PathExists(psk_file_path) && GetPSKFile().empty();
  }

  bool IsXauthCredentialsFileCleared(
      const base::FilePath& xauth_credentials_file_path) const {
    return !base::PathExists(xauth_credentials_file_path) &&
           GetXauthCredentialsFile().empty();
  }

  // Used to assert that a flag appears in the options.
  void ExpectInFlags(const std::vector<std::string>& options,
                     const std::string& flag,
                     const std::string& value);

  base::FilePath SetupPSKFile();
  base::FilePath SetupXauthCredentialsFile();

  base::FilePath GetPSKFile() const { return driver_->psk_file_; }
  base::FilePath GetXauthCredentialsFile() const {
    return driver_->xauth_credentials_file_;
  }

  void InvokeNotify(const std::string& reason,
                    const std::map<std::string, std::string>& dict) {
    driver_->Notify(reason, dict);
  }

  void FakeUpConnect(base::FilePath* psk_file,
                     base::FilePath* xauth_credentials_file) {
    *psk_file = SetupPSKFile();
    *xauth_credentials_file = SetupXauthCredentialsFile();
    SetEventHandler(&event_handler_);
  }

  void ExpectMetricsReported() {
    Error unused_error;
    PropertyStore store;
    driver_->InitPropertyStore(&store);
    store.SetStringProperty(kL2TPIPsecPskProperty, "x", &unused_error);
    store.SetStringProperty(kL2TPIPsecPasswordProperty, "y", &unused_error);
    store.SetStringProperty(kL2TPIPsecTunnelGroupProperty, "z", &unused_error);
    EXPECT_CALL(metrics_, SendEnumToUMA(Metrics::kMetricVpnDriver,
                                        Metrics::kVpnDriverL2tpIpsec,
                                        Metrics::kMetricVpnDriverMax));
    EXPECT_CALL(metrics_,
                SendEnumToUMA(Metrics::kMetricVpnRemoteAuthenticationType,
                              Metrics::kVpnRemoteAuthenticationTypeL2tpIpsecPsk,
                              Metrics::kVpnRemoteAuthenticationTypeMax));
    EXPECT_CALL(
        metrics_,
        SendEnumToUMA(
            Metrics::kMetricVpnUserAuthenticationType,
            Metrics::kVpnUserAuthenticationTypeL2tpIpsecUsernamePassword,
            Metrics::kVpnUserAuthenticationTypeMax));
    EXPECT_CALL(metrics_,
                SendEnumToUMA(Metrics::kMetricVpnL2tpIpsecTunnelGroupUsage,
                              Metrics::kVpnL2tpIpsecTunnelGroupUsageYes,
                              Metrics::kVpnL2tpIpsecTunnelGroupUsageMax));

    ExpectCipherMetricsReported();
  }

  void ExpectCipherMetricsReported() {
    EXPECT_CALL(process_manager_,
                StartProcessInMinijailWithStdout(_, _, _, _, _, _))
        .WillOnce(WithArg<5>([](ProcessManager::ExitWithStdoutCallback cb) {
          // Invokes the callback directly.
          std::move(cb).Run(0, kStrokeStatusAllOutput);
          return 123;
        }));

    // Expects metrics for IKE.
    EXPECT_CALL(
        metrics_,
        SendEnumToUMA(Metrics::kMetricVpnL2tpIpsecIkeEncryptionAlgorithm,
                      Metrics::kVpnIpsecEncryptionAlgorithm_AES_CBC_128,
                      Metrics::kMetricVpnL2tpIpsecIkeEncryptionAlgorithmMax));
    EXPECT_CALL(
        metrics_,
        SendEnumToUMA(Metrics::kMetricVpnL2tpIpsecIkeIntegrityAlgorithm,
                      Metrics::kVpnIpsecIntegrityAlgorithm_HMAC_SHA2_256_128,
                      Metrics::kMetricVpnL2tpIpsecIkeIntegrityAlgorithmMax));
    EXPECT_CALL(metrics_,
                SendEnumToUMA(Metrics::kMetricVpnL2tpIpsecIkeDHGroup,
                              Metrics::kVpnIpsecDHGroup_MODP_3072,
                              Metrics::kMetricVpnL2tpIpsecIkeDHGroupMax));

    // Expect metrics for ESP.
    EXPECT_CALL(
        metrics_,
        SendEnumToUMA(Metrics::kMetricVpnL2tpIpsecEspEncryptionAlgorithm,
                      Metrics::kVpnIpsecEncryptionAlgorithm_AES_CBC_128,
                      Metrics::kMetricVpnL2tpIpsecEspEncryptionAlgorithmMax));
    EXPECT_CALL(
        metrics_,
        SendEnumToUMA(Metrics::kMetricVpnL2tpIpsecEspIntegrityAlgorithm,
                      Metrics::kVpnIpsecIntegrityAlgorithm_HMAC_SHA2_256_128,
                      Metrics::kMetricVpnL2tpIpsecEspIntegrityAlgorithmMax));
  }

  void ExpectEndReasonMetricsReported(Service::ConnectFailure failure) {
    EXPECT_CALL(
        metrics_,
        SendEnumToUMA(Metrics::kMetricVpnL2tpIpsecStrokeEndReason,
                      Metrics::ConnectFailureToServiceErrorEnum(failure),
                      Metrics::kMetricVpnL2tpIpsecStrokeEndReasonMax));
  }

  void SaveLoginPassword(const std::string& password_str) {
    driver_->password_provider_ =
        std::make_unique<password_provider::FakePasswordProvider>();

    int fds[2];
    base::CreateLocalNonBlockingPipe(fds);
    base::ScopedFD read_dbus_fd(fds[0]);
    base::ScopedFD write_scoped_fd(fds[1]);

    size_t data_size = password_str.length();
    base::WriteFileDescriptor(write_scoped_fd.get(), password_str);
    auto password = password_provider::Password::CreateFromFileDescriptor(
        read_dbus_fd.get(), data_size);
    ASSERT_TRUE(password);

    driver_->password_provider_->SavePassword(*password);
  }

  // Inherited from RpcTaskDelegate.
  void GetLogin(std::string* user, std::string* password) override;
  void Notify(const std::string& reason,
              const std::map<std::string, std::string>& dict) override;

  base::ScopedTempDir temp_dir_;
  MockControl control_;
  EventDispatcherForTest dispatcher_;
  MockMetrics metrics_;
  MockProcessManager process_manager_;
  MockManager manager_;
  NiceMock<MockDeviceInfo> device_info_;
  MockVPNDriverEventHandler event_handler_;
  std::unique_ptr<L2TPIPsecDriver> driver_;
  MockCertificateFile* certificate_file_;  // Owned by |driver_|.
  base::WeakPtrFactory<L2TPIPsecDriverTest> weak_factory_;
};

const char L2TPIPsecDriverTest::kInterfaceName[] = "ppp0";
const int L2TPIPsecDriverTest::kInterfaceIndex = 123;

void L2TPIPsecDriverTest::GetLogin(std::string* /*user*/,
                                   std::string* /*password*/) {}

void L2TPIPsecDriverTest::Notify(
    const std::string& /*reason*/,
    const std::map<std::string, std::string>& /*dict*/) {}

void L2TPIPsecDriverTest::ExpectInFlags(const std::vector<std::string>& options,
                                        const std::string& flag,
                                        const std::string& value) {
  const auto flag_value =
      base::StringPrintf("%s=%s", flag.c_str(), value.c_str());
  EXPECT_TRUE(base::Contains(options, flag_value));
}

base::FilePath L2TPIPsecDriverTest::SetupPSKFile() {
  base::FilePath psk_file;
  EXPECT_TRUE(base::CreateTemporaryFileInDir(temp_dir_.GetPath(), &psk_file));
  EXPECT_FALSE(psk_file.empty());
  EXPECT_TRUE(base::PathExists(psk_file));
  driver_->psk_file_ = psk_file;
  return psk_file;
}

base::FilePath L2TPIPsecDriverTest::SetupXauthCredentialsFile() {
  base::FilePath xauth_credentials_file;
  EXPECT_TRUE(base::CreateTemporaryFileInDir(temp_dir_.GetPath(),
                                             &xauth_credentials_file));
  EXPECT_FALSE(xauth_credentials_file.empty());
  EXPECT_TRUE(base::PathExists(xauth_credentials_file));
  driver_->xauth_credentials_file_ = xauth_credentials_file;
  return xauth_credentials_file;
}

TEST_F(L2TPIPsecDriverTest, GetProviderType) {
  EXPECT_EQ(kProviderL2tpIpsec, GetProviderType());
}

TEST_F(L2TPIPsecDriverTest, Cleanup) {
  driver_->Cleanup();  // Ensure no crash.

  base::FilePath psk_file;
  base::FilePath xauth_credentials_file;
  FakeUpConnect(&psk_file, &xauth_credentials_file);
  driver_->external_task_.reset(new MockExternalTask(
      &control_, &process_manager_, weak_factory_.GetWeakPtr(),
      base::Callback<void(pid_t, int)>()));
  SetEventHandler(&event_handler_);
  EXPECT_CALL(event_handler_,
              OnDriverFailure(Service::kFailureBadPassphrase, _));
  ExpectEndReasonMetricsReported(Service::kFailureBadPassphrase);
  driver_->FailService(Service::kFailureBadPassphrase);  // Trigger Cleanup.
  EXPECT_TRUE(IsPSKFileCleared(psk_file));
  EXPECT_TRUE(IsXauthCredentialsFileCleared(xauth_credentials_file));
  EXPECT_FALSE(driver_->event_handler_);
  EXPECT_FALSE(driver_->external_task_);

  SetEventHandler(&event_handler_);
  ExpectEndReasonMetricsReported(Service::kFailureDisconnect);
  driver_->Disconnect();
  EXPECT_FALSE(driver_->event_handler_);
}

TEST_F(L2TPIPsecDriverTest, DeleteTemporaryFiles) {
  base::FilePath psk_file = SetupPSKFile();
  base::FilePath xauth_credentials_file = SetupXauthCredentialsFile();
  driver_->DeleteTemporaryFiles();
  EXPECT_TRUE(IsPSKFileCleared(psk_file));
  EXPECT_TRUE(IsXauthCredentialsFileCleared(xauth_credentials_file));
}

TEST_F(L2TPIPsecDriverTest, InitOptionsNoHost) {
  Error error;
  std::vector<std::string> options;
  EXPECT_FALSE(driver_->InitOptions(&options, &error));
  EXPECT_EQ(Error::kInvalidArguments, error.type());
  EXPECT_TRUE(options.empty());
}

TEST_F(L2TPIPsecDriverTest, InitOptions) {
  static const char kHost[] = "192.168.2.254";
  static const char kPSK[] = "foobar";
  static const char kXauthUser[] = "silly";
  static const char kXauthPassword[] = "rabbit";
  const std::vector<std::string> kCaCertPEM{"Insert PEM encoded data here"};
  static const char kPEMCertfile[] = "/tmp/der-file-from-pem-cert";
  base::FilePath pem_cert(kPEMCertfile);

  SetArg(kProviderHostProperty, kHost);
  SetArg(kL2TPIPsecPskProperty, kPSK);
  SetArg(kL2TPIPsecXauthUserProperty, kXauthUser);
  SetArg(kL2TPIPsecXauthPasswordProperty, kXauthPassword);
  SetArgArray(kL2TPIPsecCaCertPemProperty, kCaCertPEM);

  EXPECT_CALL(*certificate_file_, CreatePEMFromStrings(kCaCertPEM))
      .WillOnce(Return(pem_cert));
  const base::FilePath temp_dir(temp_dir_.GetPath());
  // Once each for PSK and Xauth options.
  EXPECT_CALL(manager_, run_path())
      .WillOnce(ReturnRef(temp_dir))
      .WillOnce(ReturnRef(temp_dir));

  Error error;
  std::vector<std::string> options;
  EXPECT_TRUE(driver_->InitOptions(&options, &error));
  EXPECT_TRUE(error.IsSuccess());

  ExpectInFlags(options, "--remote_host", kHost);
  ASSERT_FALSE(driver_->psk_file_.empty());
  ExpectInFlags(options, "--psk_file", driver_->psk_file_.value());
  ASSERT_FALSE(driver_->xauth_credentials_file_.empty());
  ExpectInFlags(options, "--xauth_credentials_file",
                driver_->xauth_credentials_file_.value());
  ExpectInFlags(options, "--server_ca_file", kPEMCertfile);
}

TEST_F(L2TPIPsecDriverTest, InitPSKOptions) {
  Error error;
  std::vector<std::string> options;
  static const char kPSK[] = "foobar";
  const base::FilePath bad_dir("/non/existent/directory");
  const base::FilePath temp_dir(temp_dir_.GetPath());
  EXPECT_CALL(manager_, run_path())
      .WillOnce(ReturnRef(bad_dir))
      .WillOnce(ReturnRef(temp_dir));

  EXPECT_TRUE(driver_->InitPSKOptions(&options, &error));
  EXPECT_TRUE(options.empty());
  EXPECT_TRUE(error.IsSuccess());

  SetArg(kL2TPIPsecPskProperty, kPSK);

  EXPECT_FALSE(driver_->InitPSKOptions(&options, &error));
  EXPECT_TRUE(options.empty());
  EXPECT_EQ(Error::kInternalError, error.type());
  error.Reset();

  EXPECT_TRUE(driver_->InitPSKOptions(&options, &error));
  ASSERT_FALSE(driver_->psk_file_.empty());
  ExpectInFlags(options, "--psk_file", driver_->psk_file_.value());
  EXPECT_TRUE(error.IsSuccess());
  std::string contents;
  EXPECT_TRUE(base::ReadFileToString(driver_->psk_file_, &contents));
  EXPECT_EQ(kPSK, contents);
  struct stat buf;
  ASSERT_EQ(0, stat(driver_->psk_file_.value().c_str(), &buf));
  EXPECT_EQ(S_IFREG | S_IRUSR | S_IRGRP, buf.st_mode);
}

TEST_F(L2TPIPsecDriverTest, InitPEMOptions) {
  const std::vector<std::string> kCaCertPEM{"Insert PEM encoded data here"};
  static const char kPEMCertfile[] = "/tmp/der-file-from-pem-cert";
  base::FilePath empty_cert;
  base::FilePath pem_cert(kPEMCertfile);
  SetArgArray(kL2TPIPsecCaCertPemProperty, kCaCertPEM);
  EXPECT_CALL(*certificate_file_, CreatePEMFromStrings(kCaCertPEM))
      .WillOnce(Return(empty_cert))
      .WillOnce(Return(pem_cert));

  std::vector<std::string> options;
  driver_->InitPEMOptions(&options);
  EXPECT_TRUE(options.empty());
  driver_->InitPEMOptions(&options);
  ExpectInFlags(options, "--server_ca_file", kPEMCertfile);
}

TEST_F(L2TPIPsecDriverTest, InitXauthOptions) {
  std::vector<std::string> options;
  EXPECT_CALL(manager_, run_path()).Times(0);
  {
    Error error;
    EXPECT_TRUE(driver_->InitXauthOptions(&options, &error));
    EXPECT_TRUE(error.IsSuccess());
  }
  EXPECT_TRUE(options.empty());

  static const char kUser[] = "foobar";
  SetArg(kL2TPIPsecXauthUserProperty, kUser);
  {
    Error error;
    EXPECT_FALSE(driver_->InitXauthOptions(&options, &error));
    EXPECT_EQ(Error::kInvalidArguments, error.type());
  }
  EXPECT_TRUE(options.empty());

  static const char kPassword[] = "foobar";
  SetArg(kL2TPIPsecXauthUserProperty, "");
  SetArg(kL2TPIPsecXauthPasswordProperty, kPassword);
  {
    Error error;
    EXPECT_FALSE(driver_->InitXauthOptions(&options, &error));
    EXPECT_EQ(Error::kInvalidArguments, error.type());
  }
  EXPECT_TRUE(options.empty());
  Mock::VerifyAndClearExpectations(&manager_);

  SetArg(kL2TPIPsecXauthUserProperty, kUser);
  const base::FilePath bad_dir("/non/existent/directory");
  const base::FilePath temp_dir(temp_dir_.GetPath());
  EXPECT_CALL(manager_, run_path())
      .WillOnce(ReturnRef(bad_dir))
      .WillOnce(ReturnRef(temp_dir));

  {
    Error error;
    EXPECT_FALSE(driver_->InitXauthOptions(&options, &error));
    EXPECT_EQ(Error::kInternalError, error.type());
  }
  EXPECT_TRUE(options.empty());

  {
    Error error;
    EXPECT_TRUE(driver_->InitXauthOptions(&options, &error));
    EXPECT_TRUE(error.IsSuccess());
  }
  ASSERT_FALSE(driver_->xauth_credentials_file_.empty());
  ExpectInFlags(options, "--xauth_credentials_file",
                driver_->xauth_credentials_file_.value());
  std::string contents;
  EXPECT_TRUE(
      base::ReadFileToString(driver_->xauth_credentials_file_, &contents));
  std::string expected_contents(std::string(kUser) + "\n" + kPassword + "\n");
  EXPECT_EQ(expected_contents, contents);
  struct stat buf;
  ASSERT_EQ(0, stat(driver_->xauth_credentials_file_.value().c_str(), &buf));
  EXPECT_EQ(S_IFREG | S_IRUSR | S_IRGRP, buf.st_mode);
}

TEST_F(L2TPIPsecDriverTest, AppendValueOption) {
  static const char kOption[] = "--l2tpipsec-option";
  static const char kProperty[] = "L2TPIPsec.SomeProperty";
  static const char kValue[] = "some-property-value";
  static const char kOption2[] = "--l2tpipsec-option2";
  static const char kProperty2[] = "L2TPIPsec.SomeProperty2";
  static const char kValue2[] = "some-property-value2";

  std::vector<std::string> options;
  EXPECT_FALSE(driver_->AppendValueOption("L2TPIPsec.UnknownProperty", kOption,
                                          &options));
  EXPECT_TRUE(options.empty());

  SetArg(kProperty, "");
  EXPECT_FALSE(driver_->AppendValueOption(kProperty, kOption, &options));
  EXPECT_TRUE(options.empty());

  SetArg(kProperty, kValue);
  SetArg(kProperty2, kValue2);
  EXPECT_TRUE(driver_->AppendValueOption(kProperty, kOption, &options));
  EXPECT_TRUE(driver_->AppendValueOption(kProperty2, kOption2, &options));
  EXPECT_EQ(2, options.size());
  EXPECT_EQ(base::StringPrintf("%s=%s", kOption, kValue), options[0]);
  EXPECT_EQ(base::StringPrintf("%s=%s", kOption2, kValue2), options[1]);
}

TEST_F(L2TPIPsecDriverTest, AppendFlag) {
  static const char kTrueOption[] = "--l2tpipsec-option";
  static const char kFalseOption[] = "--nol2tpipsec-option";
  static const char kProperty[] = "L2TPIPsec.SomeProperty";
  static const char kTrueOption2[] = "--l2tpipsec-option2";
  static const char kFalseOption2[] = "--nol2tpipsec-option2";
  static const char kProperty2[] = "L2TPIPsec.SomeProperty2";

  std::vector<std::string> options;
  EXPECT_FALSE(driver_->AppendFlag("L2TPIPsec.UnknownProperty", kTrueOption,
                                   kFalseOption, &options));
  EXPECT_TRUE(options.empty());

  SetArg(kProperty, "");
  EXPECT_FALSE(
      driver_->AppendFlag(kProperty, kTrueOption, kFalseOption, &options));
  EXPECT_TRUE(options.empty());

  SetArg(kProperty, "true");
  SetArg(kProperty2, "false");
  EXPECT_TRUE(
      driver_->AppendFlag(kProperty, kTrueOption, kFalseOption, &options));
  EXPECT_TRUE(
      driver_->AppendFlag(kProperty2, kTrueOption2, kFalseOption2, &options));
  EXPECT_EQ(2, options.size());
  EXPECT_EQ(kTrueOption, options[0]);
  EXPECT_EQ(kFalseOption2, options[1]);
}

TEST_F(L2TPIPsecDriverTest, GetLogin) {
  static const char kUser[] = "joesmith";
  static const char kPassword[] = "random-password";
  std::string user, password;
  SetArg(kL2TPIPsecUserProperty, kUser);
  SetArg(kL2TPIPsecUseLoginPasswordProperty, "false");
  driver_->GetLogin(&user, &password);
  EXPECT_TRUE(user.empty());
  EXPECT_TRUE(password.empty());
  SetArg(kL2TPIPsecUserProperty, "");
  SetArg(kL2TPIPsecPasswordProperty, kPassword);
  driver_->GetLogin(&user, &password);
  EXPECT_TRUE(user.empty());
  EXPECT_TRUE(password.empty());
  SetArg(kL2TPIPsecUserProperty, kUser);
  driver_->GetLogin(&user, &password);
  EXPECT_EQ(kUser, user);
  EXPECT_EQ(kPassword, password);
}

TEST_F(L2TPIPsecDriverTest, UseLoginPassword) {
  static const char kUser[] = "joesmith";
  static const char kPassword[] = "random-password";
  std::string user, password;
  SetArg(kL2TPIPsecUserProperty, kUser);
  SetArg(kL2TPIPsecUseLoginPasswordProperty, "true");
  driver_->GetLogin(&user, &password);
  EXPECT_TRUE(user.empty());
  EXPECT_TRUE(password.empty());
  SaveLoginPassword(kPassword);
  driver_->GetLogin(&user, &password);
  EXPECT_EQ(kUser, user);
  EXPECT_EQ(kPassword, password);
}

TEST_F(L2TPIPsecDriverTest, OnL2TPIPsecVPNDied) {
  const int kPID = 123456;
  SetEventHandler(&event_handler_);
  EXPECT_CALL(event_handler_, OnDriverFailure(Service::kFailureDNSLookup, _));
  ExpectEndReasonMetricsReported(Service::kFailureDNSLookup);
  driver_->OnL2TPIPsecVPNDied(kPID,
                              vpn_manager::kServiceErrorResolveHostnameFailed);
  EXPECT_FALSE(driver_->event_handler_);
}

TEST_F(L2TPIPsecDriverTest, SpawnL2TPIPsecVPN) {
  Error error;
  // Fail without sufficient arguments.
  EXPECT_FALSE(driver_->SpawnL2TPIPsecVPN(&error));
  EXPECT_TRUE(error.IsFailure());

  // Provide the required arguments.
  static const char kHost[] = "192.168.2.254";
  SetArg(kProviderHostProperty, kHost);

  EXPECT_CALL(process_manager_,
              StartProcessInMinijail(
                  _, _, _, _, MinijailOptionsMatchCloseNonstdFDs(true), _))
      .WillOnce(Return(-1))
      .WillOnce(Return(1));

  EXPECT_FALSE(driver_->SpawnL2TPIPsecVPN(&error));
  EXPECT_FALSE(driver_->external_task_);
  EXPECT_TRUE(driver_->SpawnL2TPIPsecVPN(&error));
  EXPECT_NE(nullptr, driver_->external_task_);
}

TEST_F(L2TPIPsecDriverTest, Connect) {
  static const char kHost[] = "192.168.2.254";
  SetArg(kProviderHostProperty, kHost);

  EXPECT_CALL(process_manager_,
              StartProcessInMinijail(
                  _, _, _, _, MinijailOptionsMatchCloseNonstdFDs(true), _))
      .WillOnce(Return(1));
  base::TimeDelta timeout = driver_->ConnectAsync(&event_handler_);
  EXPECT_NE(timeout, VPNDriver::kTimeoutNone);
}

TEST_F(L2TPIPsecDriverTest, Disconnect) {
  SetEventHandler(&event_handler_);
  ExpectEndReasonMetricsReported(Service::kFailureDisconnect);
  driver_->Disconnect();
  EXPECT_FALSE(driver_->event_handler_);
}

TEST_F(L2TPIPsecDriverTest, OnConnectTimeout) {
  SetEventHandler(&event_handler_);
  EXPECT_CALL(event_handler_, OnDriverFailure(Service::kFailureConnect, _));
  ExpectEndReasonMetricsReported(Service::kFailureConnect);
  driver_->OnConnectTimeout();
  EXPECT_FALSE(driver_->event_handler_);
}

TEST_F(L2TPIPsecDriverTest, InitPropertyStore) {
  // Quick test property store initialization.
  PropertyStore store;
  driver_->InitPropertyStore(&store);
  const std::string kUser = "joe";
  Error error;
  store.SetStringProperty(kL2TPIPsecUserProperty, kUser, &error);
  EXPECT_TRUE(error.IsSuccess());
  EXPECT_EQ(kUser, GetArgs()->Lookup<std::string>(kL2TPIPsecUserProperty, ""));
}

TEST_F(L2TPIPsecDriverTest, GetProvider) {
  PropertyStore store;
  driver_->InitPropertyStore(&store);
  {
    KeyValueStore props;
    Error error;
    SetArg(kL2TPIPsecClientCertIdProperty, "");
    EXPECT_TRUE(
        store.GetKeyValueStoreProperty(kProviderProperty, &props, &error));
    EXPECT_TRUE(props.Lookup<bool>(kPassphraseRequiredProperty, false));
    EXPECT_TRUE(props.Lookup<bool>(kL2TPIPsecPskRequiredProperty, false));
  }
  {
    KeyValueStore props;
    Error error;
    SetArg(kL2TPIPsecClientCertIdProperty, "some-cert-id");
    EXPECT_TRUE(
        store.GetKeyValueStoreProperty(kProviderProperty, &props, &error));
    EXPECT_TRUE(props.Lookup<bool>(kPassphraseRequiredProperty, false));
    EXPECT_FALSE(props.Lookup<bool>(kL2TPIPsecPskRequiredProperty, true));
    SetArg(kL2TPIPsecClientCertIdProperty, "");
  }
  {
    KeyValueStore props;
    SetArg(kL2TPIPsecPasswordProperty, "random-password");
    SetArg(kL2TPIPsecPskProperty, "random-psk");
    Error error;
    EXPECT_TRUE(
        store.GetKeyValueStoreProperty(kProviderProperty, &props, &error));
    EXPECT_FALSE(props.Lookup<bool>(kPassphraseRequiredProperty, true));
    EXPECT_FALSE(props.Lookup<bool>(kL2TPIPsecPskRequiredProperty, true));
    EXPECT_FALSE(props.Contains<std::string>(kL2TPIPsecPasswordProperty));
  }
}

TEST_F(L2TPIPsecDriverTest, Notify) {
  std::map<std::string, std::string> config{
      {kPPPInterfaceName, kInterfaceName}};
  base::FilePath psk_file;
  base::FilePath xauth_credentials_file;
  FakeUpConnect(&psk_file, &xauth_credentials_file);

  // Make sure that a notification of an intermediate state doesn't cause
  // the driver to fail the connection.
  EXPECT_CALL(event_handler_, OnDriverConnected(_, _)).Times(0);
  EXPECT_CALL(event_handler_, OnDriverFailure(_, _)).Times(0);
  EXPECT_TRUE(driver_->event_handler_);
  InvokeNotify(kPPPReasonAuthenticating, config);
  EXPECT_TRUE(driver_->event_handler_);
  InvokeNotify(kPPPReasonAuthenticated, config);
  EXPECT_TRUE(driver_->event_handler_);

  ExpectMetricsReported();
  EXPECT_CALL(event_handler_,
              OnDriverConnected(kInterfaceName, kInterfaceIndex));
  EXPECT_CALL(device_info_, GetIndex(kInterfaceName))
      .WillOnce(Return(kInterfaceIndex));
  InvokeNotify(kPPPReasonConnect, config);
  EXPECT_TRUE(IsPSKFileCleared(psk_file));
  EXPECT_TRUE(IsXauthCredentialsFileCleared(xauth_credentials_file));
}

TEST_F(L2TPIPsecDriverTest, NotifyWithoutDeviceInfoReady) {
  std::map<std::string, std::string> config{
      {kPPPInterfaceName, kInterfaceName}};
  base::FilePath psk_file;
  base::FilePath xauth_credentials_file;
  FakeUpConnect(&psk_file, &xauth_credentials_file);
  DeviceInfo::LinkReadyCallback link_ready_callback;
  EXPECT_CALL(event_handler_, OnDriverConnected(_, _)).Times(0);
  EXPECT_CALL(device_info_, GetIndex(kInterfaceName)).WillOnce(Return(-1));
  EXPECT_CALL(device_info_, AddVirtualInterfaceReadyCallback(kInterfaceName, _))
      .WillOnce([&link_ready_callback](const std::string&,
                                       DeviceInfo::LinkReadyCallback callback) {
        link_ready_callback = std::move(callback);
      });
  InvokeNotify(kPPPReasonConnect, config);

  EXPECT_CALL(event_handler_,
              OnDriverConnected(kInterfaceName, kInterfaceIndex));
  std::move(link_ready_callback).Run(kInterfaceName, kInterfaceIndex);
}

TEST_F(L2TPIPsecDriverTest, NotifyDisconnected) {
  std::map<std::string, std::string> dict;
  SetEventHandler(&event_handler_);
  base::Callback<void(pid_t, int)> death_callback;
  MockExternalTask* local_external_task = new MockExternalTask(
      &control_, &process_manager_, weak_factory_.GetWeakPtr(), death_callback);
  driver_->external_task_.reset(local_external_task);  // passes ownership
  EXPECT_CALL(event_handler_, OnDriverFailure(_, _));
  ExpectEndReasonMetricsReported(Service::kFailureUnknown);
  EXPECT_CALL(*local_external_task, OnDelete());
  driver_->Notify(kPPPReasonDisconnect, dict);
  EXPECT_EQ(nullptr, driver_->external_task_);
}

}  // namespace shill
