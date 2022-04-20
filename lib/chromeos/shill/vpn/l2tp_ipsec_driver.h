// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_VPN_L2TP_IPSEC_DRIVER_H_
#define SHILL_VPN_L2TP_IPSEC_DRIVER_H_

#include <sys/types.h>

#include <map>
#include <memory>
#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <gtest/gtest_prod.h>  // for FRIEND_TEST
#include <libpasswordprovider/password_provider.h>

#include "shill/ipconfig.h"
#include "shill/rpc_task.h"
#include "shill/vpn/ipsec_connection.h"
#include "shill/vpn/vpn_driver.h"
#include "shill/vpn/vpn_util.h"

namespace shill {

class CertificateFile;
class ExternalTask;

class L2TPIPsecDriver : public VPNDriver, public RpcTaskDelegate {
 public:
  // Parses the output of `stroke statusall` and gets cipher suites used by this
  // connection. Returns whether the metrics should be reported. This function
  // is supposed to only be used in this class. Make it static for testing.
  static bool ParseStrokeStatusAllOutput(
      const std::string& stroke_output,
      IPsecConnection::CipherSuite* ike_cipher,
      IPsecConnection::CipherSuite* esp_cipher);

  L2TPIPsecDriver(Manager* manager, ProcessManager* process_manager);
  L2TPIPsecDriver(const L2TPIPsecDriver&) = delete;
  L2TPIPsecDriver& operator=(const L2TPIPsecDriver&) = delete;

  ~L2TPIPsecDriver() override;

  // Inherited from VPNDriver.
  base::TimeDelta ConnectAsync(EventHandler* handler) override;
  void Disconnect() override;
  IPConfig::Properties GetIPProperties() const override;
  std::string GetProviderType() const override;
  void OnConnectTimeout() override;

  // Disconnects from the VPN service before suspend or when the current default
  // physical service becomes unavailable. The reconnection behavior relies on
  // whether the user sets "Automatically connect to this network".
  void OnBeforeSuspend(const ResultCallback& callback) override;
  void OnDefaultPhysicalServiceEvent(
      DefaultPhysicalServiceEvent event) override;

 private:
  friend class L2TPIPsecDriverTest;
  FRIEND_TEST(L2TPIPsecDriverTest, AppendFlag);
  FRIEND_TEST(L2TPIPsecDriverTest, AppendValueOption);
  FRIEND_TEST(L2TPIPsecDriverTest, Cleanup);
  FRIEND_TEST(L2TPIPsecDriverTest, Connect);
  FRIEND_TEST(L2TPIPsecDriverTest, DeleteTemporaryFiles);
  FRIEND_TEST(L2TPIPsecDriverTest, Disconnect);
  FRIEND_TEST(L2TPIPsecDriverTest, GetLogin);
  FRIEND_TEST(L2TPIPsecDriverTest, InitOptions);
  FRIEND_TEST(L2TPIPsecDriverTest, InitOptionsNoHost);
  FRIEND_TEST(L2TPIPsecDriverTest, InitPEMOptions);
  FRIEND_TEST(L2TPIPsecDriverTest, InitPSKOptions);
  FRIEND_TEST(L2TPIPsecDriverTest, InitXauthOptions);
  FRIEND_TEST(L2TPIPsecDriverTest, Notify);
  FRIEND_TEST(L2TPIPsecDriverTest, NotifyWithExistingDevice);
  FRIEND_TEST(L2TPIPsecDriverTest, NotifyDisconnected);
  FRIEND_TEST(L2TPIPsecDriverTest, OnConnectTimeout);
  FRIEND_TEST(L2TPIPsecDriverTest, OnL2TPIPsecVPNDied);
  FRIEND_TEST(L2TPIPsecDriverTest, SpawnL2TPIPsecVPN);
  FRIEND_TEST(L2TPIPsecDriverTest, UseLoginPassword);

  static const char kL2TPIPsecVPNPath[];
  static const Property kProperties[];

  bool SpawnL2TPIPsecVPN(Error* error);

  bool InitOptions(std::vector<std::string>* options, Error* error);
  bool InitPSKOptions(std::vector<std::string>* options, Error* error);
  bool InitPEMOptions(std::vector<std::string>* options);
  bool InitXauthOptions(std::vector<std::string>* options, Error* error);

  // Resets the VPN state and deallocates all resources. If there's a service
  // associated through Connect, notifies it to sets its state to
  // Service::kStateFailure, sets the failure reason to |failure|, sets its
  // ErrorDetails property to |error_details|, and disassociates from the
  // service.
  void FailService(Service::ConnectFailure failure);

  // Called by public Disconnect and FailService methods. Resets the VPN
  // state and deallocates all resources.
  void Cleanup();

  void DeleteTemporaryFile(base::FilePath* temporary_file);
  void DeleteTemporaryFiles();

  // Returns true if an opton was appended.
  bool AppendValueOption(const std::string& property,
                         const std::string& option,
                         std::vector<std::string>* options);

  // Returns true if a flag was appended.
  bool AppendFlag(const std::string& property,
                  const std::string& true_option,
                  const std::string& false_option,
                  std::vector<std::string>* options);

  // Returns true if neither a PSK nor a client certificate has been provided
  // for the IPsec phase of the authentication process.
  bool IsPskRequired() const;

  // Inherit from VPNDriver to add custom properties.
  KeyValueStore GetProvider(Error* error) override;

  // Implements RpcTaskDelegate.
  void GetLogin(std::string* user, std::string* password) override;
  void Notify(const std::string& reason,
              const std::map<std::string, std::string>& dict) override;
  // Called when the l2tpipsec_vpn process exits.
  void OnL2TPIPsecVPNDied(pid_t pid, int status);

  void OnLinkReady(const std::string& link_name, int interface_index);

  void ReportConnectionMetrics();

  // Parses the output of `stroke statusall` to get the cipher suites used by
  // this connection, and reports them.
  void ParseCipherSuitesAndReport(int exit_status,
                                  const std::string& stdout_str);

  std::unique_ptr<ExternalTask> external_task_;
  base::FilePath psk_file_;
  base::FilePath xauth_credentials_file_;
  std::unique_ptr<CertificateFile> certificate_file_;
  IPConfig::Properties ip_properties_;
  EventHandler* event_handler_ = nullptr;
  std::unique_ptr<password_provider::PasswordProviderInterface>
      password_provider_;
  std::unique_ptr<VPNUtil> vpn_util_;

  base::WeakPtrFactory<L2TPIPsecDriver> weak_factory_{this};
};

}  // namespace shill

#endif  // SHILL_VPN_L2TP_IPSEC_DRIVER_H_
