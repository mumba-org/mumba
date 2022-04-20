// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_VPN_OPENVPN_DRIVER_H_
#define SHILL_VPN_OPENVPN_DRIVER_H_

#include <map>
#include <memory>
#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <gtest/gtest_prod.h>  // for FRIEND_TEST

#include "shill/ipconfig.h"
#include "shill/net/sockets.h"
#include "shill/rpc_task.h"
#include "shill/vpn/vpn_driver.h"
#include "shill/vpn/vpn_util.h"

namespace shill {

class CertificateFile;
class Error;
class OpenVPNManagementServer;

class OpenVPNDriver : public VPNDriver, public RpcTaskDelegate {
 public:
  enum ReconnectReason {
    kReconnectReasonUnknown,
    kReconnectReasonOffline,
    kReconnectReasonTLSError,
  };

  OpenVPNDriver(Manager* manager, ProcessManager* process_manager);
  OpenVPNDriver(const OpenVPNDriver&) = delete;
  OpenVPNDriver& operator=(const OpenVPNDriver&) = delete;

  ~OpenVPNDriver() override;

  // Inherited from VPNDriver. This driver first creates a tunnel interface
  // via DeviceInfo, and then sets up and spawns an external 'openvpn' process.
  // IP configuration settings are passed back from the external process through
  // the |Notify| RPC service method.
  base::TimeDelta ConnectAsync(EventHandler* handler) override;
  void Disconnect() override;
  IPConfig::Properties GetIPProperties() const override;
  std::string GetProviderType() const override;
  void OnConnectTimeout() override;
  void OnDefaultPhysicalServiceEvent(
      DefaultPhysicalServiceEvent event) override;

  virtual void OnReconnecting(ReconnectReason reason);

  // Resets the VPN state and deallocates all resources. If there's a service
  // associated through Connect, notifies it to sets its state to
  // Service::kStateFailure, sets the failure reason to |failure|, sets its
  // ErrorDetails property to |error_details|, and disassociates from the
  // service.
  virtual void FailService(Service::ConnectFailure failure,
                           const std::string& error_details);

  // Append zero-valued, single-valued and double-valued options to the
  // |options| array.
  static void AppendOption(const std::string& option,
                           std::vector<std::vector<std::string>>* options);
  static void AppendOption(const std::string& option,
                           const std::string& value,
                           std::vector<std::vector<std::string>>* options);
  static void AppendOption(const std::string& option,
                           const std::string& value0,
                           const std::string& value1,
                           std::vector<std::vector<std::string>>* options);

  // Appends remote option to the |options| array.
  void AppendRemoteOption(const std::string& host,
                          std::vector<std::vector<std::string>>* options);

  // Returns true if an option was appended.
  bool AppendValueOption(const std::string& property,
                         const std::string& option,
                         std::vector<std::vector<std::string>>* options);

  // If |property| exists, split its value up using |delimiter|.  Each element
  // will be a separate argument to |option|. Returns true if the option was
  // appended to |options|.
  bool AppendDelimitedValueOption(
      const std::string& property,
      const std::string& option,
      char delimiter,
      std::vector<std::vector<std::string>>* options);

  // Returns true if a flag was appended.
  bool AppendFlag(const std::string& property,
                  const std::string& option,
                  std::vector<std::vector<std::string>>* options);

  virtual void ReportCipherMetrics(const std::string& cipher);

 private:
  friend class OpenVPNDriverTest;
  FRIEND_TEST(OpenVPNDriverTest, Cleanup);
  FRIEND_TEST(OpenVPNDriverTest, ConnectAsync);
  FRIEND_TEST(OpenVPNDriverTest, ConnectTunnelFailure);
  FRIEND_TEST(OpenVPNDriverTest, Disconnect);
  FRIEND_TEST(OpenVPNDriverTest, GetCommandLineArgs);
  FRIEND_TEST(OpenVPNDriverTest, GetRouteOptionEntry);
  FRIEND_TEST(OpenVPNDriverTest, InitCAOptions);
  FRIEND_TEST(OpenVPNDriverTest, InitCertificateVerifyOptions);
  FRIEND_TEST(OpenVPNDriverTest, InitClientAuthOptions);
  FRIEND_TEST(OpenVPNDriverTest, InitExtraCertOptions);
  FRIEND_TEST(OpenVPNDriverTest, InitLoggingOptions);
  FRIEND_TEST(OpenVPNDriverTest, InitOptions);
  FRIEND_TEST(OpenVPNDriverTest, InitOptionsAdvanced);
  FRIEND_TEST(OpenVPNDriverTest, InitOptionsHostWithExtraHosts);
  FRIEND_TEST(OpenVPNDriverTest, InitOptionsHostWithPort);
  FRIEND_TEST(OpenVPNDriverTest, InitOptionsNoHost);
  FRIEND_TEST(OpenVPNDriverTest, InitOptionsNoPrimaryHost);
  FRIEND_TEST(OpenVPNDriverTest, InitPKCS11Options);
  FRIEND_TEST(OpenVPNDriverTest, Notify);
  FRIEND_TEST(OpenVPNDriverTest, NotifyUMA);
  FRIEND_TEST(OpenVPNDriverTest, NotifyFail);
  FRIEND_TEST(OpenVPNDriverTest, OnConnectTimeout);
  FRIEND_TEST(OpenVPNDriverTest, OnConnectTimeoutResolve);
  FRIEND_TEST(OpenVPNDriverTest, OnDefaultPhysicalServiceEvent);
  FRIEND_TEST(OpenVPNDriverTest, OnOpenVPNDied);
  FRIEND_TEST(OpenVPNDriverTest, ParseForeignOption);
  FRIEND_TEST(OpenVPNDriverTest, ParseForeignOptions);
  FRIEND_TEST(OpenVPNDriverTest, ParseIPConfiguration);
  FRIEND_TEST(OpenVPNDriverTest, ParseRouteOption);
  FRIEND_TEST(OpenVPNDriverTest, SetRoutes);
  FRIEND_TEST(OpenVPNDriverTest, SpawnOpenVPN);
  FRIEND_TEST(OpenVPNDriverTest, SplitPortFromHost);
  FRIEND_TEST(OpenVPNDriverTest, WriteConfigFile);

  // The map is a sorted container that allows us to iterate through the options
  // in order.
  using ForeignOptions = std::map<int, std::string>;
  using RouteOptions = std::map<int, IPConfig::Route>;

  static const char kDefaultCACertificates[];

  static const char kOpenVPNPath[];
  static const char kOpenVPNScript[];
  static const Property kProperties[];

  static const char kLSBReleaseFile[];

  static const char kDefaultOpenVPNConfigurationDirectory[];

  static constexpr base::TimeDelta kConnectTimeout = base::Minutes(2);
  static constexpr base::TimeDelta kReconnectOfflineTimeout = base::Minutes(2);
  static constexpr base::TimeDelta kReconnectTLSErrorTimeout =
      base::Seconds(20);

  static void ParseForeignOptions(const ForeignOptions& options,
                                  IPConfig::Properties* properties);
  static void ParseForeignOption(const std::string& option,
                                 std::vector<std::string>* domain_search,
                                 std::vector<std::string>* dns_servers);
  static IPConfig::Route* GetRouteOptionEntry(const std::string& prefix,
                                              const std::string& key,
                                              RouteOptions* routes);
  static void ParseRouteOption(const std::string& key,
                               const std::string& value,
                               RouteOptions* routes);
  static void SetRoutes(const RouteOptions& routes,
                        IPConfig::Properties* properties);

  // If |host| is in the "name:port" format, sets up |name| and |port|
  // appropriately and returns true. Otherwise, returns false.
  static bool SplitPortFromHost(const std::string& host,
                                std::string* name,
                                std::string* port);

  void InitOptions(std::vector<std::vector<std::string>>* options,
                   Error* error);
  bool InitCAOptions(std::vector<std::vector<std::string>>* options,
                     Error* error);
  void InitCertificateVerifyOptions(
      std::vector<std::vector<std::string>>* options);
  void InitClientAuthOptions(std::vector<std::vector<std::string>>* options);
  bool InitExtraCertOptions(std::vector<std::vector<std::string>>* options,
                            Error* error);
  void InitPKCS11Options(std::vector<std::vector<std::string>>* options);
  bool InitManagementChannelOptions(
      std::vector<std::vector<std::string>>* options, Error* error);
  void InitLoggingOptions(std::vector<std::vector<std::string>>* options);

  std::vector<std::string> GetCommandLineArgs();
  void ParseIPConfiguration(
      const std::map<std::string, std::string>& configuration,
      IPConfig::Properties* properties) const;

  void OnLinkReady(const std::string& link_name, int interface_index);

  bool SpawnOpenVPN();

  // Called by public Disconnect and FailService methods. Resets the VPN
  // state and deallocates all resources.
  void Cleanup();

  static base::TimeDelta GetReconnectTimeout(ReconnectReason reason);

  // Join a list of options into a single string.
  static std::string JoinOptions(
      const std::vector<std::vector<std::string>>& options, char separator);

  // Output an OpenVPN configuration.
  bool WriteConfigFile(const std::vector<std::vector<std::string>>& options,
                       base::FilePath* config_file);

  // Called when the openpvn process exits.
  void OnOpenVPNDied(int exit_status);

  // Inherit from VPNDriver to add custom properties.
  KeyValueStore GetProvider(Error* error) override;

  // Implements RpcTaskDelegate.
  void GetLogin(std::string* user, std::string* password) override;
  void Notify(const std::string& reason,
              const std::map<std::string, std::string>& dict) override;

  void ReportConnectionMetrics();

  Sockets sockets_;
  std::unique_ptr<OpenVPNManagementServer> management_server_;
  std::unique_ptr<CertificateFile> certificate_file_;
  std::unique_ptr<CertificateFile> extra_certificates_file_;
  base::FilePath lsb_release_file_;

  std::unique_ptr<RpcTask> rpc_task_;
  base::FilePath tls_auth_file_;
  base::FilePath openvpn_config_directory_;
  base::FilePath openvpn_config_file_;
  IPConfig::Properties ip_properties_;

  // The PID of the spawned openvpn process. May be 0 if no process has been
  // spawned yet or the process has died.
  int pid_;

  std::string interface_name_;
  int interface_index_ = -1;

  EventHandler* event_handler_ = nullptr;
  std::unique_ptr<VPNUtil> vpn_util_;

  base::WeakPtrFactory<OpenVPNDriver> weak_factory_{this};
};

}  // namespace shill

#endif  // SHILL_VPN_OPENVPN_DRIVER_H_
