// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_VPN_IPSEC_CONNECTION_H_
#define SHILL_VPN_IPSEC_CONNECTION_H_

#include <memory>
#include <optional>
#include <string>
#include <tuple>
#include <vector>

#include <base/callback.h>
#include <base/files/file_path.h>
#include <base/files/file_path_watcher.h>
#include <base/files/scoped_temp_dir.h>

#include "shill/certificate_file.h"
#include "shill/device_info.h"
#include "shill/metrics.h"
#include "shill/mockable.h"
#include "shill/process_manager.h"
#include "shill/service.h"
#include "shill/vpn/vpn_connection.h"
#include "shill/vpn/vpn_util.h"

namespace shill {

// IPsecConnection manages the IPsec connection by starting charon process and
// taking to it via swanctl.
// When connecting, IPsecConnection will do the following steps to initiate the
// IPsec connection:
// - Create a temp dir in `/run/ipsec/` to store all the configuration files;
// - Generate strongswan.conf in the created temp dir;
// - Start charon process which is the IKE daemon;
// - Generate swanctl.conf in the created temp dir;
// - Invoke swanctl to let charon load the configurations in swanctl.conf;
// - Invoke swanctl to initiate the connection;
// - Invoke swanctl to read the needed information about this connection.
// TODO(b/165170125): Document temporary files.
class IPsecConnection : public VPNConnection {
 public:
  struct Config {
    enum class IKEVersion {
      kV1,
      kV2,
    };

    IKEVersion ike_version;

    // Remote hostname or IP address.
    std::string remote;

    // Fields required when using cert auth.
    std::optional<std::string> client_cert_id;
    std::optional<std::string> client_cert_slot;

    // Field required when using psk auth.
    std::optional<std::string> psk;

    // Username and password when using Xauth (the second round of
    // authentication in IKEv1) or EAP-MSCHAPv2 (IKEv2). Strongswan treats these
    // two kinds of authentication similarly in the secret section of the config
    // file so we use the same fields for them here.
    std::optional<std::string> xauth_user;
    std::optional<std::string> xauth_password;

    // Optional local (remote) identity.
    std::optional<std::string> local_id;
    std::optional<std::string> remote_id;

    // If set, authenticate server by CA cert.
    std::optional<std::vector<std::string>> ca_cert_pem_strings;

    // Cisco tunnel group name.
    std::optional<std::string> tunnel_group;

    // Protocol and port on the local/remote side. Should be in form of
    // "proto/port", e.g., "17/1701". For the valid values of proto and port,
    // see https://wiki.strongswan.org/projects/strongswan/wiki/Swanctlconf
    // Ignored if |ike_version| is set to kV2.
    std::string local_proto_port;
    std::string remote_proto_port;
  };

  // This enum is only used internally. It need to be public to be accessible in
  // tests. Each value represents an step in the connect procedure. Also see
  // ScheduleConnectTask().
  enum class ConnectStep {
    kStart,
    kStrongSwanConfigWritten,
    kSwanctlConfigWritten,
    kCharonStarted,
    kSwanctlConfigLoaded,
    kIPsecConnected,
    kIPsecStatusRead,
  };

  // Parses the cipher suite from an string output by swanctl or stroke. |input|
  // is like "AES_CBC-128/HMAC_SHA2_256_128/PRF_HMAC_SHA2_256/MODP_3072".
  using CipherSuite = std::tuple<Metrics::VpnIpsecEncryptionAlgorithm,
                                 Metrics::VpnIpsecIntegrityAlgorithm,
                                 Metrics::VpnIpsecDHGroup>;
  static CipherSuite ParseCipherSuite(const std::string& input);

  explicit IPsecConnection(std::unique_ptr<Config> config,
                           std::unique_ptr<Callbacks> callbacks,
                           std::unique_ptr<VPNConnection> l2tp_connection,
                           DeviceInfo* device_info,
                           EventDispatcher* dispatcher,
                           ProcessManager* process_manager);
  ~IPsecConnection();

  Metrics::VpnIpsecEncryptionAlgorithm ike_encryption_algo() const {
    return ike_encryption_algo_;
  }
  Metrics::VpnIpsecIntegrityAlgorithm ike_integrity_algo() const {
    return ike_integrity_algo_;
  }
  Metrics::VpnIpsecDHGroup ike_dh_group() const { return ike_dh_group_; }
  Metrics::VpnIpsecEncryptionAlgorithm esp_encryption_algo() const {
    return esp_encryption_algo_;
  }
  Metrics::VpnIpsecIntegrityAlgorithm esp_integrity_algo() const {
    return esp_integrity_algo_;
  }

 private:
  friend class IPsecConnectionUnderTest;

  using SwanctlCallback = base::OnceCallback<void(const std::string&)>;

  void OnConnect() override;
  void OnDisconnect() override;

  // Run tasks for connecting in order based on the current |step|.
  virtual void ScheduleConnectTask(ConnectStep step);

  // Tasks scheduled by ScheduleConnectTask(). Each function should call
  // ScheduleConnectTask() (either directly or using a callback) on the task
  // done, or call NoitfyFailure() to indicate a failure.

  // Generates strongswan.conf. On success, this function will trigger
  // |kStrongSwanConfigWritten| step and set |strongswan_conf_path_|.
  void WriteStrongSwanConfig();
  // Starts charon process with minijail. The charon process will create the
  // vici socket file and then listen on it. This function will trigger
  // |kCharonStarted| step after that socket it ready. |charon_pid_| will be set
  // if charon is started successfully.
  void StartCharon();
  // Writes swanctl.conf. On success, this function will trigger
  // |kSwanctlConfigWritten| step and set |swanctl_conf_path_| (and also
  // |server_ca_| and |server_ca_path_| if cert auth is used).
  void WriteSwanctlConfig();
  // Executes `swanctl --load-all`. Trigger |kSwanctlConfigLoaded| on success.
  void SwanctlLoadConfig();
  // Executes `swanctl --initiate`. Trigger |kIPsecConnected| on success.
  void SwanctlInitiateConnection();
  // Executes `swanctl --list-sas`, and parses the needed information from the
  // stdout of the execution. Trigger |kIPsecStatusRead| on success.
  void SwanctlListSAs();
  // Lets DeviceInfo create a XFRM interface. Will only be called for an IKEv2
  // connection.
  void CreateXFRMInterface();

  // This function will be called when the vici socket file is created, and may
  // be called multiple times if charon is still not listening on that socket.
  // |remaining_attempts| controls the remaining times that this function can be
  // entered.
  void OnViciSocketPathEvent(int remaining_attempts,
                             const base::FilePath& path,
                             bool error);
  void OnCharonExitedUnexpectedly(int exit_code);
  void OnSwanctlListSAsDone(const std::string& stdout_str);

  // Helper functions to run swanctl. RunSwanctl() executes `swanctl` with
  // |args|, and invokes |on_success| if the execution succeeds and the exit
  // code is 0, otherwise invokes NoitfyFailure() with |message_on_failure|.
  void RunSwanctl(const std::vector<std::string>& args,
                  SwanctlCallback on_success,
                  const std::string& message_on_failure);
  void OnSwanctlExited(SwanctlCallback on_success,
                       const std::string& message_on_failure,
                       int exit_code,
                       const std::string& stdout_str);
  // Used as the success callback for RunSwanctl(). Ignore |stdout_str| and
  // executes |step|.
  void SwanctlNextStep(ConnectStep step, const std::string& stdout_str);

  // Parses and sets the |local_virtual_ip| (the overlay IP) from the output of
  // `swanctl --list-sas`.
  void ParseLocalVirtualIP(const std::vector<std::string>& swanctl_output);
  // Parses and sets the cipher suite for IKE and ESP from the output of
  // `swanctl --list-sas`.
  void ParseIKECipherSuite(const std::vector<std::string>& swanctl_output);
  void ParseESPCipherSuite(const std::vector<std::string>& swanctl_output);

  // Callbacks from L2TPConnection.
  void OnL2TPConnected(const std::string& interface_name,
                       int interface_index,
                       const IPConfig::Properties& properties);
  void OnL2TPFailure(Service::ConnectFailure reason);
  void OnL2TPStopped();

  // Callback from DeviceInfo.
  void OnXFRMInterfaceReady(const std::string& if_name, int if_index);

  // Stops the charon process if it is running and invokes NotifyStopped().
  void StopCharon();

  std::unique_ptr<Config> config_;
  std::unique_ptr<VPNConnection> l2tp_connection_;

  // Runtime variables.
  base::ScopedTempDir temp_dir_;
  CertificateFile server_ca_;
  base::FilePath server_ca_path_;
  base::FilePath strongswan_conf_path_;
  base::FilePath swanctl_conf_path_;
  pid_t charon_pid_ = -1;
  base::FilePath vici_socket_path_;
  std::unique_ptr<base::FilePathWatcher> vici_socket_watcher_;

  // Variables only used in an IKEv2 connection.
  // Set when the XFRM interface is created.
  std::optional<int> xfrm_interface_index_;
  // Set when the IPsec layer is connected.
  std::string local_virtual_ip_;

  // Cipher algorithms used by this connection. Set when IPsec is connected.
  Metrics::VpnIpsecEncryptionAlgorithm ike_encryption_algo_;
  Metrics::VpnIpsecIntegrityAlgorithm ike_integrity_algo_;
  Metrics::VpnIpsecDHGroup ike_dh_group_;
  Metrics::VpnIpsecEncryptionAlgorithm esp_encryption_algo_;
  Metrics::VpnIpsecIntegrityAlgorithm esp_integrity_algo_;

  // External dependencies.
  DeviceInfo* device_info_;
  ProcessManager* process_manager_;
  std::unique_ptr<VPNUtil> vpn_util_;

  base::WeakPtrFactory<IPsecConnection> weak_factory_{this};
};

}  // namespace shill

#endif  // SHILL_VPN_IPSEC_CONNECTION_H_
