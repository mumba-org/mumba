// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_IO_THREAD_H__
#define MUMBA_HOST_IO_THREAD_H__

#include <memory>

#include "base/macros.h"
#include "base/compiler_specific.h"
#include "base/memory/ref_counted.h"
#include "base/memory/weak_ptr.h"
#include "base/synchronization/waitable_event.h"
#include "base/bind.h"
#include "base/callback.h"
#include "base/command_line.h"
#include "base/debug/alias.h"
#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/macros.h"
#include "base/message_loop/message_loop.h"
#include "base/run_loop.h"
#include "base/single_thread_task_runner.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "base/strings/stringize_macros.h"
#include "base/strings/utf_string_conversions.h"
#include "base/task_scheduler/task_scheduler.h"
#include "base/atomic_sequence_num.h"
#include "build/build_config.h"
//#include "components/policy/policy_constants.h"
#include "ipc/ipc_channel.h"
#include "ipc/ipc_channel_proxy.h"
#include "ipc/ipc_listener.h"
#include "jingle/glue/thread_wrapper.h"
#include "core/common/process_launcher_delegate.h"
#include "base/uuid.h"
#include "core/host/host_thread_delegate.h"
#include "core/host/net/ssl_config_service_manager.h"
#include "core/host/net/host_net_log.h"
#include "core/host/application/domain_process_host.h"
#include "core/host/application/application_process_host_observer.h"
#include "net/base/network_change_notifier.h"
#include "services/network/public/mojom/network_service.mojom.h"
#include "services/network/url_request_context_owner.h"
#include "mojo/edk/embedder/embedder.h"
#include "mojo/edk/embedder/incoming_broker_client_invitation.h"
#include "mojo/edk/embedder/platform_channel_pair.h"
#include "mojo/edk/embedder/scoped_ipc_support.h"
#include "net/base/network_change_notifier.h"
#include "net/base/url_util.h"
#include "net/socket/client_socket_factory.h"
#include "net/url_request/url_fetcher.h"
//#include "core/host/net/auto_thread_task_runner.h"
//#include "core/host/net/chromium_url_request.h"
//#include "core/host/net/constants.h"
//#include "core/host/net/logging.h"
//#include "core/host/net/oauth_token_getter_impl.h"
//#include "core/host/net/rsa_key_pair.h"
//#include "core/host/net/service_urls.h"
//#include "core/host/net/util.h"
//#include "core/host/net/branding.h"
//#include "core/host/net/peer_host.h"
//#include "core/host/net/peer_host_context.h"
//#include "core/host/net/peer_host_authenticator_factory.h"
//#include "core/host/net/peer_messages.h"
//#include "core/host/net/config_file_watcher.h"
//#include "core/host/net/config_watcher.h"
//#include "core/host/net/desktop_environment.h"
//#include "core/host/net/desktop_environment_options.h"
//#include "core/host/net/desktop_session_connector.h"
//#include "core/host/net/dns_blackhole_checker.h"
//#include "core/host/net/gcd_rest_client.h"
//#include "core/host/net/gcd_state_updater.h"
//#include "core/host/net/heartbeat_sender.h"
//#include "core/host/net/host_change_notification_listener.h"
//#include "core/host/net/host_config.h"
//#include "core/host/net/host_event_logger.h"
//#include "core/host/net/host_exit_codes.h"
//#include "core/host/net/host_main.h"
//#include "core/host/net/host_power_save_blocker.h"
//#include "core/host/net/host_status_logger.h"
//#include "core/host/net/input_injector.h"
//#include "core/host/net/ipc_desktop_environment.h"
//#include "core/host/net/ipc_host_event_logger.h"
//#include "core/host/net/logging.h"
//#include "core/host/net/me2me_desktop_environment.h"
//#include "core/host/net/pairing_registry_delegate.h"
//#include "core/host/net/pin_hash.h"
//#include "core/host/net/policy_watcher.h"
//#include "core/host/net/security_key/security_key_auth_handler.h"
//#include "core/host/net/security_key/security_key_extension.h"
//#include "core/host/net/shutdown_watchdog.h"
//#include "core/host/net/signaling_connector.h"
//#include "core/host/net/single_window_desktop_environment.h"
//#include "core/host/net/switches.h"
//#include "core/host/net/test_echo_extension.h"
//#include "core/host/net/third_party_auth_config.h"
//#include "core/host/net/token_validator_factory_impl.h"
//#include "core/host/net/usage_stats_consent.h"
//#include "core/host/net/username.h"
//#include "core/host/net/authenticator.h"
//#include "core/host/net/channel_authenticator.h"
//#include "core/host/net/chromium_port_allocator_factory.h"
//#include "core/host/net/jingle_session_manager.h"
//#include "core/host/net/network_settings.h"
//#include "core/host/net/pairing_registry.h"
//#include "core/host/net/port_range.h"
//#include "core/host/net/token_validator.h"
//#include "core/host/net/transport_context.h"
//#include "core/host/net/push_notification_subscriber.h"
//#include "core/host/net/xmpp_signal_strategy.h"
//#include "third_party/webrtc/rtc_base/scoped_ref_ptr.h"

#if defined(OS_POSIX)
#include <signal.h>
#include <sys/types.h>
#include <unistd.h>
#include "base/file_descriptor_posix.h"
//#include "core/host/net/pam_authorization_factory_posix.h"
#endif  // defined(OS_POSIX)

#if defined(OS_MACOSX)
#include "base/mac/scoped_cftyperef.h"
#endif  // defined(OS_MACOSX)

#if defined(OS_LINUX)
//#include <gtk/gtk.h>
#include "base/linux_util.h"
//#include "core/host/net/audio_capturer_linux.h"
//#include "core/host/net/linux/certificate_watcher.h"
//#include "ui/gfx/x/x11.h"
#endif  // defined(OS_LINUX)

#if defined(OS_WIN)
#include <commctrl.h>
#include "base/win/registry.h"
#include "base/win/scoped_handle.h"
//#include "core/host/net/pairing_registry_delegate_win.h"
//#include "core/host/net/win/session_desktop_environment.h"
#endif  // defined(OS_WIN)

class PrefRegistrySimple;

namespace net {
class CertVerifier;
class CTLogVerifier;
class HostResolver;
class HttpAuthHandlerFactory;
class HttpAuthPreferences;
class NetworkQualityEstimator;
class RTTAndThroughputEstimatesObserver;
class SSLConfigService;
class URLRequestContext;
class URLRequestContextGetter;
}  // namespace net

namespace network {
class URLRequestContextBuilderMojo;
}

namespace host {
class Domain;
//class DomainProcessHost;
class Application;
//class ApplicationProcessHost;
class DomainManager;
class PeerManager;
class SystemNetworkContextManager;
class StorageManager;
class ApplicationContents;
class ApplicationWindowHost;
class ApplicationWindowHostDelegate;
class ResourceContextImpl;
class HostNetworkContext;

class IOThread : public HostThreadDelegate,
                 public ApplicationProcessHostObserver,
                 public DomainProcessHost::Observer {//,
                 //public ConfigWatcher::Delegate,
                 //public HostChangeNotificationListener::Listener {
public:
 
 static void RegisterPrefs(PrefRegistrySimple* registry);

 IOThread(SystemNetworkContextManager* system_network_context_manager);
 ~IOThread() override;

 base::WaitableEvent* shutdown_event() { return &shutdown_event_; }
  
 base::WeakPtr<IOThread> weak_ptr() { return weak_factory_.GetWeakPtr(); }

 HostNetLog* net_log() const {
   return net_log_.get();
 }

 net::URLRequestContextGetter* system_url_request_context_getter();

//  ResourceContextImpl* GetResourceContext() const {
//   return resource_context_.get();
//  }

 HostNetworkContext* GetNetworkContext() const {
   return system_network_context_.get();
 }

 net::URLRequestContext* system_url_request_context() const {
   return system_request_context_;
 }

 //PeerHost* peer_host() const { return peer_host_.get(); }
 PeerManager* peer_manager() const { return peer_manager_.get(); }

 void CleanUpOnIOThread();

 //void LaunchDomainProcess();
 void LaunchApplicationProcess(std::unique_ptr<ApplicationProcessHost> process, base::Callback<void(ApplicationProcessHost*, bool)> cb);

 void ScheduleVolumeInstall(const base::FilePath& path);

 net::SSLConfigService* GetSSLConfigService();
 std::unique_ptr<net::HttpAuthHandlerFactory> CreateDefaultAuthHandlerFactory(net::HostResolver* host_resolver);
 std::unique_ptr<net::HostResolver> CreateHostResolver(bool system = false);

private:
 friend class DomainManager;
 friend class ApplicationManager;
 friend class ApplicationContents;
 friend class SystemURLRequestContextGetter;

 // HostThreadDelegate
 void Init() override;
 void CleanUp() override;

 void ConstructSystemRequestContext();
 //void InitializeSignaling();
 //void CreateAuthenticatorFactory();

 //void OnAuthFailed();
 //void OnUnknownHostIdError();
 //void OnHeartbeatSuccessful();

 // ConfigWatcher::Delegate interface.
 //void OnConfigUpdated(const std::string& serialized_config) override;
 //void OnConfigWatcherError() override;

 // HostChangeNotificationListener::Listener overrides.
 //void OnHostDeleted() override;

 //void CertificateWatcherDoNothing();

 bool IsExiting() const { return exiting_; } //override { return exiting_; }

 DomainProcessHost* LaunchDomainProcessOnIOThread(Domain* shell, StorageManager* storage_manager, const std::string& app_name, const base::UUID& id, const scoped_refptr<base::SingleThreadTaskRunner>& acceptor_task_runner);
 void LaunchApplicationProcessOnIOThread(std::unique_ptr<ApplicationProcessHost> process, scoped_refptr<base::SingleThreadTaskRunner> task_runner, base::Callback<void(ApplicationProcessHost*, bool)> cb);

 // ApplicationProcessHostObserver
  void ApplicationProcessExited(ApplicationProcessHost* host,
                               const ChildProcessTerminationInfo& info) override;
  void ApplicationProcessHostDestroyed(ApplicationProcessHost* host) override;

  void DomainProcessExited(DomainProcessHost* host,
                            const ChildProcessTerminationInfo& info) override;
  void DomainProcessHostDestroyed(DomainProcessHost* host) override;

 base::WaitableEvent shutdown_event_;

 const base::TimeTicks creation_time_;

 base::WaitableEvent shutdown_done_;

 bool exiting_;

 //std::vector<std::unique_ptr<DomainProcessHost>> domain_process_vector_;
 //std::vector<std::unique_ptr<ApplicationProcessHost>> application_process_vector_;

 // no need to own as the process hosts delete themselves
 std::vector<std::unique_ptr<DomainProcessHost, HostThread::DeleteOnIOThread>> domain_process_vector_;
 std::vector<std::unique_ptr<ApplicationProcessHost>> application_process_vector_;

 //std::unique_ptr<PeerHostContext> context_;

//#if defined(OS_LINUX)
  // Watch for certificate changes and kill the host when changes occur
//  std::unique_ptr<CertificateWatcher> cert_watcher_;
//#endif

  // XMPP server/remoting bot configuration (initialized from the command line).
  //XmppSignalStrategy::XmppServerConfig xmpp_server_config_;
  //std::string directory_bot_jid_;

  // Created on the UI thread but used from the network thread.
  //base::FilePath host_config_path_;
  //std::string host_config_;
 // std::unique_ptr<DesktopEnvironmentFactory> desktop_environment_factory_;

  //std::unique_ptr<ConfigWatcher> config_watcher_;

  //std::string host_id_;
  //std::string pin_hash_;
  //scoped_refptr<RsaKeyPair> key_pair_;
  //std::string oauth_refresh_token_;
  //std::string serialized_config_;
  //std::string host_owner_;
  //std::string host_owner_email_;

  //std::unique_ptr<PolicyWatcher> policy_watcher_;
  //PolicyState policy_state_ = POLICY_INITIALIZING;
  //std::vector<std::string> client_domain_list_;
  //std::vector<std::string> host_domain_list_;
  //bool allow_nat_traversal_ = true;
  //bool allow_relay_ = true;
  //PortRange udp_port_range_;
  //std::string talkgadget_prefix_;
  //bool allow_pairing_ = true;
  //bool use_service_account_ = true;

//  DesktopEnvironmentOptions desktop_environment_options_;
  //ThirdPartyAuthConfig third_party_auth_config_;
  //bool security_key_auth_policy_enabled_ = false;
  //bool security_key_extension_supported_ = true;

  // Must outlive |gcd_state_updater_| and |signaling_connector_|.
 //std::unique_ptr<OAuthTokenGetter> oauth_token_getter_;

 //std::unique_ptr<SignalingConnector> signaling_connector_;
 //std::unique_ptr<HeartbeatSender> heartbeat_sender_;
 //std::unique_ptr<XmppSignalStrategy> signaling_;

 //std::unique_ptr<HostChangeNotificationListener> host_change_notification_listener_;
 //std::unique_ptr<HostStatusLogger> host_status_logger_;
 //std::unique_ptr<HostEventLogger> host_event_logger_;
 //std::unique_ptr<PeerHost> peer_host_;
 std::unique_ptr<HostNetLog> net_log_;
 std::unique_ptr<PeerManager> peer_manager_;
 network::URLRequestContextOwner system_request_context_owner_;
 net::URLRequestContext* system_request_context_;
 std::unique_ptr<net::HttpAuthPreferences> http_auth_preferences_;
 std::unique_ptr<HostNetworkContext> system_network_context_;
 network::mojom::NetworkContextRequest network_context_request_;
 network::mojom::NetworkContextParamsPtr network_context_params_;

 std::unique_ptr<SSLConfigServiceManager> ssl_config_service_manager_;

 scoped_refptr<net::URLRequestContextGetter> system_url_request_context_getter_;
 std::unique_ptr<net::NetworkQualityEstimator> deprecated_network_quality_estimator_;
 //std::unique_ptr<NamedIpcServer> named_ipc_server_;
//  std::unique_ptr<ResourceContextImpl> resource_context_;

 bool signal_parent_ = false;

 //scoped_refptr<PairingRegistry> pairing_registry_;

 base::AtomicSequenceNumber named_server_sequence_;

 base::WeakPtrFactory<IOThread> weak_factory_;

 DISALLOW_COPY_AND_ASSIGN(IOThread);
};

}

#endif
