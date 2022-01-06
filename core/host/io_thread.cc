// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/io_thread.h"

#include "base/files/file_util.h"
#include "base/path_service.h"
#include "base/bind_helpers.h"
#include "base/stl_util.h"
#include "base/strings/string_number_conversions.h"
#include "base/threading/thread_restrictions.h"
#include "base/threading/thread_checker.h"
#include "core/shared/common/switches.h"
#include "core/shared/common/paths.h"
#include "core/shared/common/child_process_host.h"
#include "core/shared/common/child_process_messages.h"
#include "core/host/host.h"
#include "core/host/host_main_loop.h"
#include "core/host/application/application_process_host.h"
#include "core/host/application/application_window_host.h"
#include "core/host/application/domain_process_host.h"
#include "core/host/application/resource_context.h"
#include "core/host/application/resource_context_impl.h"
#include "core/host/host_thread.h"
#include "core/host/host_controller.h"
#include "core/host/net/host_network_delegate.h"
#include "core/host/net/host_network_context.h"
#include "core/host/volume/volume_manager.h"
#include "core/host/net/peer_manager.h"
#include "core/host/net/system_network_context_manager.h"
#include "core/host/network_service_instance.h"
#include "net/cert/caching_cert_verifier.h"
#include "net/cert/cert_verifier.h"
#include "net/cert/cert_verify_proc.h"
#include "net/cert/ct_known_logs.h"
#include "net/cert/ct_log_verifier.h"
#include "net/cert/ct_verifier.h"
#include "net/cert/multi_log_ct_verifier.h"
#include "net/cert/multi_threaded_cert_verifier.h"
#include "net/cert/cert_net_fetcher.h"
#include "net/cert_net/cert_net_fetcher_impl.h"
#include "net/dns/host_cache.h"
#include "net/dns/host_resolver.h"
#include "net/dns/mapped_host_resolver.h"
#include "net/http/http_auth_filter.h"
#include "net/http/http_auth_handler_factory.h"
#include "net/http/http_auth_preferences.h"
#include "net/http/http_network_session.h"
#include "net/http/http_server_properties_impl.h"
#include "net/http/http_transaction_factory.h"
#include "net/net_buildflags.h"
#include "net/nqe/network_quality_estimator.h"
#include "net/nqe/network_quality_estimator_params.h"
#include "net/proxy_resolution/pac_file_fetcher_impl.h"
#include "net/proxy_resolution/proxy_config_service.h"
#include "net/proxy_resolution/proxy_resolution_service.h"
#include "net/quic/chromium/quic_utils_chromium.h"
#include "net/socket/ssl_client_socket.h"
#include "net/url_request/url_fetcher.h"
#include "net/url_request/url_request_context.h"
#include "net/url_request/url_request_context_builder.h"
#include "net/url_request/url_request_context_getter.h"
#include "services/network/ignore_errors_cert_verifier.h"
#include "services/network/network_service.h"
#include "services/network/public/cpp/features.h"
#include "services/network/public/cpp/network_switches.h"
#include "services/network/url_request_context_builder_mojo.h"
#include "url/url_constants.h"

// #include "core/host/net/peer_host.h"
// #include "core/host/net/jingle_session_manager.h"
// #include "core/host/net/peer_host_context.h"
// #include "core/host/net/transport_context.h"
// #include "core/host/net/xmpp_signal_strategy.h"
// #include "core/host/net/pairing_registry_delegate.h"
// #include "core/host/net/branding.h"
#include "ipc/ipc_channel_proxy.h"
#include "net/url_request/url_request_context_getter.h"

namespace host {

namespace {

const char kUserDataDir[] = "user-data-dir";

}  

class SystemURLRequestContextGetter : public net::URLRequestContextGetter {
 public:
  explicit SystemURLRequestContextGetter(IOThread* io_thread);

  // Implementation for net::UrlRequestContextGetter.
  net::URLRequestContext* GetURLRequestContext() override;
  scoped_refptr<base::SingleThreadTaskRunner> GetNetworkTaskRunner()
      const override;

 protected:
  ~SystemURLRequestContextGetter() override;

 private:
  IOThread* const io_thread_;  // Weak pointer, owned by BrowserProcess.
  scoped_refptr<base::SingleThreadTaskRunner> network_task_runner_;

  base::debug::LeakTracker<SystemURLRequestContextGetter> leak_tracker_;
};

SystemURLRequestContextGetter::SystemURLRequestContextGetter(
    IOThread* io_thread)
    : io_thread_(io_thread),
      network_task_runner_(
          HostThread::GetTaskRunnerForThread(HostThread::IO)) {}

SystemURLRequestContextGetter::~SystemURLRequestContextGetter() {}

net::URLRequestContext* SystemURLRequestContextGetter::GetURLRequestContext() {
  DCHECK_CURRENTLY_ON(HostThread::IO);
  DCHECK(io_thread_->system_request_context_);

  return io_thread_->system_request_context_;
}

scoped_refptr<base::SingleThreadTaskRunner>
SystemURLRequestContextGetter::GetNetworkTaskRunner() const {
  return network_task_runner_;
}

 // static
void IOThread::RegisterPrefs(PrefRegistrySimple* registry) {
 
}

IOThread::IOThread(SystemNetworkContextManager* system_network_context_manager) : 
  shutdown_event_(base::WaitableEvent::ResetPolicy::MANUAL, base::WaitableEvent::InitialState::NOT_SIGNALED),
  creation_time_(base::TimeTicks::Now()),
  shutdown_done_(base::WaitableEvent::ResetPolicy::AUTOMATIC, base::WaitableEvent::InitialState::NOT_SIGNALED),
  exiting_(false),
  net_log_(new HostNetLog()),
  system_request_context_(nullptr),
  weak_factory_(this) {
  
 HostThread::SetDelegate(HostThread::IO, this);

 ssl_config_service_manager_.reset(
      SSLConfigServiceManager::CreateDefaultManager(
          HostThread::GetTaskRunnerForThread(HostThread::IO)));

 system_network_context_manager->SetUp(&network_context_request_,
                                       &network_context_params_);
}

IOThread::~IOThread() {
 HostThread::SetDelegate(HostThread::IO, NULL);
}

void IOThread::Init()  {
 CHECK(HostThread::CurrentlyOn(HostThread::IO));

 // TODO: we need to disable this when possible
 base::ThreadRestrictions::SetIOAllowed(true);

 peer_manager_.reset(new PeerManager());
 
 //mojo::edk::NamedPlatformHandle name_channel_handle("/tmp/hello_ipc");
 //int ipc_server_id = named_server_sequence_.GetNext() + 1;  
 //named_ipc_server_ = NamedIpcServer::Create(ipc_server_id);
 //if (!named_ipc_server_->Init(name_channel_handle)) {
 //  LOG(ERROR) << "Failed to initialize NamedIpcServer";
 //  return;
 //}
 //DCHECK(HostThread::IsThreadInitialized(HostThread::PROCESS_LAUNCHER));
 
 // data_use_ascriber_ =
 //      std::make_unique<data_use_measurement::ChromeDataUseAscriber>();

 // data_use_aggregator_ =
 //      std::make_unique<data_usage::DataUseAggregator>(
 //          std::make_unique<chrome_browser_data_usage::TabIdAnnotator>(),
 //          std::move(data_use_amortizer));

  // dns_probe_service_ =
  //     std::make_unique<chrome_browser_net::DnsProbeService>();

  // if (command_line.HasSwitch(switches::kIgnoreUrlFetcherCertRequests))
  //   net::URLFetcher::SetIgnoreCertificateRequests(true);

// #if defined(OS_ANDROID) && defined(ARCH_CPU_ARMEL)
//   crypto::EnsureOpenSSLInit();
// #endif

//   std::vector<scoped_refptr<const net::CTLogVerifier>> ct_logs(
//       net::ct::CreateLogVerifiersForKnownLogs());
//   globals_->ct_logs.assign(ct_logs.begin(), ct_logs.end());

  ConstructSystemRequestContext();

  net::URLFetcher::SetIgnoreCertificateRequests(true);

//   ServiceUrls* service_urls = ServiceUrls::GetInstance();

//   const std::string& xmpp_server =
//       service_urls->xmpp_server_address_for_me2me_host();
//   if (!net::ParseHostAndPort(xmpp_server, &xmpp_server_config_.host,
//                              &xmpp_server_config_.port)) {
//     LOG(ERROR) << "Invalid XMPP server: " << xmpp_server;
//     return;
//   }

//   xmpp_server_config_.use_tls = service_urls->xmpp_server_use_tls();
//   directory_bot_jid_ = service_urls->directory_bot_jid();

//   //signal_parent_ = cmd_line->HasSwitch(kSignalParentSwitchName);
 
//   context_ =
//       PeerHostContext::Create(
//           base::ThreadTaskRunnerHandle::Get(), // io_thread
//           HostThread::GetTaskRunnerForThread(HostThread::UI));

// //  std::unique_ptr<net::NetworkChangeNotifier> network_change_notifier(
// //      net::NetworkChangeNotifier::Create());

//   base::FilePath default_config_dir = GetConfigDir();
//   host_config_path_ = default_config_dir.Append(kDefaultHostConfigFile);

//   if (!base::PathExists(host_config_path_)) {
//     key_pair_ = RsaKeyPair::Generate();
//     std::string json_data = "{\n  \"" + std::string(kPrivateKeyConfigPath) + "\": \"" + key_pair_->ToString() + "\"\n}\n";
//     base::WriteFile(host_config_path_, json_data.data(), json_data.size());
//   }

//   if (!key_pair_) {
//     if (!base::ReadFileToString(host_config_path_, &serialized_config_)) {
//       LOG(ERROR) << "Could not read config file: " << host_config_path_;
//       return;
//     }

//     std::unique_ptr<base::DictionaryValue> config(
//         HostConfigFromJson(serialized_config_));
//     if (!config) {
//       LOG(ERROR) << "Invalid configuration.";
//       //ShutdownHost(kInvalidHostConfigurationExitCode);
//       return;
//     }     

//     std::string key_base64;
//     if (!config->GetString(kPrivateKeyConfigPath, &key_base64)) {
//       LOG(ERROR) << "Private key couldn't be read from the config file.";
//       return;
//     }

//     key_pair_ = RsaKeyPair::FromString(key_base64);
//     if (!key_pair_.get()) {
//       LOG(ERROR) << "Invalid private key in the config file.";
//       return;
//     }
//   }

//   InitializeSignaling();

//   uint32_t network_flags = 0;
//   if (allow_nat_traversal_) {
//     network_flags = NetworkSettings::NAT_TRAVERSAL_STUN |
//                     NetworkSettings::NAT_TRAVERSAL_OUTGOING;
//     if (allow_relay_)
//       network_flags |= NetworkSettings::NAT_TRAVERSAL_RELAY;
//   }

//   NetworkSettings network_settings(network_flags);

//   if (!udp_port_range_.is_null()) {
//     network_settings.port_range = udp_port_range_;
//   } else if (!allow_nat_traversal_) {
//     // For legacy reasons we have to restrict the port range to a set of default
//     // values when nat traversal is disabled, even if the port range was not
//     // set in policy.
//     network_settings.port_range.min_port = NetworkSettings::kDefaultMinPort;
//     network_settings.port_range.max_port = NetworkSettings::kDefaultMaxPort;
//   }

//  scoped_refptr<TransportContext> transport_context =
//     new TransportContext(
//         signaling_.get(),
//         std::make_unique<ChromiumPortAllocatorFactory>(),
//         std::make_unique<ChromiumUrlRequestFactory>(
//             context_->url_request_context_getter()),
//         network_settings, 
//         TransportRole::SERVER);

//  transport_context->set_ice_config_url(
//      ServiceUrls::GetInstance()->ice_config_url(), oauth_token_getter_.get());

//  std::unique_ptr<SessionManager> session_manager(
//      new JingleSessionManager(signaling_.get()));

//  std::unique_ptr<CandidateSessionConfig> protocol_config = 
//   CandidateSessionConfig::CreateDefault();
//  protocol_config->set_webrtc_supported(true);
//  session_manager->set_protocol_config(std::move(protocol_config));

//  peer_host_.reset(new PeerHost(std::move(session_manager), 
//                   transport_context));

//  host_change_notification_listener_.reset(new HostChangeNotificationListener(
//   this, host_id_, signaling_.get(), directory_bot_jid_));

//  host_status_logger_.reset(
//       new HostStatusLogger(peer_host_->status_monitor(), ServerLogEntry::ME2ME,
//                            signaling_.get(), directory_bot_jid_));

//  peer_host_->Start("whatever@dontknow.bollocks");

//  CreateAuthenticatorFactory();

}

// void IOThread::InitializeSignaling() {
//   // Create SignalStrategy.
//   signaling_.reset(new XmppSignalStrategy(
//       net::ClientSocketFactory::GetDefaultFactory(),
//       context_->url_request_context_getter(), xmpp_server_config_));

//   // Create SignalingConnector.
//   std::unique_ptr<DnsBlackholeChecker> dns_blackhole_checker(
//       new DnsBlackholeChecker(context_->url_request_context_getter(),
//                               talkgadget_prefix_));
//   std::unique_ptr<OAuthTokenGetter::OAuthAuthorizationCredentials>
//       oauth_credentials(new OAuthTokenGetter::OAuthAuthorizationCredentials(
//           xmpp_server_config_.username, oauth_refresh_token_,
//           use_service_account_));
//   oauth_token_getter_.reset(
//       new OAuthTokenGetterImpl(std::move(oauth_credentials),
//                                context_->url_request_context_getter(), false));
//   signaling_connector_.reset(new SignalingConnector(
//       signaling_.get(), std::move(dns_blackhole_checker),
//       oauth_token_getter_.get(),
//       base::Bind(&IOThread::OnAuthFailed, base::Unretained(this))));

//   // Create HeartbeatSender.
//   heartbeat_sender_.reset(new HeartbeatSender(
//       base::Bind(&IOThread::OnHeartbeatSuccessful, base::Unretained(this)),
//       base::Bind(&IOThread::OnUnknownHostIdError, base::Unretained(this)),
//       host_id_, signaling_.get(), key_pair_, directory_bot_jid_));
// }

// void IOThread::CreateAuthenticatorFactory() {
//   DCHECK(HostThread::CurrentlyOn(HostThread::IO));

//   std::string local_certificate = key_pair_->GenerateCertificate();
//   if (local_certificate.empty()) {
//     LOG(ERROR) << "Failed to generate host certificate.";
//     //ShutdownHost(kInitializationFailed);
//     return;
//   }

//   std::unique_ptr<AuthenticatorFactory> factory;

//   if (third_party_auth_config_.is_null()) {
//     scoped_refptr<PairingRegistry> pairing_registry;
//     if (allow_pairing_) {
//       // On Windows |pairing_registry_| is initialized in
//       // InitializePairingRegistry().
// #if !defined(OS_WIN)
//       if (!pairing_registry_) {
//         std::unique_ptr<PairingRegistry::Delegate> delegate =
//             CreatePairingRegistryDelegate();

//         if (delegate)
//           pairing_registry_ = new PairingRegistry(context_->file_task_runner(),
//                                                   std::move(delegate));
//       }
// #endif  // defined(OS_WIN)

//       pairing_registry = pairing_registry_;
//     }

//     factory = PeerHostAuthenticatorFactory::CreateWithPin(
//         use_service_account_, host_owner_, local_certificate, key_pair_,
//         client_domain_list_, pin_hash_, pairing_registry);

//     peer_host_->set_pairing_registry(pairing_registry);
//   } else {
//     // ThirdPartyAuthConfig::Parse() leaves the config in a valid state, so
//     // these URLs are both valid.
//     DCHECK(third_party_auth_config_.token_url.is_valid());
//     DCHECK(third_party_auth_config_.token_validation_url.is_valid());

// #if defined(OS_LINUX)
//     if (!cert_watcher_) {
//       cert_watcher_.reset(new CertificateWatcher(
//           base::Bind(&IOThread::CertificateWatcherDoNothing, base::Unretained(this)),
//           context_->file_task_runner()));
//       cert_watcher_->Start();
//     }
//     cert_watcher_->SetMonitor(peer_host_->status_monitor());
// #endif

//     scoped_refptr<TokenValidatorFactory> token_validator_factory =
//         new TokenValidatorFactoryImpl(third_party_auth_config_, key_pair_,
//                                       context_->url_request_context_getter());
//     factory = PeerHostAuthenticatorFactory::CreateWithThirdPartyAuth(
//         use_service_account_, host_owner_, local_certificate, key_pair_,
//         client_domain_list_, token_validator_factory);
//   }

// #if defined(OS_POSIX)
//   // On Linux and Mac, perform a PAM authorization step after authentication.
//   factory.reset(new PamAuthorizationFactory(std::move(factory)));
// #endif
//   peer_host_->SetAuthenticatorFactory(std::move(factory));
//}

void IOThread::CleanUp() {
  // we need to do this on UI thread
  for (auto it = application_process_vector_.begin(); it != application_process_vector_.end(); ++it) {
    (*it)->DestroyWindow();
    (*it)->UnregisterHost((*it)->GetID());
    (*it)->RemoveObserver(this);
    (*it)->Cleanup();
  }

  for (auto it = domain_process_vector_.begin(); it != domain_process_vector_.end(); ++it) {
    (*it)->RemoveObserver(this);
    (*it)->Cleanup();
  }

  application_process_vector_.clear();
}

void IOThread::ScheduleVolumeInstall(const base::FilePath& path) {
  DCHECK(false);
  // scoped_refptr<HostController> controller = HostController::Instance();

  // base::ThreadTaskRunnerHandle::Get()->PostDelayedTask(
  //   FROM_HERE, 
  //   base::BindOnce(&HostController::InstallVolume, 
  //     controller,
  //     path),
  //   base::TimeDelta::FromSeconds(5));
}

net::URLRequestContextGetter* IOThread::system_url_request_context_getter() {
  if (!system_url_request_context_getter_.get()) {
     system_url_request_context_getter_ =
         base::MakeRefCounted<SystemURLRequestContextGetter>(this);
   }
  return system_url_request_context_getter_.get();
}

// void IOThread::LaunchDomainProcess() {
//   HostThread::PostTask(
//     HostThread::IO, FROM_HERE,
//     base::BindOnce(&IOThread::LaunchDomainProcessOnIOThread, 
//       weak_factory_.GetWeakPtr()));
// }


void IOThread::LaunchApplicationProcess(std::unique_ptr<ApplicationProcessHost> process, base::Callback<void(ApplicationProcessHost*, bool)> cb) { 
  HostThread::PostTask(
     HostThread::IO, 
     FROM_HERE,
     base::BindOnce(&IOThread::LaunchApplicationProcessOnIOThread,
       weak_factory_.GetWeakPtr(),
       base::Passed(std::move(process)),
       // we are assuming we are on the UI here, is this always true?
       HostThread::GetTaskRunnerForThread(HostThread::UI),
       base::Passed(std::move(cb))));
}

DomainProcessHost* IOThread::LaunchDomainProcessOnIOThread(Domain* shell, StorageManager* storage_manager, const std::string& app_name, const base::UUID& id, const scoped_refptr<base::SingleThreadTaskRunner>& acceptor_task_runner) {
  std::unique_ptr<DomainProcessHost, HostThread::DeleteOnIOThread> domain_process(new DomainProcessHost(shell, storage_manager, acceptor_task_runner));
  DomainProcessHost* domain_process_ref = domain_process.get();
  if (domain_process->Init(app_name, id)) {
    domain_process->AddObserver(this);
    domain_process_vector_.push_back(std::move(domain_process));
  } else {
    domain_process->Cleanup();
    domain_process_ref = nullptr;
  }
  return domain_process_ref;
}

void IOThread::LaunchApplicationProcessOnIOThread(std::unique_ptr<ApplicationProcessHost> process, scoped_refptr<base::SingleThreadTaskRunner> task_runner, base::Callback<void(ApplicationProcessHost*, bool)> cb) {
  ApplicationProcessHost* application_process = process.get();
  bool result = application_process->Init();
  if (result) {
    application_process->AddObserver(this);
    application_process_vector_.push_back(std::move(process));
  } else {
    application_process->Cleanup();
  }
  task_runner->PostTask(FROM_HERE, base::Bind(cb, application_process, result));
}

void IOThread::CleanUpOnIOThread() {
 CHECK(HostThread::CurrentlyOn(HostThread::IO));
 
 peer_manager_.reset();

 exiting_ = true;

 system_url_request_context_getter_ = nullptr;

 domain_process_vector_.clear();

//  for (auto it = domain_process_vector_.begin(); it != domain_process_vector_.end(); ++it) {
//     //(*it)->Send(new ChildProcessMsg_Shutdown());
//     //it->reset();
//     it->Cleanup();
//  }

//  for (auto it = application_process_vector_.begin(); it != application_process_vector_.end(); ++it) {
//     //it->reset();
//     it->Cleanup();
//  }

 weak_factory_.InvalidateWeakPtrs();

 system_network_context_.reset();

 shutdown_event_.Signal();
}

// void IOThread::OnAuthFailed() {
//   LOG(ERROR) << "IOThread::OnAuthFailed";
// }

// void IOThread::OnUnknownHostIdError() {
//   LOG(ERROR) << "Host ID not found.";
// }

// void IOThread::OnHeartbeatSuccessful() {
//   LOG(INFO) << "IOThread::OnHeartbeatSuccessful";
// }

std::unique_ptr<net::HttpAuthHandlerFactory>
IOThread::CreateDefaultAuthHandlerFactory(net::HostResolver* host_resolver) {
  std::vector<std::string> supported_schemes; // = base::SplitString(
  //    auth_schemes_, ",", base::TRIM_WHITESPACE, base::SPLIT_WANT_NONEMPTY);
  supported_schemes.push_back("http");
  supported_schemes.push_back("https");

#if defined(OS_POSIX)  
  http_auth_preferences_ =
      std::make_unique<net::HttpAuthPreferences>(supported_schemes, "libgssapi.so.3");
                                                 //gssapi_library_name_);
#elif defined(OS_WIN)
  http_auth_preferences_ =
      std::make_unique<net::HttpAuthPreferences>(supported_schemes);
#endif

  //UpdateServerWhitelist();
  //UpdateDelegateWhitelist();
  //UpdateNegotiateDisableCnameLookup();
  //UpdateNegotiateEnablePort();
//#if defined(OS_POSIX)
//  UpdateNtlmV2Enabled();
//#endif
//#if defined(OS_ANDROID)
//  UpdateAndroidAuthNegotiateAccountType();
//#endif

  return net::HttpAuthHandlerRegistryFactory::Create(
      http_auth_preferences_.get(), host_resolver);
}

net::SSLConfigService* IOThread::GetSSLConfigService() {
  return ssl_config_service_manager_->Get();
}

void IOThread::ConstructSystemRequestContext() {
   std::unique_ptr<network::URLRequestContextBuilderMojo> builder =
       std::make_unique<network::URLRequestContextBuilderMojo>();

  auto host_network_delegate = std::make_unique<HostNetworkDelegate>();
//   //     extension_event_router_forwarder(), &system_enable_referrers_);
//   // // By default, data usage is considered off the record.
//   // chrome_network_delegate->set_data_use_aggregator(
//   //     globals_->data_use_aggregator.get(),
//   //     true /* is_data_usage_off_the_record */);
   builder->set_network_delegate(std::move(host_network_delegate));
//   //    data_use_ascriber_->CreateNetworkDelegate(
//   //        std::move(host_network_delegate), GetMetricsDataUseForwarder()));
   std::unique_ptr<net::HostResolver> host_resolver = CreateHostResolver(true);

   builder->set_ssl_config_service(GetSSLConfigService());
   builder->SetHttpAuthHandlerFactory(CreateDefaultAuthHandlerFactory(host_resolver.get()));

   builder->set_host_resolver(std::move(host_resolver));

   std::unique_ptr<net::CertVerifier> cert_verifier;
// #if defined(OS_CHROMEOS)
//   // Creates a CertVerifyProc that doesn't allow any profile-provided certs.
//   cert_verifier = std::make_unique<net::CachingCertVerifier>(
//       std::make_unique<net::MultiThreadedCertVerifier>(
//           base::MakeRefCounted<chromeos::CertVerifyProcChromeOS>()));
// #else
   cert_verifier = std::make_unique<net::CachingCertVerifier>(
       std::make_unique<net::MultiThreadedCertVerifier>(
           net::CertVerifyProc::CreateDefault()));
// #endif
  
   const base::CommandLine& command_line =
       *base::CommandLine::ForCurrentProcess();
   builder->SetCertVerifier(
       network::IgnoreErrorsCertVerifier::MaybeWrapCertVerifier(
           command_line, kUserDataDir, std::move(cert_verifier)));
//   //UMA_HISTOGRAM_BOOLEAN(
//   //    "Net.Certificate.IgnoreCertificateErrorsSPKIListPresent",
//   //    command_line.HasSwitch(
//   //        network::switches::kIgnoreCertificateErrorsSPKIList));

   std::unique_ptr<net::MultiLogCTVerifier> ct_verifier =
       std::make_unique<net::MultiLogCTVerifier>();
//   // Add built-in logs
   //ct_verifier->AddLogs(ct_logs_);
   builder->set_ct_verifier(std::move(ct_verifier));
  
   builder->set_pac_quick_check_enabled(true);
   builder->set_pac_sanitize_url_policy(net::ProxyResolutionService::SanitizeUrlPolicy::UNSAFE);

  //  if (base::FeatureList::IsEnabled(network::features::kNetworkService)) {
  //    DLOG()
  //    deprecated_network_quality_estimator_ =
  //         std::make_unique<net::NetworkQualityEstimator>(
  //             std::make_unique<net::NetworkQualityEstimatorParams>(
  //                 std::map<std::string, std::string>()),
  //             net_log_.get());
  //    system_request_context_owner_ = builder->Create(
  //        std::move(network_context_params_).get(), false,
  //        net_log_.get(), deprecated_network_quality_estimator_.get());
  //     //system_network_context_ = system_request_context_owner_.url_request_context.get();
  //    system_request_context_ = system_request_context_owner_.url_request_context.get();
  //    //GetNetworkService()->CreateNetworkContext(
  //    //        std::move(network_context_request_),
  //    //        std::move(network_context_params_));
  //   //DCHECK(system_network_context_);
  //  } else {
    // NOTE: as long as network service is running on the host process
    // this will work, otherwise we will need to change this 
    system_network_context_ = 
      std::make_unique<HostNetworkContext>(
        GetNetworkServiceImpl(), 
        std::move(network_context_request_),
        std::move(network_context_params_), 
        std::move(builder));

    system_request_context_ = system_network_context_->url_request_context();
   //}

//   // TODO(mmenke): This class currently requires an in-process
//   // NetworkQualityEstimator.  Fix that.
//   // globals_->network_quality_observer = content::CreateNetworkQualityObserver(
//   //     globals_->system_request_context->network_quality_estimator());

// #if defined(USE_NSS_CERTS)
//   net::SetURLRequestContextForNSSHttpIO(system_request_context_);
// #endif
// #if defined(OS_ANDROID) || defined(OS_FUCHSIA) || \
//     (defined(OS_LINUX) && !defined(OS_CHROMEOS)) || defined(OS_MACOSX)
   net::SetGlobalCertNetFetcher(
       net::CreateCertNetFetcher(system_request_context_));
// #endif
}

std::unique_ptr<net::HostResolver> IOThread::CreateHostResolver(bool system) {
  //TRACE_EVENT0("startup", "IOThread::CreateGlobalHostResolver");
  if (system) {
    std::unique_ptr<net::HostResolver> global_host_resolver =
      net::HostResolver::CreateSystemResolver(net::HostResolver::Options(), net_log_.get());
    return global_host_resolver;
  }
  std::unique_ptr<net::HostResolver> host_resolver =
    net::HostResolver::CreateDefaultResolver(net_log_.get());
      //net::HostResolver::CreateSystemResolver(net::HostResolver::Options(), net_log_.get());

  // If hostname remappings were specified on the command-line, layer these
  // rules on top of the real host resolver. This allows forwarding all requests
  // through a designated test server.
  //const base::CommandLine& command_line =
  //    *base::CommandLine::ForCurrentProcess();
  //if (!command_line.HasSwitch(network::switches::kHostResolverRules))
  //return global_host_resolver;

  auto remapped_resolver = std::make_unique<net::MappedHostResolver>(
      std::move(host_resolver));
  //remapped_resolver->SetRulesFromString(
  //    command_line.GetSwitchValueASCII(network::switches::kHostResolverRules));
  return remapped_resolver;
}

void IOThread::ApplicationProcessExited(ApplicationProcessHost* host,
                                        const ChildProcessTerminationInfo& info) {
 // DLOG(INFO) << "IOThread::ApplicationProcessExited";
}

void IOThread::ApplicationProcessHostDestroyed(ApplicationProcessHost* host) {
 // DLOG(INFO) << "IOThread::ApplicationProcessHostDestroyed";
 ApplicationProcessHost* ptr = nullptr;
  for (auto it = application_process_vector_.begin(); it != application_process_vector_.end(); ++it) {
    if (it->get() == host) {
      // We let the ApplicationProcessHost 'destroy itself'
      // we need it as other observers may not get called because of this
      ptr = it->release();
      application_process_vector_.erase(it);
      return;
    }
  }
}

void IOThread::DomainProcessExited(DomainProcessHost* host,
                                    const ChildProcessTerminationInfo& info)  {
  //DLOG(INFO) << "IOThread::DomainProcessExited";
}

void IOThread::DomainProcessHostDestroyed(DomainProcessHost* host) {
  //DLOG(INFO) << "IOThread::DomainProcessHostDestroyed";
  DCHECK_CURRENTLY_ON(HostThread::UI);
  for (auto it = domain_process_vector_.begin(); it != domain_process_vector_.end(); ++it) {
    if (it->get() == host) {
      domain_process_vector_.erase(it);
      return;
    }
  }
}

// void IOThread::OnConfigUpdated(const std::string& serialized_config) {
//   LOG(INFO) << "IOThread::OnConfigUpdated";
// }

// void IOThread::OnConfigWatcherError() {
//   LOG(INFO) << "IOThread::OnConfigWatcherError";
// }

// void IOThread::OnHostDeleted() {
//   LOG(INFO) << "IOThread::OnHostDeleted";
// }

// void IOThread::CertificateWatcherDoNothing() {
//   LOG(INFO) << "IOThread::CertificateWatcherDoNothing";
// }

}
