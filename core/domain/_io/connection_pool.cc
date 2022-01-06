// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/domain/io/connection_pool.h"

#include "base/macros.h"
#include "base/base64.h"
#include "base/compiler_specific.h"
#include "base/logging.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_split.h"
#include "net/base/completion_callback.h"
#include "net/base/host_port_pair.h"
#include "net/cert/ct_policy_enforcer.h"
#include "net/cert/ct_policy_status.h"
#include "net/cert/do_nothing_ct_verifier.h"
#include "net/cert/mock_cert_verifier.h"
#include "net/cert/signed_certificate_timestamp_and_status.h"
#include "net/dns/host_resolver_impl.h"
#include "net/http/http_cache.h"
#include "net/http/http_network_transaction.h"
#include "net/log/net_log_with_source.h"
#include "net/socket/client_socket_handle.h"
#include "net/socket/next_proto.h"
#include "net/socket/socket_tag.h"
#include "net/socket/ssl_client_socket.h"
#include "net/socket/transport_client_socket_pool.h"
#include "net/spdy/chromium/buffered_spdy_framer.h"
#include "net/spdy/chromium/spdy_http_utils.h"
#include "net/spdy/chromium/spdy_session_pool.h"
#include "net/spdy/chromium/spdy_stream.h"
#include "net/spdy/core/spdy_alt_svc_wire_format.h"
#include "net/spdy/core/spdy_framer.h"
//#include "net/test/gtest_util.h"
#include "net/traffic_annotation/network_traffic_annotation_test_helper.h"
#include "net/url_request/url_request_job_factory_impl.h"
#include "core/domain/io/connection.h"

namespace domain {

namespace {

net::HttpNetworkSession::Params CreateHttpSessionParams(
  const net::SettingsMap& http2_settings) {
  net::HttpNetworkSession::Params params;
      
      // host_resolver = std::make_unique<MockCachingHostResolver>();
      // cert_verifier = std::make_unique<MockCertVerifier>();
      // channel_id_service = nullptr;
      // transport_security_state = std::make_unique<TransportSecurityState>();
      // cert_transparency_verifier = std::make_unique<DoNothingCTVerifier>();
      // ct_policy_enforcer = std::make_unique<CTPolicyEnforcer>();
      // proxy_resolution_service = std::move(proxy_resolution_service);
      // ssl_config_service = base::MakeRefCounted<SSLConfigServiceDefaults>();
      // socket_factory = std::make_unique<MockClientSocketFactory>();
      // http_auth_handler_factory = HttpAuthHandlerFactory::CreateDefault(host_resolver.get());
      // http_server_properties = std::make_unique<HttpServerPropertiesImpl>();
      // enable_ip_namespaceing = true;
      // enable_ping = false;
      // enable_user_alternate_protocol_ports = false;
      // enable_quic = false;
      // enable_server_push_cancellation = false;
      // session_max_recv_window_size = kDefaultInitialWindowSize;
      // time_func = &base::TimeTicks::Now;
      // enable_http2_alternative_service = false;
      // enable_websocket_over_http2 = false;
      // net_log = nullptr;
      // http_09_on_non_default_ports_enabled = false;
      // disable_idle_sockets_close_on_memory_pressure = false

  params.enable_spdy_ping_based_connection_checking = false;
  params.enable_user_alternate_protocol_ports = false;
  params.enable_quic = false;
  params.enable_server_push_cancellation = false;
  params.spdy_session_max_recv_window_size = net::kDefaultInitialWindowSize;
  params.http2_settings = http2_settings;
  params.time_func = &base::TimeTicks::Now;
  params.enable_http2_alternative_service = false;
  params.enable_websocket_over_http2 = false;
  params.http_09_on_non_default_ports_enabled = false;
  params.disable_idle_sockets_close_on_memory_pressure = false;
  return params;
}

net::HttpNetworkSession::Context CreateHttpSessionContext(
      net::ClientSocketFactory* socket_factory,
      net::HostResolver* host_resolver,
      net::CertVerifier* cert_verifier,
      net::TransportSecurityState* transport_security_state,
      net::CTPolicyEnforcer* ct_policy_enforcer,
      net::HttpAuthHandlerFactory* http_auth_handler_factory,
      net::HttpServerProperties* http_server_properties,
      net::ProxyResolutionService* proxy_resolution_service,
      net::CTVerifier* cert_transparency_verifier,
      net::SSLConfigService* ssl_config_service,
      net::ProxyDelegate* proxy_delegate) {

  net::HttpNetworkSession::Context context;
  context.client_socket_factory = socket_factory;
  context.host_resolver = host_resolver;
  context.cert_verifier = cert_verifier;
  context.channel_id_service = nullptr;
  context.transport_security_state = transport_security_state;
  context.cert_transparency_verifier = cert_transparency_verifier;
  context.ct_policy_enforcer = ct_policy_enforcer;
  context.proxy_resolution_service = proxy_resolution_service;
  context.ssl_config_service = ssl_config_service;
  context.http_auth_handler_factory = http_auth_handler_factory;
  context.http_server_properties = http_server_properties;
  context.proxy_delegate = proxy_delegate;
  context.net_log = nullptr;
  return context;
}

}

ConnectionPool::ConnectionPool(): 
 spdy_session_pool_(nullptr) {
  net::HostResolver::Options options;
  host_resolver_ = std::make_unique<net::HostResolverImpl>(options, nullptr);
  transport_security_state_ = std::make_unique<net::TransportSecurityState>();
  cert_transparency_verifier_ = std::make_unique<net::DoNothingCTVerifier>();
  ct_policy_enforcer_ = std::make_unique<net::CTPolicyEnforcer>();
  proxy_resolution_service_ = net::ProxyResolutionService::CreateDirect();//std::move(net::proxy_resolution_service);
  ssl_config_service_ = base::MakeRefCounted<net::SSLConfigServiceDefaults>();
  socket_factory_.reset(net::ClientSocketFactory::GetDefaultFactory());
  http_auth_handler_factory_ = net::HttpAuthHandlerFactory::CreateDefault(host_resolver_.get());
  http_server_properties_ = std::make_unique<net::HttpServerPropertiesImpl>();
}

ConnectionPool::~ConnectionPool() {

}

void ConnectionPool::Init() {
  net::HttpNetworkSession::Params session_params = CreateHttpSessionParams(http2_settings_);
  net::HttpNetworkSession::Context session_context = CreateHttpSessionContext(
    socket_factory_.get(),
    host_resolver_.get(),
    cert_verifier_.get(),
    transport_security_state_.get(),
    ct_policy_enforcer_.get(),
    http_auth_handler_factory_.get(),
    http_server_properties_.get(),
    proxy_resolution_service_.get(),
    cert_transparency_verifier_.get(),
    ssl_config_service_.get(),
    proxy_delegate_.get());
  
  session_context.client_socket_factory = socket_factory_.get();
  
  http_network_session_.reset(new net::HttpNetworkSession(session_params, session_context));
  spdy_session_pool_ = http_network_session_->spdy_session_pool();
}

void ConnectionPool::Shutdown() {
  if (spdy_session_pool_) {
    spdy_session_pool_->CloseAllSessions();
  }
  http_network_session_.reset();
}

std::unique_ptr<Connection> ConnectionPool::CreateIPCConnection() {
  return {};
}

std::unique_ptr<Connection> ConnectionPool::CreateHTTPConnection() {
  return {};
}

}