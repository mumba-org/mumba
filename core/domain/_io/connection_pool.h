// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_NAMESPACE_CONNECTION_POOL_H_
#define MUMBA_DOMAIN_NAMESPACE_CONNECTION_POOL_H_

#include <memory>

#include "base/macros.h"
#include "net/spdy/chromium/spdy_session_pool.h"
#include "crypto/ec_private_key.h"
#include "crypto/ec_signature_creator.h"
#include "net/base/completion_once_callback.h"
#include "net/base/proxy_delegate.h"
#include "net/base/proxy_server.h"
#include "net/base/request_priority.h"
#include "net/base/test_completion_callback.h"
#include "net/cert/cert_verifier.h"
#include "net/dns/mock_host_resolver.h"
#include "net/http/http_auth_handler_factory.h"
#include "net/http/http_network_session.h"
#include "net/http/http_response_info.h"
#include "net/http/http_server_properties_impl.h"
#include "net/http/transport_security_state.h"
#include "net/proxy_resolution/proxy_resolution_service.h"
//#include "net/socket/socket_test_util.h"
#include "net/spdy/chromium/spdy_session.h"
#include "net/spdy/core/spdy_protocol.h"
#include "net/socket/client_socket_factory.h"
#include "net/spdy/platform/api/spdy_string.h"
#include "net/spdy/platform/api/spdy_string_piece.h"
#include "net/ssl/ssl_config_service_defaults.h"
#include "net/url_request/url_request_context.h"
#include "net/url_request/url_request_context_storage.h"

namespace domain {
class Connection;

class ConnectionPool {
public:
  ConnectionPool();
  ~ConnectionPool();

  void Init();
  void Shutdown();

  std::unique_ptr<Connection> CreateIPCConnection();
  std::unique_ptr<Connection> CreateHTTPConnection();

private:
  std::unique_ptr<net::HttpNetworkSession> http_network_session_;
  // a http 2 session namespace to create sessions to pass
  // to the HttpConnection
  net::SpdySessionPool* spdy_session_pool_;

  std::unique_ptr<net::HostResolverImpl> host_resolver_;
  std::unique_ptr<net::CertVerifier> cert_verifier_;
  std::unique_ptr<net::ConceptIDService> channel_id_service_;
  std::unique_ptr<net::TransportSecurityState> transport_security_state_;
  std::unique_ptr<net::CTVerifier> cert_transparency_verifier_;
  std::unique_ptr<net::CTPolicyEnforcer> ct_policy_enforcer_;
  std::unique_ptr<net::ProxyResolutionService> proxy_resolution_service_;
  scoped_refptr<net::SSLConfigService> ssl_config_service_;
  std::unique_ptr<net::ClientSocketFactory> socket_factory_;
  std::unique_ptr<net::HttpAuthHandlerFactory> http_auth_handler_factory_;
  std::unique_ptr<net::HttpServerPropertiesImpl> http_server_properties_;
  std::unique_ptr<net::ProxyDelegate> proxy_delegate_;
  net::SettingsMap http2_settings_;

  DISALLOW_COPY_AND_ASSIGN(ConnectionPool);
};

}

#endif