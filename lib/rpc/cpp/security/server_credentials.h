/*
 *
 * Copyright 2015 gRPC authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#ifndef GRPCXX_SECURITY_SERVER_CREDENTIALS_H
#define GRPCXX_SECURITY_SERVER_CREDENTIALS_H

#include <memory>
#include <vector>

#include <rpc/cpp/security/auth_metadata_processor.h>
#include <rpc/cpp/support/config.h>
#include <rpc/grpc_security_constants.h>
#include "base/callback.h"
#include "base/bind.h"

struct grpc_server;
struct grpc_endpoint;
struct grpc_tcp_server_acceptor;
struct grpc_pollset;
struct grpc_exec_ctx;
struct grpc_error;

namespace grpc {
class Server;

/// Wrapper around \a grpc_server_credentials, a way to authenticate a server.
class ServerCredentials {
 public:
  virtual ~ServerCredentials();

  /// This method is not thread-safe and has to be called before the server is
  /// started. The last call to this function wins.
  virtual void SetAuthMetadataProcessor(
      const std::shared_ptr<AuthMetadataProcessor>& processor) = 0;

 private:
  friend class ::grpc::Server;

  /// Tries to bind \a server to the given \a addr (eg, localhost:1234,
  /// 192.168.1.1:31416, [::1]:27182, etc.)
  ///
  /// \return bound port number on sucess, 0 on failure.
  // TODO(dgq): the "port" part seems to be a misnomer.
  virtual int AddPortToServer(const grpc::string& addr,
                              grpc_server* server,
                              void* state,
                              void (*read_cb)(grpc_exec_ctx*, void*, grpc_error*)) = 0;
};

/// Options to create ServerCredentials with SSL
struct SslServerCredentialsOptions {
  /// \warning Deprecated
  SslServerCredentialsOptions()
      : force_client_auth(false),
        client_certificate_request(GRPC_SSL_DONT_REQUEST_CLIENT_CERTIFICATE) {}
  SslServerCredentialsOptions(
      grpc_ssl_client_certificate_request_type request_type)
      : force_client_auth(false), client_certificate_request(request_type) {}

  struct PemKeyCertPair {
    grpc::string private_key;
    grpc::string cert_chain;
  };
  grpc::string pem_root_certs;
  std::vector<PemKeyCertPair> pem_key_cert_pairs;
  /// \warning Deprecated
  bool force_client_auth;

  /// If both \a force_client_auth and \a client_certificate_request
  /// fields are set, \a force_client_auth takes effect, i.e.
  /// \a REQUEST_AND_REQUIRE_CLIENT_CERTIFICATE_AND_VERIFY
  /// will be enforced.
  grpc_ssl_client_certificate_request_type client_certificate_request;
};

/// Builds SSL ServerCredentials given SSL specific options
std::shared_ptr<ServerCredentials> SslServerCredentials(
    const SslServerCredentialsOptions& options);

/// Builds insecure server credentials.
std::shared_ptr<ServerCredentials> InsecureServerCredentials();

}  // namespace grpc

#endif  // GRPCXX_SECURITY_SERVER_CREDENTIALS_H
