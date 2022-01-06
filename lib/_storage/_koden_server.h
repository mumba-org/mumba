// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_NET_MUMBA_SERVER_H_
#define MUMBA_NET_MUMBA_SERVER_H_

#include "base/macros.h"
#include "base/callback.h"
#include "base/bind.h"
#include "base/task_scheduler/post_task.h"
#include "base/single_thread_task_runner.h"
#include "net/tools/quic/quic_server.h"
#include "net/tools/quic/quic_dispatcher.h"
#include "storage/koden_protocol.h"
#include "net/quic/core/crypto/quic_random.h"
#include "net/quic/core/quic_utils.h"
#include "net/quic/core/tls_server_handshaker.h"
#include "net/quic/platform/api/quic_arraysize.h"
#include "net/quic/platform/api/quic_flags.h"
#include "net/quic/platform/api/quic_logging.h"
#include "net/quic/platform/api/quic_socket_address.h"
//#include "net/quic/platform/api/quic_test.h"
//#include "net/quic/platform/api/quic_test_loopback.h"
//#include "net/quic/test_tools/crypto_test_utils.h"
//#include "net/quic/test_tools/mock_quic_dispatcher.h"
#include "net/tools/quic/quic_epoll_alarm_factory.h"
#include "net/tools/quic/quic_epoll_connection_helper.h"
#include "net/tools/quic/quic_simple_crypto_server_stream_helper.h"
#include "net/tools/quic/test_tools/quic_server_peer.h"
#include "net/tools/quic/quic_simple_dispatcher.h"
#include "net/tools/quic/test_tools/quic_test_server.h"
#include "net/tools/quic/quic_packet_writer_wrapper.h"

namespace storage {
// class QuicPacketWriterWrapper;

// class MumbaQuicDispatcher : public QuicSimpleDispatcher {
// public:
//   MumbaQuicDispatcher(const QuicConfig& config,
//       const QuicCryptoServerConfig* crypto_config,
//       QuicVersionManager* version_manager,
//       std::unique_ptr<QuicConnectionHelperInterface> helper,
//       std::unique_ptr<QuicCryptoServerStream::Helper> session_helper,
//       std::unique_ptr<QuicAlarmFactory> alarm_factory,
//       QuicHttpResponseCache* response_cache);

//   ~MumbaQuicDispatcher() override;

//   void OnCanWrite() override;
//   bool HasPendingWrites() const override;
//   bool HasChlosBuffered() const override;
//   void ProcessBufferedChlos(size_t max_connections_to_create) override;
//   void DeleteSessions() override;

// protected:

//   //QuicSession* CreateQuicSession(QuicConnectionId connection_id,
//   //                               const QuicSocketAddress& peer_address,
//   //                               QuicStringPiece alpn) override;

//   void OnConnectionRejectedStatelessly() override;
//   void OnConnectionClosedStatelessly(QuicErrorCode error) override;
//   bool ShouldAttemptCheapStatelessRejection() override;

// private:

//   DISALLOW_COPY_AND_ASSIGN(MumbaQuicDispatcher);  
// };


class MumbaServer {//: public QuicServer {
public:
  MumbaServer(scoped_refptr<base::SingleThreadTaskRunner> server_task_runner, int port);
  ~MumbaServer();// override;

  MumbaHandler* handler() const {
    return handler_;
  }

  void RegisterHandler(MumbaHandler* handler) {
    handler_ = handler;
  }

  void Start();

//protected:
  
  //QuicDefaultPacketWriter* CreateWriter(int fd) override;
  //QuicDispatcher* CreateQuicDispatcher() override;

private:
  void ProcessRequest();

  void DoHandshake();
  void DoInterested();
  void DoUninterested();
  void DoChoke();
  void DoUnchoke();
  void DoBitfield();
  void DoRequest();
  void DoSubscription();
  void DoRevokeSubscription();

  //void AddToCache(QuicStringPiece path,
  //                int response_code,
  //                QuicStringPiece body);

  MumbaHandler* handler_;
  //QuicHttpResponseCache response_cache_;
  //QuicSocketAddress server_address_;
  //QuicString server_hostname_;
  //QuicConfig server_config_;
  //QuicPacketWriterWrapper* server_writer_;
  //QuicDefaultPacketWriter* server_writer_;
  //ParsedQuicVersionVector server_supported_versions_;
  //QuicTagVector client_extra_copts_;
  //ParsedQuicVersion negotiated_version_;
 // size_t chlo_multiplier_;
 // test::QuicTestServer::StreamFactory* stream_factory_;
  scoped_refptr<base::SingleThreadTaskRunner> server_task_runner_;
  
  DISALLOW_COPY_AND_ASSIGN(MumbaServer);
};


}

#endif