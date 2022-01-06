// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "storage/koden_server.h"

#include "net/quic/chromium/crypto/proof_source_chromium.h"
#include "net/base/ip_address.h"
#include "net/base/ip_endpoint.h"
#include "net/quic/core/crypto/aes_128_gcm_12_encrypter.h"
#include "net/quic/core/crypto/null_encrypter.h"
#include "net/quic/core/quic_framer.h"
#include "net/quic/core/quic_packet_creator.h"
#include "net/quic/core/quic_packets.h"
#include "net/quic/core/quic_server_id.h"
#include "net/quic/core/quic_session.h"
#include "net/quic/core/quic_spdy_client_session_base.h"
#include "net/quic/core/quic_utils.h"
#include "net/quic/platform/api/quic_flags.h"
#include "net/quic/platform/api/quic_logging.h"
#include "net/quic/platform/api/quic_ptr_util.h"
#include "net/quic/platform/api/quic_sleep.h"
#include "net/quic/platform/api/quic_socket_address.h"
#include "net/quic/platform/api/quic_str_cat.h"
#include "net/quic/platform/api/quic_string.h"
#include "net/quic/platform/api/quic_string_piece.h"
#include "net/quic/platform/api/quic_text_utils.h"
#include "net/quic/test_tools/quic_config_peer.h"
#include "net/quic/test_tools/quic_connection_peer.h"
#include "net/quic/test_tools/quic_flow_controller_peer.h"
#include "net/quic/test_tools/quic_sent_packet_manager_peer.h"
#include "net/quic/test_tools/quic_session_peer.h"
#include "net/quic/test_tools/quic_spdy_session_peer.h"
#include "net/quic/test_tools/quic_stream_peer.h"
#include "net/quic/test_tools/quic_stream_sequencer_peer.h"
#include "net/tools/epoll_server/epoll_server.h"
#include "net/tools/quic/platform/impl/quic_socket_utils.h"
#include "net/tools/quic/quic_epoll_connection_helper.h"
#include "net/tools/quic/quic_http_response_cache.h"
#include "net/tools/quic/quic_packet_writer_wrapper.h"
#include "net/tools/quic/quic_server.h"
#include "net/tools/quic/quic_simple_server_stream.h"
#include "net/tools/quic/quic_spdy_client_stream.h"
#include "net/tools/quic/test_tools/bad_packet_writer.h"
#include "net/tools/quic/test_tools/packet_reordering_writer.h"
#include "net/tools/quic/test_tools/quic_client_peer.h"
#include "net/tools/quic/test_tools/quic_dispatcher_peer.h"
#include "net/tools/quic/test_tools/quic_server_peer.h"
#include "net/tools/quic/test_tools/quic_test_server.h"
#include "net/tools/quic/test_tools/server_thread.h"

namespace storage {

namespace {

const char kFooResponseBody[] = "Artichoke hearts make me happy.";
const char kBarResponseBody[] = "Palm hearts are pretty delicious, also.";

}

// MumbaQuicDispatcher::MumbaQuicDispatcher(
//        const QuicConfig& config,
//        const QuicCryptoServerConfig* crypto_config,
//        QuicVersionManager* version_manager,
//        std::unique_ptr<QuicConnectionHelperInterface> helper,
//        std::unique_ptr<QuicCryptoServerStream::Helper> session_helper,
//        std::unique_ptr<QuicAlarmFactory> alarm_factory,
//        QuicHttpResponseCache* response_cache): 
//               QuicSimpleDispatcher(config,
//                                    crypto_config,
//                                    version_manager,
//                                    std::move(helper),
//                                    std::move(session_helper),
//                                    std::move(alarm_factory),
//                                    response_cache) {
// }

// MumbaQuicDispatcher::~MumbaQuicDispatcher() {

// }

// void MumbaQuicDispatcher::OnCanWrite() {
//   //D//LOG(INFO) << "MumbaQuicDispatcher::OnCanWrite";
//   QuicDispatcher::OnCanWrite();
// }

// bool MumbaQuicDispatcher::HasPendingWrites() const {
//   //D//LOG(INFO) << "MumbaQuicDispatcher::HasPendingWrites";
//   return QuicDispatcher::HasPendingWrites();
// }

// bool MumbaQuicDispatcher::HasChlosBuffered() const  {
//   //D//LOG(INFO) << "MumbaQuicDispatcher::HasChlosBuffered";
//   return QuicDispatcher::HasChlosBuffered();
// }
// void MumbaQuicDispatcher::ProcessBufferedChlos(size_t max_connections_to_create) {
//   //D//LOG(INFO) << "MumbaQuicDispatcher::ProcessBufferedChlos";
//   QuicDispatcher::ProcessBufferedChlos(max_connections_to_create);
// }

// void MumbaQuicDispatcher::DeleteSessions() {
//   //D//LOG(INFO) << "MumbaQuicDispatcher::DeleteSessions";
//   QuicDispatcher::DeleteSessions();
// }

// //QuicSession* MumbaQuicDispatcher::CreateQuicSession(QuicConnectionId connection_id,
// //                                                     const QuicSocketAddress& peer_address,
// //                                                      QuicStringPiece alpn) {
// //  return nullptr;
// //}

// void MumbaQuicDispatcher::OnConnectionRejectedStatelessly() {
//   //D//LOG(INFO) << "MumbaQuicDispatcher::OnConnectionRejectedStatelessly";
//   QuicDispatcher::OnConnectionRejectedStatelessly();
// }

// void MumbaQuicDispatcher::OnConnectionClosedStatelessly(QuicErrorCode error) {
//   //D//LOG(INFO) << "MumbaQuicDispatcher::OnConnectionClosedStatelessly";
//   QuicDispatcher::OnConnectionClosedStatelessly(error);
// }

// bool MumbaQuicDispatcher::ShouldAttemptCheapStatelessRejection() {
//   //D//LOG(INFO) << "MumbaQuicDispatcher::ShouldAttemptCheapStatelessRejection";
//   return QuicDispatcher::ShouldAttemptCheapStatelessRejection();
// }

MumbaServer::MumbaServer(scoped_refptr<base::SingleThreadTaskRunner> server_task_runner, int port): 
              //QuicServer(std::make_unique<ProofSourceChromium>(),
              //           &response_cache_), 
              handler_(nullptr),
              //server_address_(QuicSocketAddress(QuicIpAddress::Any4(), port)),
              //server_hostname_("test.example.com"),
              //client_writer_(nullptr),
              //server_writer_(nullptr),
              //negotiated_version_(PROTOCOL_UNSUPPORTED, QUIC_VERSION_UNSUPPORTED),
              //chlo_multiplier_(0),
              //stream_factory_(nullptr),
              server_task_runner_(server_task_runner) {
  //AddToCache("/foo", 200, kFooResponseBody);
  //AddToCache("/bar", 200, kBarResponseBody);
}

MumbaServer::~MumbaServer() {
}

// QuicDefaultPacketWriter* MumbaServer::CreateWriter(int fd) {
//   return new QuicDefaultPacketWriter(fd);
// }

// QuicDispatcher* MumbaServer::CreateQuicDispatcher() {
//   return new MumbaQuicDispatcher(
//        config(), 
//        &crypto_config(), 
//        version_manager(),
//        std::unique_ptr<QuicEpollConnectionHelper>(
//           new QuicEpollConnectionHelper(epoll_server(),
//                                         QuicAllocator::BUFFER_POOL)),
//        std::unique_ptr<QuicCryptoServerStream::Helper>(
//            new QuicSimpleCryptoServerStreamHelper(QuicRandom::GetInstance())),
//        std::unique_ptr<QuicEpollAlarmFactory>(
//            new QuicEpollAlarmFactory(epoll_server())),
//        &response_cache_);
// }

void MumbaServer::Start() {
  //QuicTagVector copt;
  //server_config_.SetConnectionOptionsToSend(copt);
  //server_writer_ = new QuicPacketWriterWrapper();
  //CreateUDPSocketAndListen(server_address_);
  //QuicDispatcher* dispatcher =
  //      test::QuicServerPeer::GetDispatcher(this);
  //test::QuicDispatcherPeer::UseWriter(dispatcher, server_writer_);
  //server_writer_->Initialize(test::QuicDispatcherPeer::GetHelper(dispatcher),
  //                           test::QuicDispatcherPeer::GetAlarmFactory(dispatcher));//,
  //                           new ServerDelegate(dispatcher)); 
}

void MumbaServer::ProcessRequest() {
  int code = 0;
  switch (code) {
    case kKOD_HANDSHAKE:
       DoHandshake();
       break;
    case kKOD_INTERESTED:
       DoInterested();
       break;
    case kKOD_UNINTERESTED:
       DoUninterested();
       break;
    case kKOD_CHOKE:
       DoChoke();
       break;
    case kKOD_UNCHOKE:
       DoUnchoke();
       break;
    case kKOD_BITFIELD:
       DoBitfield();
       break;
    case kKOD_REQUEST:
       DoRequest();
       break;
    case kKOD_SUBSCRIPTION:
       DoSubscription();
       break;
    case kKOD_REVOKE_SUBSCRIPTION:
       DoRevokeSubscription();
       break;
    default:
     NOTREACHED();
  }
}

void MumbaServer::DoHandshake() {
  handler_->OnHandshake();
}

void MumbaServer::DoInterested() {
  handler_->OnInterested();
}

void MumbaServer::DoUninterested() {
  handler_->OnUninterested();
}

void MumbaServer::DoChoke() {
  handler_->OnChoke();
}

void MumbaServer::DoUnchoke() {
  handler_->OnUnchoke();
}

void MumbaServer::DoBitfield() {
  handler_->OnBitfield();
}

void MumbaServer::DoRequest() {
  handler_->OnRequest();
}

void MumbaServer::DoSubscription() {
  handler_->OnSubscription();
}

void MumbaServer::DoRevokeSubscription() {
  handler_->OnRevokeSubscription();
}

//void MumbaServer::AddToCache(QuicStringPiece path,
//                              int response_code,
//                              QuicStringPiece body) {
//  response_cache_.AddSimpleResponse(server_hostname_, path, response_code, body);
//}

}