// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_NET_P2P_SOCKET_DISPATCHER_HOST_H_
#define MUMBA_HOST_NET_P2P_SOCKET_DISPATCHER_HOST_H_

#include <stdint.h>

#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include "base/macros.h"
#include "base/atomic_sequence_num.h"
#include "base/sequenced_task_runner.h"
#include "core/host/net/p2p/socket_host_throttler.h"
#include "core/shared/common/p2p_socket_type.h"
#include "core/host/host_message_filter.h"
#include "core/host/host_thread.h"
#include "core/host/net/p2p/socket_host.h"
#include "core/host/net/p2p/webrtc_callbacks.h"
#include "net/log/net_log_source.h"
#include "net/log/net_log_with_source.h"
#include "net/base/ip_address.h"
#include "net/base/ip_endpoint.h"
#include "net/log/net_log.h"
#include "net/base/network_change_notifier.h"
#include "net/dns/host_resolver.h"

namespace net {
struct MutableNetworkTrafficAnnotationTag;
class URLRequestContextGetter;
}

namespace network {
class ProxyResolvingClientSocketFactory;
}

namespace host {
class ResourceContext;
class Domain;

class P2PSocketDispatcherHost
    : public HostMessageFilter,
      public net::NetworkChangeNotifier::NetworkChangeObserver,
      public P2PSocketHost::Delegate {
 public:
  P2PSocketDispatcherHost(//ResourceContext* resource_context,
                          scoped_refptr<Workspace> workspace,
                          Domain* shell,
                          net::URLRequestContextGetter* url_context,
                          const scoped_refptr<base::SingleThreadTaskRunner>& acceptor_task_runner);

  // content::BrowserMessageFilter overrides.
  void OnChannelClosing() override;
  void OnDestruct() const override;
  bool OnMessageReceived(const IPC::Message& message) override;

  // net::NetworkChangeNotifier::NetworkChangeObserver interface.
  void OnNetworkChanged(
      net::NetworkChangeNotifier::ConnectionType type) override;
  // Starts the RTP packet header dumping. Must be called on the IO thread.
  void StartRtpDump(
      bool incoming,
      bool outgoing,
      const WebRtcRtpPacketCallback& packet_callback);

  // Stops the RTP packet header dumping. Must be Called on the UI thread.
  void StopRtpDumpOnUIThread(bool incoming, bool outgoing);

  int GetNextSocketId() override;
  scoped_refptr<Workspace> workspace() override;
  Domain* shell() override;
  void DisposeSocket(P2PSocketHost* socket) override;
  scoped_refptr<base::SingleThreadTaskRunner> acceptor_task_runner() const override;

  void Shutdown();

 protected:
  ~P2PSocketDispatcherHost() override;

 private:
  friend struct HostThread::DeleteOnThread<HostThread::IO>;
  friend class base::DeleteHelper<P2PSocketDispatcherHost>;

  typedef std::map<int, std::unique_ptr<P2PSocketHost>> SocketsMap;

  class DnsRequest;

  P2PSocketHost* LookupSocket(int socket_id);

  // Handlers for the messages coming from the renderer.
  void OnStartNetworkNotifications();
  void OnStopNetworkNotifications();
  void OnGetHostAddress(const std::string& host_name, int32_t request_id);

  void OnCreateSocket(common::P2PSocketType type,
                      int socket_id,
                      const common::P2PSocketOptions& options);
  
  void CreateSocket(common::P2PSocketType type,
                    int socket_id,
                    const common::P2PSocketOptions& options);

  void OnAcceptIncomingTcpConnection(int listen_socket_id,
                                     const net::IPEndPoint& remote_address);

  void AcceptIncomingTcpConnection(
    int listen_socket_id, const net::IPEndPoint& remote_address);

  void OnSend(
      int socket_id,
      const std::vector<char>& data,
      const common::P2PPacketInfo& packet_info,
      const net::MutableNetworkTrafficAnnotationTag& traffic_annotation);
  
  void DoSend(
      int socket_id,
      const std::vector<char>& data,
      const common::P2PPacketInfo& packet_info,
      const net::MutableNetworkTrafficAnnotationTag& traffic_annotation);

  void OnSetOption(int socket_id, common::P2PSocketOption option, int value);
  void OnDestroySocket(int socket_id);
  void OnRpcReceiveMessage(int socket_id, int call_id, int method_type);
  void OnRpcSendMessage(int socket_id, int call_id, const std::vector<char>& data, int method_type);
  void OnRpcSendMessageNow(int socket_id, int call_id, const std::vector<char>& data, int method_type);
  void OnRpcSendStatus(int socket_id, int call_id, int status_code);

  void DoGetNetworkList();
  void SendNetworkList(const net::NetworkInterfaceList& list,
                       const net::IPAddress& default_ipv4_local_address,
                       const net::IPAddress& default_ipv6_local_address);

  // This connects a UDP socket to a public IP address and gets local
  // address. Since it binds to the "any" address (0.0.0.0 or ::) internally, it
  // retrieves the default local address.
  net::IPAddress GetDefaultLocalAddress(int family);

  void OnAddressResolved(DnsRequest* request,
                         const net::IPAddressList& addresses);

  void StopRtpDumpOnIOThread(bool incoming, bool outgoing);

  bool IsSocketIdAlreadyRegistered(int id);

  void DestroySocketsOnThread();
  void DestructOnAcceptor();

  scoped_refptr<Workspace> workspace_;

  Domain* domain_;

  //ResourceContext* resource_context_;
  scoped_refptr<net::URLRequestContextGetter> url_context_;
  // Initialized on browser IO thread.
  std::unique_ptr<network::ProxyResolvingClientSocketFactory>
      proxy_resolving_socket_factory_;

  SocketsMap sockets_;

  bool monitoring_networks_;

  std::set<std::unique_ptr<DnsRequest>> dns_requests_;
  P2PMessageThrottler throttler_;

  net::IPAddress default_ipv4_local_address_;
  net::IPAddress default_ipv6_local_address_;

  bool dump_incoming_rtp_packet_;
  bool dump_outgoing_rtp_packet_;
  WebRtcRtpPacketCallback packet_callback_;

  net::NetLog net_log_;
  // FIXME: HostResolver shouldnt be here and should be global to all host process instead
  std::unique_ptr<net::HostResolver> host_resolver_;

  // Used to call DoGetNetworkList, which may briefly block since getting the
  // default local address involves creating a dummy socket.
  const scoped_refptr<base::SequencedTaskRunner> network_list_task_runner_;
  
  //scoped_refptr<base::SingleThreadTaskRunner> acceptor_task_runner_;
  //base::Thread acceptor_thread_;
  scoped_refptr<base::SingleThreadTaskRunner> acceptor_task_runner_;

  base::AtomicSequenceNumber id_gen_;
  
  // binary tree/rbtree would be cooler here.. now we are O(N)
  std::vector<int> registered_socket_ids_;

  base::WeakPtrFactory<P2PSocketDispatcherHost> weak_ptr_factory_;
 
  DISALLOW_COPY_AND_ASSIGN(P2PSocketDispatcherHost);
};

}  // namespace host

#endif  // CONTENT_BROWSER_RENDERER_HOST_P2P_SOCKET_DISPATCHER_HOST_H_
