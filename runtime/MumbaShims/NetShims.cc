// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "NetShims.h"
#include "NetHelper.h"
#include "base/memory/scoped_refptr.h"
#include "core/shared/domain/module/module_state.h"
#include "core/shared/domain/net/socket_dispatcher.h"

struct IPCSocketShim {
  scoped_refptr<IPCSocket> handle;
  IPCSocketShim(scoped_refptr<IPCSocket> _handle): handle(std::move(_handle)) {}
  IPCSocketShim(domain::P2PSocketDispatcher* dispatcher,
    SocketCallbacks callbacks,
    void* state): handle(base::MakeRefCounted<IPCSocket>(dispatcher, callbacks, state)) {}
};

SocketHandleRef SocketCreate(
  ShellContextRef shell,
  SocketCallbacks callbacks,
  void* state,
  int type,
  const uint8_t* local_addr, 
  int local_port,
  uint16_t port_range_min,
  uint16_t port_range_max,
  const uint8_t* remote_addr, 
  int remote_port) {
  domain::ModuleState* engine_state = reinterpret_cast<domain::ModuleState*>(shell);
  domain::P2PSocketDispatcher* dispatcher = engine_state->socket_dispatcher();
  DCHECK(dispatcher);
  IPCSocketShim* handle_shim = new IPCSocketShim(dispatcher, callbacks, state);
  
  net::IPAddress local_ipaddr(local_addr[0], local_addr[1], local_addr[2], local_addr[3]);
  net::IPAddress remote_ipaddr(remote_addr[0], remote_addr[1], remote_addr[2], remote_addr[3]);
  
  handle_shim->handle->Init(
    static_cast<common::P2PSocketType>(type), 
    net::IPEndPoint(local_ipaddr, local_port), 
    port_range_min, 
    port_range_max, 
    common::P2PHostAndIPEndPoint(
      "remotehost.remotedomain.com", 
      net::IPEndPoint(remote_ipaddr, remote_port)));
  
  return handle_shim;
}

SocketHandleRef SocketCreateRPC(
  ShellContextRef shell,
  SocketCallbacks callbacks,
  void* state,
  int type,
  const uint8_t* local_addr, 
  int local_port,
  uint16_t port_range_min,
  uint16_t port_range_max,
  const uint8_t* remote_addr, 
  int remote_port,
  const char* package,
  int package_len,
  const char* name,
  int name_len) {
  
  domain::ModuleState* engine_state = reinterpret_cast<domain::ModuleState*>(shell);
  domain::P2PSocketDispatcher* dispatcher = engine_state->socket_dispatcher();
  DCHECK(dispatcher);
  IPCSocketShim* handle_shim = new IPCSocketShim(dispatcher, callbacks, state);
  
  net::IPAddress local_ipaddr(local_addr[0], local_addr[1], local_addr[2], local_addr[3]);
  net::IPAddress remote_ipaddr(remote_addr[0], remote_addr[1], remote_addr[2], remote_addr[3]);
  
  handle_shim->handle->Init(
    static_cast<common::P2PSocketType>(type), 
    net::IPEndPoint(local_ipaddr, local_port), 
    port_range_min, 
    port_range_max, 
    common::P2PHostAndIPEndPoint(
      "remotehost.remotedomain.com", 
      net::IPEndPoint(remote_ipaddr, remote_port)),
    std::string(package, (size_t)package_len),
    std::string(name, (size_t)name_len));
  
  return handle_shim;
}

SocketHandleRef SocketCreateRPCWithHost(
  ShellContextRef shell,
  SocketCallbacks callbacks,
  void* state,
  int type,
  const char* host,
  const uint8_t* local_addr, 
  int local_port,
  uint16_t port_range_min,
  uint16_t port_range_max,
  const uint8_t* remote_addr, 
  int remote_port,
  const char* package,
  int package_len,
  const char* name,
  int name_len) {
  
  domain::ModuleState* engine_state = reinterpret_cast<domain::ModuleState*>(shell);
  domain::P2PSocketDispatcher* dispatcher = engine_state->socket_dispatcher();
  DCHECK(dispatcher);
  IPCSocketShim* handle_shim = new IPCSocketShim(dispatcher, callbacks, state);
  
  net::IPAddress local_ipaddr(local_addr[0], local_addr[1], local_addr[2], local_addr[3]);
  net::IPAddress remote_ipaddr(remote_addr[0], remote_addr[1], remote_addr[2], remote_addr[3]);
  
  handle_shim->handle->Init(
    static_cast<common::P2PSocketType>(type), 
    net::IPEndPoint(local_ipaddr, local_port), 
    port_range_min, 
    port_range_max, 
    common::P2PHostAndIPEndPoint(
      host, 
      net::IPEndPoint(remote_ipaddr, remote_port)),
    std::string(package, (size_t)package_len),
    std::string(name, (size_t)name_len));
  
  return handle_shim;
}

void SocketClose(SocketHandleRef socket) {
  IPCSocketShim* socket_shim = reinterpret_cast<IPCSocketShim *>(socket);
  socket_shim->handle->Close();
}

void SocketDestroy(SocketHandleRef socket) {
  IPCSocketShim* socket_shim = reinterpret_cast<IPCSocketShim *>(socket);
  socket_shim->handle = nullptr;
  delete socket_shim;
}

void SocketWrite(SocketHandleRef socket, const unsigned char* data, int size) {
  rtc::PacketOptions opt;
  net::IPEndPoint address;
  IPCSocketShim* socket_shim = reinterpret_cast<IPCSocketShim *>(socket);
  std::vector<char> buf(reinterpret_cast<const char *>(data), reinterpret_cast<const char *>(data+size));
  socket_shim->handle->Send(address, buf, opt);
}

void SocketWriteWithAddress(SocketHandleRef socket, const unsigned char* data, int size, const unsigned char* addr, int addr_size, int port) {
  rtc::PacketOptions opt;
  net::IPEndPoint address(net::IPAddress(addr, (size_t)addr_size), (uint16_t)port);
  IPCSocketShim* socket_shim = reinterpret_cast<IPCSocketShim *>(socket);
  std::vector<char> buf(reinterpret_cast<const char *>(data), reinterpret_cast<const char *>(data+size));
  socket_shim->handle->Send(address, buf, opt);
}

void SocketSetState(SocketHandleRef socket, void* state) {
  IPCSocketShim* socket_shim = reinterpret_cast<IPCSocketShim *>(socket);
  socket_shim->handle->set_state(state);
}

void SocketSetStateAndCallbacks(SocketHandleRef socket, void* state, SocketCallbacks callbacks) {
  IPCSocketShim* socket_shim = reinterpret_cast<IPCSocketShim *>(socket);
  socket_shim->handle->set_state(state);
  socket_shim->handle->set_callbacks(callbacks);
}

void SocketReceiveRPCMessage(SocketHandleRef socket, int call_id, int method_type) {
  IPCSocketShim* socket_shim = reinterpret_cast<IPCSocketShim *>(socket);
  socket_shim->handle->ReceiveRPCMessage(call_id, method_type);
}

void SocketSendRPCMessage(SocketHandleRef socket, int call_id, const unsigned char* data, int size, int method_type) {
  IPCSocketShim* socket_shim = reinterpret_cast<IPCSocketShim *>(socket);
  std::vector<char> buf(reinterpret_cast<const char *>(data), reinterpret_cast<const char *>(data+size));
  socket_shim->handle->SendRPCMessage(call_id, buf, method_type);
}

void SocketSendRPCMessageNow(SocketHandleRef socket, int call_id, const unsigned char* data, int size, int method_type) {
  IPCSocketShim* socket_shim = reinterpret_cast<IPCSocketShim *>(socket);
  std::vector<char> buf(reinterpret_cast<const char *>(data), reinterpret_cast<const char *>(data+size));
  socket_shim->handle->SendRPCMessageNow(call_id, buf, method_type);
}

void SocketSendRPCStatus(SocketHandleRef socket, int call_id, int status) {
  IPCSocketShim* socket_shim = reinterpret_cast<IPCSocketShim *>(socket);
  socket_shim->handle->SendRPCStatus(call_id, status);
}