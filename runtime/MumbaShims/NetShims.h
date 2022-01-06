// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_RUNTIME_MUMBA_SHIMS_NET_H_
#define MUMBA_RUNTIME_MUMBA_SHIMS_NET_H_

#include "Globals.h"
#include "NetCallbacks.h"

typedef void* ShellContextRef;
typedef void* SocketHandleRef;

EXPORT SocketHandleRef SocketCreate(
  ShellContextRef shell,
  SocketCallbacks callbacks,
  void* state,
  int type,
  const uint8_t* local_addr, 
  int local_port,
  uint16_t port_range_min,
  uint16_t port_range_max,
  const uint8_t* remote_addr, 
  int remote_port);

EXPORT SocketHandleRef SocketCreateRPC(
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
  int name_len);

EXPORT SocketHandleRef SocketCreateRPCWithHost(
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
  int name_len);

EXPORT void SocketClose(SocketHandleRef socket);
EXPORT void SocketDestroy(SocketHandleRef socket);
EXPORT void SocketWrite(SocketHandleRef socket, const unsigned char* data, int size);
EXPORT void SocketWriteWithAddress(SocketHandleRef socket, const unsigned char* data, int size, const unsigned char* addr, int addr_size, int port);
EXPORT void SocketSetState(SocketHandleRef socket, void* state);
EXPORT void SocketSetStateAndCallbacks(SocketHandleRef socket, void* state, SocketCallbacks callbacks);
EXPORT void SocketReceiveRPCMessage(SocketHandleRef socket, int call_id, int method_type);
EXPORT void SocketSendRPCMessage(SocketHandleRef socket, int call_id, const unsigned char* data, int size, int method_type);
EXPORT void SocketSendRPCMessageNow(SocketHandleRef socket, int call_id, const unsigned char* data, int size, int method_type);
EXPORT void SocketSendRPCStatus(SocketHandleRef socket, int call_id, int status);

#endif