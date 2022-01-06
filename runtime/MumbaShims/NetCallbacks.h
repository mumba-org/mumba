// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_RUNTIME_MUMBA_SHIMS_NET_ALLBACKS_H_
#define MUMBA_RUNTIME_MUMBA_SHIMS_NET_ALLBACKS_H_

typedef void* SocketHandleRef;

typedef struct {
  void (*OnSocketCreate)(void* state, int id, int errcode);
  int (*OnAccept)(void* state, SocketHandleRef socket, int id);
  void (*OnError)(void* state);
  void (*OnDataReceived)(void* state, const unsigned char* addr_bytes, int addr_bytes_sz, unsigned short port, const unsigned char* data, long long data_size);
  void (*OnRPCBegin)(void* state, int call_id, const char* method, const char* caller, const char* host);
  void (*OnRPCStreamRead)(void* state, int call_id, const unsigned char* data, long long data_size);
  void (*OnRPCStreamReadEOF)(void* state, int call_id);
  void (*OnRPCStreamWrite)(void* state, int call_id);
  void (*OnRPCUnaryRead)(void* state, int call_id, const unsigned char* data, long long data_size); 
  void (*OnRPCEnd)(void* state, int call_id);
  void (*OnRPCSendMessageAck)(void* state, int call_id, int status);

} SocketCallbacks;

#endif