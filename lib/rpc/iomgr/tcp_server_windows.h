/*
 *
 * Copyright 2017 gRPC authors.
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

#ifndef GRPC_CORE_LIB_IOMGR_TCP_SERVER_WINDOWS_H
#define GRPC_CORE_LIB_IOMGR_TCP_SERVER_WINDOWS_H

#include "rpc/iomgr/resolve_address.h"
#include "rpc/iomgr/socket_windows.h"
#include "rpc/iomgr/tcp_server.h"

/* one listening port */
typedef struct grpc_tcp_listener grpc_tcp_listener;
struct grpc_tcp_listener {
  /* This seemingly magic number comes from AcceptEx's documentation. each
     address buffer needs to have at least 16 more bytes at their end. */
  uint8_t addresses[(sizeof(struct sockaddr_in6) + 16) * 2];
  /* This will hold the socket for the next accept. */
  SOCKET new_socket;
  /* The listener winsocket. */
  grpc_winsocket* socket;
  /* The actual TCP port number. */
  int port;
  unsigned port_index;
  grpc_tcp_server* server;
  /* The cached AcceptEx for that port. */
  LPFN_ACCEPTEX AcceptEx;
  int shutting_down;
  int outstanding_calls;
  void* state;
  grpc_closure read_closure;
  /* closure for socket notification of accept being ready */
  //grpc_closure on_accept;
  /* linked list */
  struct grpc_tcp_listener* next;
};

/* the overall server */
struct grpc_tcp_server {
  gpr_refcount refs;
  /* Called whenever accept() succeeds on a server port. */
  //grpc_tcp_server_cb on_accept_cb;
  void* on_accept_cb_arg;

  gpr_mu mu;

  /* active port count: how many ports are actually still listening */
  int active_ports;

  /* linked list of server ports */
  grpc_tcp_listener* head;
  grpc_tcp_listener* tail;

  /* List of closures passed to shutdown_starting_add(). */
  grpc_closure_list shutdown_starting;

  /* shutdown callback */
  grpc_closure* shutdown_complete;

  grpc_channel_args* channel_args;

  void* state;
};

#endif