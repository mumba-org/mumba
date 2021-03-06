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

#include "rpc/iomgr/port.h"
#ifdef GRPC_WINSOCK_SOCKET

#include "rpc/iomgr/sockaddr.h"

#include "rpc/iomgr/resolve_address.h"

#include <inttypes.h>
#include <string.h>
#include <sys/types.h>

#include <rpc/support/alloc.h>
#include <rpc/support/host_port.h>
#include <rpc/support/log.h>
#include <rpc/support/log_windows.h>
#include <rpc/support/string_util.h>
#include <rpc/support/thd.h>
#include <rpc/support/time.h>
#include "rpc/iomgr/block_annotate.h"
#include "rpc/iomgr/executor.h"
#include "rpc/iomgr/iomgr_internal.h"
#include "rpc/iomgr/sockaddr_utils.h"
#include "rpc/support/string.h"

typedef struct {
  char* name;
  char* default_port;
  grpc_closure request_closure;
  grpc_closure* on_done;
  grpc_resolved_addresses** addresses;
} request;

static grpc_error* blocking_resolve_address_impl(
    const char* name, const char* default_port,
    grpc_resolved_addresses** addresses) {
  struct addrinfo hints;
  struct addrinfo *result = NULL, *resp;
  char* host;
  char* port;
  int s;
  size_t i;
  grpc_error* error = GRPC_ERROR_NONE;

  /* parse name, splitting it into host and port parts */
  gpr_split_host_port(name, &host, &port);
  if (host == NULL) {
    char* msg;
    gpr_asprintf(&msg, "unparseable host:port: '%s'", name);
    error = GRPC_ERROR_CREATE_FROM_COPIED_STRING(msg);
    gpr_free(msg);
    goto done;
  }
  if (port == NULL) {
    if (default_port == NULL) {
      char* msg;
      gpr_asprintf(&msg, "no port in name '%s'", name);
      error = GRPC_ERROR_CREATE_FROM_COPIED_STRING(msg);
      gpr_free(msg);
      goto done;
    }
    port = gpr_strdup(default_port);
  }

  /* Call getaddrinfo */
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;     /* ipv4 or ipv6 */
  hints.ai_socktype = SOCK_STREAM; /* stream socket */
  hints.ai_flags = AI_PASSIVE;     /* for wildcard IP address */

  GRPC_SCHEDULING_START_BLOCKING_REGION;
  s = getaddrinfo(host, port, &hints, &result);
  GRPC_SCHEDULING_END_BLOCKING_REGION_NO_EXEC_CTX;
  if (s != 0) {
    error = GRPC_WSA_ERROR(WSAGetLastError(), "getaddrinfo");
    goto done;
  }

  /* Success path: set addrs non-NULL, fill it in */
  (*addresses) =
      (grpc_resolved_addresses*)gpr_malloc(sizeof(grpc_resolved_addresses));
  (*addresses)->naddrs = 0;
  for (resp = result; resp != NULL; resp = resp->ai_next) {
    (*addresses)->naddrs++;
  }
  (*addresses)->addrs = (grpc_resolved_address*)gpr_malloc(
      sizeof(grpc_resolved_address) * (*addresses)->naddrs);
  i = 0;
  for (resp = result; resp != NULL; resp = resp->ai_next) {
    memcpy(&(*addresses)->addrs[i].addr, resp->ai_addr, resp->ai_addrlen);
    (*addresses)->addrs[i].len = resp->ai_addrlen;
    i++;
  }

  {
    for (i = 0; i < (*addresses)->naddrs; i++) {
      char* buf;
      grpc_sockaddr_to_string(&buf, &(*addresses)->addrs[i], 0);
      gpr_free(buf);
    }
  }

done:
  gpr_free(host);
  gpr_free(port);
  if (result) {
    freeaddrinfo(result);
  }
  return error;
}

grpc_error* (*grpc_blocking_resolve_address)(
    const char* name, const char* default_port,
    grpc_resolved_addresses** addresses) = blocking_resolve_address_impl;

/* Callback to be passed to grpc_executor to asynch-ify
 * grpc_blocking_resolve_address */
static void do_request_thread(grpc_exec_ctx* exec_ctx, void* rp,
                              grpc_error* error) {
  request* r = (request*)rp;
  if (error == GRPC_ERROR_NONE) {
    error =
        grpc_blocking_resolve_address(r->name, r->default_port, r->addresses);
  } else {
    GRPC_ERROR_REF(error);
  }
  GRPC_CLOSURE_SCHED(exec_ctx, r->on_done, error);
  gpr_free(r->name);
  gpr_free(r->default_port);
  gpr_free(r);
}

void grpc_resolved_addresses_destroy(grpc_resolved_addresses* addrs) {
  if (addrs != NULL) {
    gpr_free(addrs->addrs);
  }
  gpr_free(addrs);
}

static void resolve_address_impl(grpc_exec_ctx* exec_ctx, const char* name,
                                 const char* default_port,
                                 grpc_pollset_set* interested_parties,
                                 grpc_closure* on_done,
                                 grpc_resolved_addresses** addresses) {
  request* r = (request*)gpr_malloc(sizeof(request));
  GRPC_CLOSURE_INIT(&r->request_closure, do_request_thread, r,
                    grpc_executor_scheduler(GRPC_EXECUTOR_SHORT));
  r->name = gpr_strdup(name);
  r->default_port = gpr_strdup(default_port);
  r->on_done = on_done;
  r->addresses = addresses;
  GRPC_CLOSURE_SCHED(exec_ctx, &r->request_closure, GRPC_ERROR_NONE);
}

void (*grpc_resolve_address)(
    grpc_exec_ctx* exec_ctx, const char* name, const char* default_port,
    grpc_pollset_set* interested_parties, grpc_closure* on_done,
    grpc_resolved_addresses** addresses) = resolve_address_impl;

#endif
