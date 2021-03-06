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
#ifdef GRPC_POSIX_SOCKET

#include "rpc/iomgr/sockaddr.h"

#include "rpc/iomgr/resolve_address.h"

#include <string.h>
#include <sys/types.h>

#include <rpc/support/alloc.h>
#include <rpc/support/host_port.h>
#include <rpc/support/log.h>
#include <rpc/support/string_util.h>
#include <rpc/support/thd.h>
#include <rpc/support/time.h>
#include <rpc/support/useful.h>
#include "rpc/iomgr/block_annotate.h"
#include "rpc/iomgr/executor.h"
#include "rpc/iomgr/iomgr_internal.h"
#include "rpc/iomgr/unix_sockets_posix.h"
#include "rpc/support/string.h"

static grpc_error* blocking_resolve_address_impl(
    const char* name, const char* default_port,
    grpc_resolved_addresses** addresses) {
  struct addrinfo hints;
  struct addrinfo *result = nullptr, *resp;
  char* host;
  char* port;
  int s;
  size_t i;
  grpc_error* err;

  if (name[0] == 'u' && name[1] == 'n' && name[2] == 'i' && name[3] == 'x' &&
      name[4] == ':' && name[5] != 0) {
    return grpc_resolve_unix_domain_address(name + 5, addresses);
  }

  /* parse name, splitting it into host and port parts */
  gpr_split_host_port(name, &host, &port);
  if (host == nullptr) {
    err = grpc_error_set_str(
        GRPC_ERROR_CREATE_FROM_STATIC_STRING("unparseable host:port"),
        GRPC_ERROR_STR_TARGET_ADDRESS, grpc_slice_from_copied_string(name));
    goto done;
  }
  if (port == nullptr) {
    if (default_port == nullptr) {
      err = grpc_error_set_str(
          GRPC_ERROR_CREATE_FROM_STATIC_STRING("no port in name"),
          GRPC_ERROR_STR_TARGET_ADDRESS, grpc_slice_from_copied_string(name));
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
    /* Retry if well-known service name is recognized */
    const char* svc[][2] = {{"http", "80"}, {"https", "443"}};
    for (i = 0; i < GPR_ARRAY_SIZE(svc); i++) {
      if (strcmp(port, svc[i][0]) == 0) {
        GRPC_SCHEDULING_START_BLOCKING_REGION;
        s = getaddrinfo(host, svc[i][1], &hints, &result);
        GRPC_SCHEDULING_END_BLOCKING_REGION_NO_EXEC_CTX;
        break;
      }
    }
  }

  if (s != 0) {
    err = grpc_error_set_str(
        grpc_error_set_str(
            grpc_error_set_str(
                grpc_error_set_int(
                    GRPC_ERROR_CREATE_FROM_STATIC_STRING("OS Error"),
                    GRPC_ERROR_INT_ERRNO, s),
                GRPC_ERROR_STR_OS_ERROR,
                grpc_slice_from_static_string(gai_strerror(s))),
            GRPC_ERROR_STR_SYSCALL,
            grpc_slice_from_static_string("getaddrinfo")),
        GRPC_ERROR_STR_TARGET_ADDRESS, grpc_slice_from_copied_string(name));
    goto done;
  }

  /* Success path: set addrs non-NULL, fill it in */
  *addresses =
      (grpc_resolved_addresses*)gpr_malloc(sizeof(grpc_resolved_addresses));
  (*addresses)->naddrs = 0;
  for (resp = result; resp != nullptr; resp = resp->ai_next) {
    (*addresses)->naddrs++;
  }
  (*addresses)->addrs = (grpc_resolved_address*)gpr_malloc(
      sizeof(grpc_resolved_address) * (*addresses)->naddrs);
  i = 0;
  for (resp = result; resp != nullptr; resp = resp->ai_next) {
    memcpy(&(*addresses)->addrs[i].addr, resp->ai_addr, resp->ai_addrlen);
    (*addresses)->addrs[i].len = resp->ai_addrlen;
    i++;
  }
  err = GRPC_ERROR_NONE;

done:
  gpr_free(host);
  gpr_free(port);
  if (result) {
    freeaddrinfo(result);
  }
  return err;
}

grpc_error* (*grpc_blocking_resolve_address)(
    const char* name, const char* default_port,
    grpc_resolved_addresses** addresses) = blocking_resolve_address_impl;

typedef struct {
  char* name;
  char* default_port;
  grpc_closure* on_done;
  grpc_resolved_addresses** addrs_out;
  grpc_closure request_closure;
  void* arg;
} request;

/* Callback to be passed to grpc_executor to asynch-ify
 * grpc_blocking_resolve_address */
static void do_request_thread(grpc_exec_ctx* exec_ctx, void* rp,
                              grpc_error* error) {
  request* r = (request*)rp;
  GRPC_CLOSURE_SCHED(
      exec_ctx, r->on_done,
      grpc_blocking_resolve_address(r->name, r->default_port, r->addrs_out));
  gpr_free(r->name);
  gpr_free(r->default_port);
  gpr_free(r);
}

void grpc_resolved_addresses_destroy(grpc_resolved_addresses* addrs) {
  if (addrs != nullptr) {
    gpr_free(addrs->addrs);
  }
  gpr_free(addrs);
}

static void resolve_address_impl(grpc_exec_ctx* exec_ctx, const char* name,
                                 const char* default_port,
                                 grpc_pollset_set* interested_parties,
                                 grpc_closure* on_done,
                                 grpc_resolved_addresses** addrs) {
  request* r = (request*)gpr_malloc(sizeof(request));
  GRPC_CLOSURE_INIT(&r->request_closure, do_request_thread, r,
                    grpc_executor_scheduler(GRPC_EXECUTOR_SHORT));
  r->name = gpr_strdup(name);
  r->default_port = gpr_strdup(default_port);
  r->on_done = on_done;
  r->addrs_out = addrs;
  GRPC_CLOSURE_SCHED(exec_ctx, &r->request_closure, GRPC_ERROR_NONE);
}

void (*grpc_resolve_address)(
    grpc_exec_ctx* exec_ctx, const char* name, const char* default_port,
    grpc_pollset_set* interested_parties, grpc_closure* on_done,
    grpc_resolved_addresses** addrs) = resolve_address_impl;

#endif
