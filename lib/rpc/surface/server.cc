/*
 *
 * Copyright 2015-2016 gRPC authors.
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

#include "rpc/surface/server.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include <rpc/support/alloc.h>
#include <rpc/support/log.h>
#include <rpc/support/string_util.h>
#include <rpc/support/useful.h>

#include "rpc/channel/channel_args.h"
#include "rpc/channel/connected_channel.h"
#include "rpc/debug/stats.h"
#include "rpc/iomgr/executor.h"
#include "rpc/iomgr/iomgr.h"
#include "rpc/slice/slice_internal.h"
#include "rpc/support/mpscq.h"
#include "rpc/support/spinlock.h"
#include "rpc/support/string.h"
#include "rpc/surface/api_trace.h"
#include "rpc/surface/call.h"
#include "rpc/surface/channel.h"
#include "rpc/surface/completion_queue.h"
#include "rpc/surface/init.h"
#include "rpc/transport/metadata.h"
#include "rpc/transport/static_metadata.h"

// typedef struct listener {
//   void* arg;
//   void (*start)(void (*)(grpc_exec_ctx*, void*, grpc_error*),
//                 grpc_exec_ctx* exec_ctx, grpc_server* server, void* arg,
//                 grpc_pollset** pollsets, size_t npollsets);

//   void (*destroy)(grpc_exec_ctx* exec_ctx, grpc_server* server, void* arg, grpc_closure* on_done);
  
//   void (*on_read)(grpc_exec_ctx*, void*, grpc_error*);
//   struct listener* next;
//   grpc_closure destroy_done;
// } listener;

//typedef struct call_data call_data;
//typedef struct channel_data channel_data;
//typedef struct registered_method registered_method;

typedef enum { BATCH_CALL, REGISTERED_CALL } requested_call_type;

grpc_core::TraceFlag grpc_server_channel_trace(false, "server_channel");

typedef struct requested_call {
  gpr_mpscq_node request_link; /* must be first */
  requested_call_type type;
  size_t cq_idx;
  void* tag;
  grpc_server* server;
  grpc_completion_queue* cq_bound_to_call;
  grpc_call** call;
  grpc_cq_completion completion;
  grpc_metadata_array* initial_metadata;
  union {
    struct {
      grpc_call_details* details;
    } batch;
    struct {
      registered_method* method;
      gpr_timespec* deadline;
      grpc_byte_buffer** optional_payload;
    } registered;
  } data;
} requested_call;

typedef struct channel_registered_method {
  registered_method* server_registered_method;
  uint32_t flags;
  bool has_host;
  grpc_slice method;
  grpc_slice host;
} channel_registered_method;

// struct channel_data {
//   grpc_server* server;
//   grpc_connectivity_state connectivity_state;
//   grpc_channel* channel;
//   size_t cq_idx;
//   /* linked list of all channels on a server */
//   channel_data* next;
//   channel_data* prev;
//   channel_registered_method* registered_methods;
//   uint32_t registered_method_slots;
//   uint32_t registered_method_max_probes;
//   grpc_closure finish_destroy_channel_closure;
//   grpc_closure channel_connectivity_changed;
// };

typedef struct shutdown_tag {
  void* tag;
  grpc_completion_queue* cq;
  grpc_cq_completion completion;
} shutdown_tag;

typedef enum {
  /* waiting for metadata */
  NOT_STARTED,
  /* inital metadata read, not flow controlled in yet */
  PENDING,
  /* flow controlled in, on completion queue */
  ACTIVATED,
  /* cancelled before being queued */
  ZOMBIED
} call_state;

typedef struct request_matcher request_matcher;

// struct call_data {
//   grpc_call* call;

//   gpr_atm state;

//   bool path_set;
//   bool host_set;
//   grpc_slice path;
//   grpc_slice host;
//   grpc_millis deadline;

//   grpc_completion_queue* cq_new;

//   grpc_metadata_batch* recv_initial_metadata;
//   uint32_t recv_initial_metadata_flags;
//   grpc_metadata_array initial_metadata;

//   request_matcher* matcher;
//   grpc_byte_buffer* payload;

//   grpc_closure got_initial_metadata;
//   grpc_closure server_on_recv_initial_metadata;
//   grpc_closure kill_zombie_closure;
//   grpc_closure* on_done_recv_initial_metadata;

//   grpc_closure publish;

//   call_data* pending_next;
// };

// struct request_matcher {
//   grpc_server* server;
//   call_data* pending_head;
//   call_data* pending_tail;
//   gpr_locked_mpscq* requests_per_cq;
// };

struct registered_method {
  char* method;
  char* host;
  grpc_server_register_method_payload_handling payload_handling;
  uint32_t flags;
  /* one request matcher per method */
  request_matcher matcher;
  registered_method* next;
};

typedef struct {
  grpc_channel** channels;
  size_t num_channels;
} channel_broadcaster;

// struct grpc_server {
//   grpc_channel_args* channel_args;

//   grpc_completion_queue** cqs;
//   grpc_pollset** pollsets;
//   size_t cq_count;
//   size_t pollset_count;
//   bool started;

//   /* The two following mutexes control access to server-state
//      mu_global controls access to non-call-related state (e.g., channel state)
//      mu_call controls access to call-related state (e.g., the call lists)

//      If they are ever required to be nested, you must lock mu_global
//      before mu_call. This is currently used in shutdown processing
//      (grpc_server_shutdown_and_notify and maybe_finish_shutdown) */
//   gpr_mu mu_global; /* mutex for server and channel state */
//   gpr_mu mu_call;   /* mutex for call-specific state */

//   /* startup synchronization: flag is protected by mu_global, signals whether
//      we are doing the listener start routine or not */
//   bool starting;
//   gpr_cv starting_cv;

//   registered_method* registered_methods;
//   /** one request matcher for unregistered methods */
//   request_matcher unregistered_request_matcher;

//   gpr_atm shutdown_flag;
//   uint8_t shutdown_published;
//   size_t num_shutdown_tags;
//   shutdown_tag* shutdown_tags;

//   channel_data root_channel_data;

//   listener* listeners;
//   int listeners_destroyed;
//   gpr_refcount internal_refcount;

//   /** when did we print the last shutdown progress message */
//   gpr_timespec last_shutdown_message_time;
// };

#define SERVER_FROM_CALL_ELEM(elem) \
  (((channel_data*)(elem)->channel_data)->server)

static void publish_new_rpc(grpc_exec_ctx* exec_ctx, void* calld,
                            grpc_error* error);
static void fail_call(grpc_exec_ctx* exec_ctx, grpc_server* server,
                      size_t cq_idx, requested_call* rc, grpc_error* error);
/* Before calling maybe_finish_shutdown, we must hold mu_global and not
   hold mu_call */
static void maybe_finish_shutdown(grpc_exec_ctx* exec_ctx, grpc_server* server);

/*
 * channel broadcaster
 */

/* assumes server locked */
static void channel_broadcaster_init(grpc_server* s, channel_broadcaster* cb) {
  channel_data* c;
  size_t count = 0;
  for (c = s->root_channel_data.next; c != &s->root_channel_data; c = c->next) {
    count++;
  }
  cb->num_channels = count;
  cb->channels =
      (grpc_channel**)gpr_malloc(sizeof(*cb->channels) * cb->num_channels);
  count = 0;
  for (c = s->root_channel_data.next; c != &s->root_channel_data; c = c->next) {
    cb->channels[count++] = c->channel;
    GRPC_CHANNEL_INTERNAL_REF(c->channel, "broadcast");
  }
}

struct shutdown_cleanup_args {
  grpc_closure closure;
  grpc_slice slice;
};

static void shutdown_cleanup(grpc_exec_ctx* exec_ctx, void* arg,
                             grpc_error* error) {
  struct shutdown_cleanup_args* a = (struct shutdown_cleanup_args*)arg;
  grpc_slice_unref_internal(exec_ctx, a->slice);
  gpr_free(a);
}

static void send_shutdown(grpc_exec_ctx* exec_ctx, grpc_channel* channel,
                          bool send_goaway, grpc_error* send_disconnect) {
  struct shutdown_cleanup_args* sc =
      (struct shutdown_cleanup_args*)gpr_malloc(sizeof(*sc));
  GRPC_CLOSURE_INIT(&sc->closure, shutdown_cleanup, sc,
                    grpc_schedule_on_exec_ctx);
  grpc_transport_op* op = grpc_make_transport_op(&sc->closure);
  grpc_channel_element* elem;

  op->goaway_error =
      send_goaway ? grpc_error_set_int(
                        GRPC_ERROR_CREATE_FROM_STATIC_STRING("Server shutdown"),
                        GRPC_ERROR_INT_GRPC_STATUS, GRPC_STATUS_OK)
                  : GRPC_ERROR_NONE;
  op->set_accept_stream = true;
  sc->slice = grpc_slice_from_copied_string("Server shutdown");
  op->disconnect_with_error = send_disconnect;

  elem = grpc_channel_stack_element(grpc_channel_get_channel_stack(channel), 0);
  elem->filter->start_transport_op(exec_ctx, elem, op);
}

static void channel_broadcaster_shutdown(grpc_exec_ctx* exec_ctx,
                                         channel_broadcaster* cb,
                                         bool send_goaway,
                                         grpc_error* force_disconnect) {
  size_t i;

  for (i = 0; i < cb->num_channels; i++) {
    send_shutdown(exec_ctx, cb->channels[i], send_goaway,
                  GRPC_ERROR_REF(force_disconnect));
    GRPC_CHANNEL_INTERNAL_UNREF(exec_ctx, cb->channels[i], "broadcast");
  }
  gpr_free(cb->channels);
  GRPC_ERROR_UNREF(force_disconnect);
}

/*
 * request_matcher
 */

static void request_matcher_init(request_matcher* rm, grpc_server* server) {
  memset(rm, 0, sizeof(*rm));
  rm->server = server;
  rm->requests_per_cq = (gpr_locked_mpscq*)gpr_malloc(
      sizeof(*rm->requests_per_cq) * server->cq_count);
  for (size_t i = 0; i < server->cq_count; i++) {
    gpr_locked_mpscq_init(&rm->requests_per_cq[i]);
  }
}

static void request_matcher_destroy(request_matcher* rm) {
  for (size_t i = 0; i < rm->server->cq_count; i++) {
    GPR_ASSERT(gpr_locked_mpscq_pop(&rm->requests_per_cq[i]) == nullptr);
    gpr_locked_mpscq_destroy(&rm->requests_per_cq[i]);
  }
  gpr_free(rm->requests_per_cq);
}

static void kill_zombie(grpc_exec_ctx* exec_ctx, void* elem,
                        grpc_error* error) {
  grpc_call_unref(grpc_call_from_top_element((grpc_call_element*)elem));
}

static void request_matcher_zombify_all_pending_calls(grpc_exec_ctx* exec_ctx,
                                                      request_matcher* rm) {
  while (rm->pending_head) {
    call_data* calld = rm->pending_head;
    rm->pending_head = calld->pending_next;
    gpr_atm_no_barrier_store(&calld->state, ZOMBIED);
    GRPC_CLOSURE_INIT(
        &calld->kill_zombie_closure, kill_zombie,
        grpc_call_stack_element(grpc_call_get_call_stack(calld->call), 0),
        grpc_schedule_on_exec_ctx);
    GRPC_CLOSURE_SCHED(exec_ctx, &calld->kill_zombie_closure, GRPC_ERROR_NONE);
  }
}

static void request_matcher_kill_requests(grpc_exec_ctx* exec_ctx,
                                          grpc_server* server,
                                          request_matcher* rm,
                                          grpc_error* error) {
  requested_call* rc;
  for (size_t i = 0; i < server->cq_count; i++) {
    while ((rc = (requested_call*)gpr_locked_mpscq_pop(
                &rm->requests_per_cq[i])) != nullptr) {
      fail_call(exec_ctx, server, i, rc, GRPC_ERROR_REF(error));
    }
  }
  GRPC_ERROR_UNREF(error);
}

/*
 * server proper
 */

static void server_ref(grpc_server* server) {
  gpr_ref(&server->internal_refcount);
}

static void server_delete(grpc_exec_ctx* exec_ctx, grpc_server* server) {
  registered_method* rm;
  size_t i;
  grpc_channel_args_destroy(exec_ctx, server->channel_args);
  gpr_mu_destroy(&server->mu_global);
  gpr_mu_destroy(&server->mu_call);
  gpr_cv_destroy(&server->starting_cv);
  while ((rm = server->registered_methods) != nullptr) {
    server->registered_methods = rm->next;
    if (server->started) {
      request_matcher_destroy(&rm->matcher);
    }
    gpr_free(rm->method);
    gpr_free(rm->host);
    gpr_free(rm);
  }
  if (server->started) {
    request_matcher_destroy(&server->unregistered_request_matcher);
  }
  for (i = 0; i < server->cq_count; i++) {
    GRPC_CQ_INTERNAL_UNREF(exec_ctx, server->cqs[i], "server");
  }
  gpr_free(server->cqs);
  gpr_free(server->pollsets);
  gpr_free(server->shutdown_tags);
  gpr_free(server);
}

static void server_unref(grpc_exec_ctx* exec_ctx, grpc_server* server) {
  if (gpr_unref(&server->internal_refcount)) {
    server_delete(exec_ctx, server);
  }
}

static int is_channel_orphaned(channel_data* chand) {
  return chand->next == chand;
}

static void orphan_channel(channel_data* chand) {
  chand->next->prev = chand->prev;
  chand->prev->next = chand->next;
  chand->next = chand->prev = chand;
}

static void finish_destroy_channel(grpc_exec_ctx* exec_ctx, void* cd,
                                   grpc_error* error) {
  channel_data* chand = (channel_data*)cd;
  grpc_server* server = chand->server;
  GRPC_CHANNEL_INTERNAL_UNREF(exec_ctx, chand->channel, "server");
  server_unref(exec_ctx, server);
}

static void destroy_channel(grpc_exec_ctx* exec_ctx, channel_data* chand,
                            grpc_error* error) {
  if (is_channel_orphaned(chand)) return;
  GPR_ASSERT(chand->server != nullptr);
  orphan_channel(chand);
  server_ref(chand->server);
  maybe_finish_shutdown(exec_ctx, chand->server);
  GRPC_CLOSURE_INIT(&chand->finish_destroy_channel_closure,
                    finish_destroy_channel, chand, grpc_schedule_on_exec_ctx);

  if (grpc_server_channel_trace.enabled() && error != GRPC_ERROR_NONE) {
    const char* msg = grpc_error_string(error);
    gpr_log(GPR_INFO, "Disconnected client: %s", msg);
  }
  GRPC_ERROR_UNREF(error);

  grpc_transport_op* op =
      grpc_make_transport_op(&chand->finish_destroy_channel_closure);
  op->set_accept_stream = true;
  grpc_channel_next_op(exec_ctx,
                       grpc_channel_stack_element(
                           grpc_channel_get_channel_stack(chand->channel), 0),
                       op);
}

static void done_request_event(grpc_exec_ctx* exec_ctx, void* req,
                               grpc_cq_completion* c) {
  gpr_free(req);
}

static void publish_call(grpc_exec_ctx* exec_ctx, grpc_server* server,
                         call_data* calld, size_t cq_idx, requested_call* rc) {
  grpc_call_set_completion_queue(exec_ctx, calld->call, rc->cq_bound_to_call);
  grpc_call* call = calld->call;
  *rc->call = call;
  calld->cq_new = server->cqs[cq_idx];
  GPR_SWAP(grpc_metadata_array, *rc->initial_metadata, calld->initial_metadata);
  switch (rc->type) {
    case BATCH_CALL:
      GPR_ASSERT(calld->host_set);
      GPR_ASSERT(calld->path_set);
      rc->data.batch.details->host = grpc_slice_ref_internal(calld->host);
      rc->data.batch.details->method = grpc_slice_ref_internal(calld->path);
      rc->data.batch.details->deadline =
          grpc_millis_to_timespec(calld->deadline, GPR_CLOCK_MONOTONIC);
      rc->data.batch.details->flags = calld->recv_initial_metadata_flags;
      break;
    case REGISTERED_CALL:
      *rc->data.registered.deadline =
          grpc_millis_to_timespec(calld->deadline, GPR_CLOCK_MONOTONIC);
      if (rc->data.registered.optional_payload) {
        *rc->data.registered.optional_payload = calld->payload;
        calld->payload = nullptr;
      }
      break;
    default:
      GPR_UNREACHABLE_CODE(return );
  }

  grpc_cq_end_op(exec_ctx, calld->cq_new, rc->tag, GRPC_ERROR_NONE,
                 done_request_event, rc, &rc->completion);
}

static void publish_new_rpc(grpc_exec_ctx* exec_ctx, void* arg,
                            grpc_error* error) {
  grpc_call_element* call_elem = (grpc_call_element*)arg;
  call_data* calld = (call_data*)call_elem->call_data;
  channel_data* chand = (channel_data*)call_elem->channel_data;
  request_matcher* rm = calld->matcher;
  grpc_server* server = rm->server;

  if (error != GRPC_ERROR_NONE || gpr_atm_acq_load(&server->shutdown_flag)) {
    gpr_atm_no_barrier_store(&calld->state, ZOMBIED);
    GRPC_CLOSURE_INIT(
        &calld->kill_zombie_closure, kill_zombie,
        grpc_call_stack_element(grpc_call_get_call_stack(calld->call), 0),
        grpc_schedule_on_exec_ctx);
    GRPC_CLOSURE_SCHED(exec_ctx, &calld->kill_zombie_closure,
                       GRPC_ERROR_REF(error));
    return;
  }

  for (size_t i = 0; i < server->cq_count; i++) {
    size_t cq_idx = (chand->cq_idx + i) % server->cq_count;
    requested_call* rc =
        (requested_call*)gpr_locked_mpscq_try_pop(&rm->requests_per_cq[cq_idx]);
    if (rc == nullptr) {
      continue;
    } else {
      GRPC_STATS_INC_SERVER_CQS_CHECKED(exec_ctx, i);
      gpr_atm_no_barrier_store(&calld->state, ACTIVATED);
      publish_call(exec_ctx, server, calld, cq_idx, rc);
      return; /* early out */
    }
  }

  /* no cq to take the request found: queue it on the slow list */
  GRPC_STATS_INC_SERVER_SLOWPATH_REQUESTS_QUEUED(exec_ctx);
  gpr_mu_lock(&server->mu_call);

  // We need to ensure that all the queues are empty.  We do this under
  // the server mu_call lock to ensure that if something is added to
  // an empty request queue, it will block until the call is actually
  // added to the pending list.
  for (size_t i = 0; i < server->cq_count; i++) {
    size_t cq_idx = (chand->cq_idx + i) % server->cq_count;
    requested_call* rc =
        (requested_call*)gpr_locked_mpscq_pop(&rm->requests_per_cq[cq_idx]);
    if (rc == nullptr) {
      continue;
    } else {
      gpr_mu_unlock(&server->mu_call);
      GRPC_STATS_INC_SERVER_CQS_CHECKED(exec_ctx, i + server->cq_count);
      gpr_atm_no_barrier_store(&calld->state, ACTIVATED);
      publish_call(exec_ctx, server, calld, cq_idx, rc);
      return; /* early out */
    }
  }

  gpr_atm_no_barrier_store(&calld->state, PENDING);
  if (rm->pending_head == nullptr) {
    rm->pending_tail = rm->pending_head = calld;
  } else {
    rm->pending_tail->pending_next = calld;
    rm->pending_tail = calld;
  }
  calld->pending_next = nullptr;
  gpr_mu_unlock(&server->mu_call);
}

static void finish_start_new_rpc(
    grpc_exec_ctx* exec_ctx, grpc_server* server, grpc_call_element* elem,
    request_matcher* rm,
    grpc_server_register_method_payload_handling payload_handling) {
  call_data* calld = (call_data*)elem->call_data;

  if (gpr_atm_acq_load(&server->shutdown_flag)) {
    gpr_atm_no_barrier_store(&calld->state, ZOMBIED);
    GRPC_CLOSURE_INIT(&calld->kill_zombie_closure, kill_zombie, elem,
                      grpc_schedule_on_exec_ctx);
    GRPC_CLOSURE_SCHED(exec_ctx, &calld->kill_zombie_closure, GRPC_ERROR_NONE);
    return;
  }

  calld->matcher = rm;

  switch (payload_handling) {
    case GRPC_SRM_PAYLOAD_NONE: {
      publish_new_rpc(exec_ctx, elem, GRPC_ERROR_NONE);
      break;
    }
    case GRPC_SRM_PAYLOAD_READ_INITIAL_BYTE_BUFFER: {
      grpc_op op;
      memset(&op, 0, sizeof(op));
      op.op = GRPC_OP_RECV_MESSAGE;
      op.data.recv_message.recv_message = &calld->payload;
      GRPC_CLOSURE_INIT(&calld->publish, publish_new_rpc, elem,
                        grpc_schedule_on_exec_ctx);
      grpc_call_start_batch_and_execute(exec_ctx, calld->call, &op, 1,
                                        &calld->publish);
      break;
    }
  }
}

static void start_new_rpc(grpc_exec_ctx* exec_ctx, grpc_call_element* elem) {
  channel_data* chand = (channel_data*)elem->channel_data;
  call_data* calld = (call_data*)elem->call_data;
  grpc_server* server = chand->server;
  uint32_t i;
  uint32_t hash;
  channel_registered_method* rm;

  if (chand->registered_methods && calld->path_set && calld->host_set) {
    /* TODO(ctiller): unify these two searches */
    /* check for an exact match with host */
    hash = GRPC_MDSTR_KV_HASH(grpc_slice_hash(calld->host),
                              grpc_slice_hash(calld->path));
    for (i = 0; i <= chand->registered_method_max_probes; i++) {
      rm = &chand->registered_methods[(hash + i) %
                                      chand->registered_method_slots];
      if (!rm) break;
      if (!rm->has_host) continue;
      if (!grpc_slice_eq(rm->host, calld->host)) continue;
      if (!grpc_slice_eq(rm->method, calld->path)) continue;
      if ((rm->flags & GRPC_INITIAL_METADATA_IDEMPOTENT_REQUEST) &&
          0 == (calld->recv_initial_metadata_flags &
                GRPC_INITIAL_METADATA_IDEMPOTENT_REQUEST)) {
        continue;
      }
      finish_start_new_rpc(exec_ctx, server, elem,
                           &rm->server_registered_method->matcher,
                           rm->server_registered_method->payload_handling);
      return;
    }
    /* check for a wildcard method definition (no host set) */
    hash = GRPC_MDSTR_KV_HASH(0, grpc_slice_hash(calld->path));
    for (i = 0; i <= chand->registered_method_max_probes; i++) {
      rm = &chand->registered_methods[(hash + i) %
                                      chand->registered_method_slots];
      if (!rm) break;
      if (rm->has_host) continue;
      if (!grpc_slice_eq(rm->method, calld->path)) continue;
      if ((rm->flags & GRPC_INITIAL_METADATA_IDEMPOTENT_REQUEST) &&
          0 == (calld->recv_initial_metadata_flags &
                GRPC_INITIAL_METADATA_IDEMPOTENT_REQUEST)) {
        continue;
      }
      finish_start_new_rpc(exec_ctx, server, elem,
                           &rm->server_registered_method->matcher,
                           rm->server_registered_method->payload_handling);
      return;
    }
  }
  finish_start_new_rpc(exec_ctx, server, elem,
                       &server->unregistered_request_matcher,
                       GRPC_SRM_PAYLOAD_NONE);
}

static int num_listeners(grpc_server* server) {
  listener* l;
  int n = 0;
  for (l = server->listeners; l; l = l->next) {
    n++;
  }
  return n;
}

static void done_shutdown_event(grpc_exec_ctx* exec_ctx, void* server,
                                grpc_cq_completion* completion) {
  server_unref(exec_ctx, (grpc_server*)server);
}

static int num_channels(grpc_server* server) {
  channel_data* chand;
  int n = 0;
  for (chand = server->root_channel_data.next;
       chand != &server->root_channel_data; chand = chand->next) {
    n++;
  }
  return n;
}

static void kill_pending_work_locked(grpc_exec_ctx* exec_ctx,
                                     grpc_server* server, grpc_error* error) {
  if (server->started) {
    request_matcher_kill_requests(exec_ctx, server,
                                  &server->unregistered_request_matcher,
                                  GRPC_ERROR_REF(error));
    request_matcher_zombify_all_pending_calls(
        exec_ctx, &server->unregistered_request_matcher);
    for (registered_method* rm = server->registered_methods; rm;
         rm = rm->next) {
      request_matcher_kill_requests(exec_ctx, server, &rm->matcher,
                                    GRPC_ERROR_REF(error));
      request_matcher_zombify_all_pending_calls(exec_ctx, &rm->matcher);
    }
  }
  GRPC_ERROR_UNREF(error);
}

static void maybe_finish_shutdown(grpc_exec_ctx* exec_ctx,
                                  grpc_server* server) {
  size_t i;
  if (!gpr_atm_acq_load(&server->shutdown_flag) || server->shutdown_published) {
    return;
  }

  kill_pending_work_locked(
      exec_ctx, server,
      GRPC_ERROR_CREATE_FROM_STATIC_STRING("Server Shutdown"));

  if (server->root_channel_data.next != &server->root_channel_data ||
      server->listeners_destroyed < num_listeners(server)) {
    if (gpr_time_cmp(gpr_time_sub(gpr_now(GPR_CLOCK_REALTIME),
                                  server->last_shutdown_message_time),
                     gpr_time_from_seconds(1, GPR_TIMESPAN)) >= 0) {
      server->last_shutdown_message_time = gpr_now(GPR_CLOCK_REALTIME);
      gpr_log(GPR_DEBUG,
              "Waiting for %d channels and %d/%d listeners to be destroyed"
              " before shutting down server",
              num_channels(server),
              num_listeners(server) - server->listeners_destroyed,
              num_listeners(server));
    }
    return;
  }
  server->shutdown_published = 1;
  for (i = 0; i < server->num_shutdown_tags; i++) {
    server_ref(server);
    grpc_cq_end_op(exec_ctx, server->shutdown_tags[i].cq,
                   server->shutdown_tags[i].tag, GRPC_ERROR_NONE,
                   done_shutdown_event, server,
                   &server->shutdown_tags[i].completion);
  }
}

static void server_on_recv_initial_metadata(grpc_exec_ctx* exec_ctx, void* ptr,
                                            grpc_error* error) {
  grpc_call_element* elem = (grpc_call_element*)ptr;
  call_data* calld = (call_data*)elem->call_data;
  grpc_millis op_deadline;

  if (error == GRPC_ERROR_NONE) {
    GPR_ASSERT(calld->recv_initial_metadata->idx.named.path != nullptr);
    GPR_ASSERT(calld->recv_initial_metadata->idx.named.authority != nullptr);
    calld->path = grpc_slice_ref_internal(
        GRPC_MDVALUE(calld->recv_initial_metadata->idx.named.path->md));
    calld->host = grpc_slice_ref_internal(
        GRPC_MDVALUE(calld->recv_initial_metadata->idx.named.authority->md));
    calld->path_set = true;
    calld->host_set = true;
    grpc_metadata_batch_remove(exec_ctx, calld->recv_initial_metadata,
                               calld->recv_initial_metadata->idx.named.path);
    grpc_metadata_batch_remove(
        exec_ctx, calld->recv_initial_metadata,
        calld->recv_initial_metadata->idx.named.authority);
  } else {
    GRPC_ERROR_REF(error);
  }
  op_deadline = calld->recv_initial_metadata->deadline;
  if (op_deadline != GRPC_MILLIS_INF_FUTURE) {
    calld->deadline = op_deadline;
  }
  if (calld->host_set && calld->path_set) {
    /* do nothing */
  } else {
    grpc_error* src_error = error;
    error = GRPC_ERROR_CREATE_REFERENCING_FROM_STATIC_STRING(
        "Missing :authority or :path", &error, 1);
    GRPC_ERROR_UNREF(src_error);
  }

  GRPC_CLOSURE_RUN(exec_ctx, calld->on_done_recv_initial_metadata, error);
}

static void server_mutate_op(grpc_call_element* elem,
                             grpc_transport_stream_op_batch* op) {
  call_data* calld = (call_data*)elem->call_data;

  if (op->recv_initial_metadata) {
    GPR_ASSERT(op->payload->recv_initial_metadata.recv_flags == nullptr);
    calld->recv_initial_metadata =
        op->payload->recv_initial_metadata.recv_initial_metadata;
    calld->on_done_recv_initial_metadata =
        op->payload->recv_initial_metadata.recv_initial_metadata_ready;
    op->payload->recv_initial_metadata.recv_initial_metadata_ready =
        &calld->server_on_recv_initial_metadata;
    op->payload->recv_initial_metadata.recv_flags =
        &calld->recv_initial_metadata_flags;
  }
}

static void server_start_transport_stream_op_batch(
    grpc_exec_ctx* exec_ctx, grpc_call_element* elem,
    grpc_transport_stream_op_batch* op) {
  server_mutate_op(elem, op);
  grpc_call_next_op(exec_ctx, elem, op);
}

static void got_initial_metadata(grpc_exec_ctx* exec_ctx, void* ptr,
                                 grpc_error* error) {
  grpc_call_element* elem = (grpc_call_element*)ptr;
  call_data* calld = (call_data*)elem->call_data;
  if (error == GRPC_ERROR_NONE) {
    start_new_rpc(exec_ctx, elem);
  } else {
    if (gpr_atm_full_cas(&calld->state, NOT_STARTED, ZOMBIED)) {
      GRPC_CLOSURE_INIT(&calld->kill_zombie_closure, kill_zombie, elem,
                        grpc_schedule_on_exec_ctx);
      GRPC_CLOSURE_SCHED(exec_ctx, &calld->kill_zombie_closure,
                         GRPC_ERROR_NONE);
    } else if (gpr_atm_full_cas(&calld->state, PENDING, ZOMBIED)) {
      /* zombied call will be destroyed when it's removed from the pending
         queue... later */
    }
  }
}

static void accept_stream(grpc_exec_ctx* exec_ctx, void* cd,
                          grpc_transport* transport,
                          const void* transport_server_data) {
  channel_data* chand = (channel_data*)cd;
  /* create a call */
  grpc_call_create_args args;
  memset(&args, 0, sizeof(args));
  args.channel = chand->channel;
  args.server_transport_data = transport_server_data;
  args.send_deadline = GRPC_MILLIS_INF_FUTURE;
  grpc_call* call;
  grpc_error* error = grpc_call_create(exec_ctx, &args, &call);
  grpc_call_element* elem =
      grpc_call_stack_element(grpc_call_get_call_stack(call), 0);
  if (error != GRPC_ERROR_NONE) {
    got_initial_metadata(exec_ctx, elem, error);
    GRPC_ERROR_UNREF(error);
    return;
  }
  call_data* calld = (call_data*)elem->call_data;
  grpc_op op;
  memset(&op, 0, sizeof(op));
  op.op = GRPC_OP_RECV_INITIAL_METADATA;
  op.data.recv_initial_metadata.recv_initial_metadata =
      &calld->initial_metadata;
  GRPC_CLOSURE_INIT(&calld->got_initial_metadata, got_initial_metadata, elem,
                    grpc_schedule_on_exec_ctx);
  grpc_call_start_batch_and_execute(exec_ctx, call, &op, 1,
                                    &calld->got_initial_metadata);
}

static void channel_connectivity_changed(grpc_exec_ctx* exec_ctx, void* cd,
                                         grpc_error* error) {
  channel_data* chand = (channel_data*)cd;
  grpc_server* server = chand->server;
  if (chand->connectivity_state != GRPC_CHANNEL_SHUTDOWN) {
    grpc_transport_op* op = grpc_make_transport_op(nullptr);
    op->on_connectivity_state_change = &chand->channel_connectivity_changed;
    op->connectivity_state = &chand->connectivity_state;
    grpc_channel_next_op(exec_ctx,
                         grpc_channel_stack_element(
                             grpc_channel_get_channel_stack(chand->channel), 0),
                         op);
  } else {
    gpr_mu_lock(&server->mu_global);
    destroy_channel(exec_ctx, chand, GRPC_ERROR_REF(error));
    gpr_mu_unlock(&server->mu_global);
    GRPC_CHANNEL_INTERNAL_UNREF(exec_ctx, chand->channel, "connectivity");
  }
}

static grpc_error* init_call_elem(grpc_exec_ctx* exec_ctx,
                                  grpc_call_element* elem,
                                  const grpc_call_element_args* args) {
  call_data* calld = (call_data*)elem->call_data;
  channel_data* chand = (channel_data*)elem->channel_data;
  memset(calld, 0, sizeof(call_data));
  calld->deadline = GRPC_MILLIS_INF_FUTURE;
  calld->call = grpc_call_from_top_element(elem);

  GRPC_CLOSURE_INIT(&calld->server_on_recv_initial_metadata,
                    server_on_recv_initial_metadata, elem,
                    grpc_schedule_on_exec_ctx);

  server_ref(chand->server);
  return GRPC_ERROR_NONE;
}

static void destroy_call_elem(grpc_exec_ctx* exec_ctx, grpc_call_element* elem,
                              const grpc_call_final_info* final_info,
                              grpc_closure* ignored) {
  channel_data* chand = (channel_data*)elem->channel_data;
  call_data* calld = (call_data*)elem->call_data;

  GPR_ASSERT(calld->state != PENDING);

  if (calld->host_set) {
    grpc_slice_unref_internal(exec_ctx, calld->host);
  }
  if (calld->path_set) {
    grpc_slice_unref_internal(exec_ctx, calld->path);
  }
  grpc_metadata_array_destroy(&calld->initial_metadata);
  grpc_byte_buffer_destroy(calld->payload);

  server_unref(exec_ctx, chand->server);
}

static grpc_error* init_channel_elem(grpc_exec_ctx* exec_ctx,
                                     grpc_channel_element* elem,
                                     grpc_channel_element_args* args) {
  channel_data* chand = (channel_data*)elem->channel_data;
  GPR_ASSERT(args->is_first);
  GPR_ASSERT(!args->is_last);
  chand->server = nullptr;
  chand->channel = nullptr;
  chand->next = chand->prev = chand;
  chand->registered_methods = nullptr;
  chand->connectivity_state = GRPC_CHANNEL_IDLE;
  GRPC_CLOSURE_INIT(&chand->channel_connectivity_changed,
                    channel_connectivity_changed, chand,
                    grpc_schedule_on_exec_ctx);
  return GRPC_ERROR_NONE;
}

static void destroy_channel_elem(grpc_exec_ctx* exec_ctx,
                                 grpc_channel_element* elem) {
  size_t i;
  channel_data* chand = (channel_data*)elem->channel_data;
  if (chand->registered_methods) {
    for (i = 0; i < chand->registered_method_slots; i++) {
      grpc_slice_unref_internal(exec_ctx, chand->registered_methods[i].method);
      if (chand->registered_methods[i].has_host) {
        grpc_slice_unref_internal(exec_ctx, chand->registered_methods[i].host);
      }
    }
    gpr_free(chand->registered_methods);
  }
  if (chand->server) {
    gpr_mu_lock(&chand->server->mu_global);
    chand->next->prev = chand->prev;
    chand->prev->next = chand->next;
    chand->next = chand->prev = chand;
    maybe_finish_shutdown(exec_ctx, chand->server);
    gpr_mu_unlock(&chand->server->mu_global);
    server_unref(exec_ctx, chand->server);
  }
}

const grpc_channel_filter grpc_server_top_filter = {
    server_start_transport_stream_op_batch,
    grpc_channel_next_op,
    sizeof(call_data),
    init_call_elem,
    grpc_call_stack_ignore_set_pollset_or_pollset_set,
    destroy_call_elem,
    sizeof(channel_data),
    init_channel_elem,
    destroy_channel_elem,
    grpc_channel_next_get_info,
    "server",
};

static void register_completion_queue(grpc_server* server,
                                      grpc_completion_queue* cq,
                                      void* reserved) {
  size_t i, n;
  GPR_ASSERT(!reserved);
  for (i = 0; i < server->cq_count; i++) {
    if (server->cqs[i] == cq) return;
  }

  GRPC_CQ_INTERNAL_REF(cq, "server");
  n = server->cq_count++;
  server->cqs = (grpc_completion_queue**)gpr_realloc(
      server->cqs, server->cq_count * sizeof(grpc_completion_queue*));
  server->cqs[n] = cq;
}

void grpc_server_register_completion_queue(grpc_server* server,
                                           grpc_completion_queue* cq,
                                           void* reserved) {
  GRPC_API_TRACE(
      "grpc_server_register_completion_queue(server=%p, cq=%p, reserved=%p)", 3,
      (server, cq, reserved));

  if (grpc_get_cq_completion_type(cq) != GRPC_CQ_NEXT) {
    gpr_log(GPR_INFO,
            "Completion queue which is not of type GRPC_CQ_NEXT is being "
            "registered as a server-completion-queue");
    /* Ideally we should log an error and abort but ruby-wrapped-language API
       calls grpc_completion_queue_pluck() on server completion queues */
  }

  register_completion_queue(server, cq, reserved);
}

grpc_server* grpc_server_create(const grpc_channel_args* args, void* reserved) {
  GRPC_API_TRACE("grpc_server_create(%p, %p)", 2, (args, reserved));

  grpc_server* server = (grpc_server*)gpr_zalloc(sizeof(grpc_server));

  gpr_mu_init(&server->mu_global);
  gpr_mu_init(&server->mu_call);
  gpr_cv_init(&server->starting_cv);

  /* decremented by grpc_server_destroy */
  gpr_ref_init(&server->internal_refcount, 1);
  server->root_channel_data.next = server->root_channel_data.prev =
      &server->root_channel_data;

  server->channel_args = grpc_channel_args_copy(args);

  return server;
}

static int streq(const char* a, const char* b) {
  if (a == nullptr && b == nullptr) return 1;
  if (a == nullptr) return 0;
  if (b == nullptr) return 0;
  return 0 == strcmp(a, b);
}

void* grpc_server_register_method(
    grpc_server* server, const char* method, const char* host,
    grpc_server_register_method_payload_handling payload_handling,
    uint32_t flags) {
  registered_method* m;
  GRPC_API_TRACE(
      "grpc_server_register_method(server=%p, method=%s, host=%s, "
      "flags=0x%08x)",
      4, (server, method, host, flags));
  if (!method) {
    gpr_log(GPR_ERROR,
            "grpc_server_register_method method string cannot be NULL");
    return nullptr;
  }
  for (m = server->registered_methods; m; m = m->next) {
    if (streq(m->method, method) && streq(m->host, host)) {
      gpr_log(GPR_ERROR, "duplicate registration for %s@%s", method,
              host ? host : "*");
      return nullptr;
    }
  }
  if ((flags & ~GRPC_INITIAL_METADATA_USED_MASK) != 0) {
    gpr_log(GPR_ERROR, "grpc_server_register_method invalid flags 0x%08x",
            flags);
    return nullptr;
  }
  m = (registered_method*)gpr_zalloc(sizeof(registered_method));
  m->method = gpr_strdup(method);
  m->host = gpr_strdup(host);
  m->next = server->registered_methods;
  m->payload_handling = payload_handling;
  m->flags = flags;
  server->registered_methods = m;
  return m;
}

static void start_listeners(grpc_exec_ctx* exec_ctx, void* s,
                            grpc_error* error) {
  grpc_server* server = (grpc_server*)s;
  for (listener* l = server->listeners; l; l = l->next) {
    l->start(l->on_read, exec_ctx, server, l->arg, server->pollsets, server->pollset_count);
  }

  gpr_mu_lock(&server->mu_global);
  server->starting = false;
  gpr_cv_signal(&server->starting_cv);
  gpr_mu_unlock(&server->mu_global);

  server_unref(exec_ctx, server);
}

void grpc_server_start(grpc_server* server) {
  size_t i;
  grpc_exec_ctx exec_ctx = GRPC_EXEC_CTX_INIT;

  GRPC_API_TRACE("grpc_server_start(server=%p)", 1, (server));

  server->started = true;
  server->pollset_count = 0;
  server->pollsets =
      (grpc_pollset**)gpr_malloc(sizeof(grpc_pollset*) * server->cq_count);
  for (i = 0; i < server->cq_count; i++) {
    if (grpc_cq_can_listen(server->cqs[i])) {
      server->pollsets[server->pollset_count++] =
          grpc_cq_pollset(server->cqs[i]);
    }
  }
  request_matcher_init(&server->unregistered_request_matcher, server);
  for (registered_method* rm = server->registered_methods; rm; rm = rm->next) {
    request_matcher_init(&rm->matcher, server);
  }

  server_ref(server);
  server->starting = true;
  GRPC_CLOSURE_SCHED(
      &exec_ctx,
      GRPC_CLOSURE_CREATE(start_listeners, server,
                          grpc_executor_scheduler(GRPC_EXECUTOR_SHORT)),
      GRPC_ERROR_NONE);

  grpc_exec_ctx_finish(&exec_ctx);
}

void grpc_server_get_pollsets(grpc_server* server, grpc_pollset*** pollsets,
                              size_t* pollset_count) {
  *pollset_count = server->pollset_count;
  *pollsets = server->pollsets;
}

void grpc_server_setup_transport(grpc_exec_ctx* exec_ctx, grpc_server* s,
                                 grpc_transport* transport,
                                 grpc_pollset* accepting_pollset,
                                 const grpc_channel_args* args) {
  size_t num_registered_methods;
  size_t alloc;
  registered_method* rm;
  channel_registered_method* crm;
  grpc_channel* channel;
  channel_data* chand;
  uint32_t hash;
  size_t slots;
  uint32_t probes;
  uint32_t max_probes = 0;
  grpc_transport_op* op = nullptr;

  channel = grpc_channel_create(exec_ctx, nullptr, args, GRPC_SERVER_CHANNEL,
                                transport);
  chand = (channel_data*)grpc_channel_stack_element(
              grpc_channel_get_channel_stack(channel), 0)
              ->channel_data;
  chand->server = s;
  server_ref(s);
  chand->channel = channel;

  size_t cq_idx;
  for (cq_idx = 0; cq_idx < s->cq_count; cq_idx++) {
    if (grpc_cq_pollset(s->cqs[cq_idx]) == accepting_pollset) break;
  }
  if (cq_idx == s->cq_count) {
    /* completion queue not found: pick a random one to publish new calls to */
    cq_idx = (size_t)rand() % s->cq_count;
  }
  chand->cq_idx = cq_idx;

  num_registered_methods = 0;
  for (rm = s->registered_methods; rm; rm = rm->next) {
    num_registered_methods++;
  }
  /* build a lookup table phrased in terms of mdstr's in this channels context
     to quickly find registered methods */
  if (num_registered_methods > 0) {
    slots = 2 * num_registered_methods;
    alloc = sizeof(channel_registered_method) * slots;
    chand->registered_methods = (channel_registered_method*)gpr_zalloc(alloc);
    for (rm = s->registered_methods; rm; rm = rm->next) {
      grpc_slice host;
      bool has_host;
      grpc_slice method;
      if (rm->host != nullptr) {
        host = grpc_slice_intern(grpc_slice_from_static_string(rm->host));
        has_host = true;
      } else {
        has_host = false;
      }
      method = grpc_slice_intern(grpc_slice_from_static_string(rm->method));
      hash = GRPC_MDSTR_KV_HASH(has_host ? grpc_slice_hash(host) : 0,
                                grpc_slice_hash(method));
      for (probes = 0; chand->registered_methods[(hash + probes) % slots]
                           .server_registered_method != nullptr;
           probes++)
        ;
      if (probes > max_probes) max_probes = probes;
      crm = &chand->registered_methods[(hash + probes) % slots];
      crm->server_registered_method = rm;
      crm->flags = rm->flags;
      crm->has_host = has_host;
      if (has_host) {
        crm->host = host;
      }
      crm->method = method;
    }
    GPR_ASSERT(slots <= UINT32_MAX);
    chand->registered_method_slots = (uint32_t)slots;
    chand->registered_method_max_probes = max_probes;
  }

  gpr_mu_lock(&s->mu_global);
  chand->next = &s->root_channel_data;
  chand->prev = chand->next->prev;
  chand->next->prev = chand->prev->next = chand;
  gpr_mu_unlock(&s->mu_global);

  GRPC_CHANNEL_INTERNAL_REF(channel, "connectivity");
  op = grpc_make_transport_op(nullptr);
  op->set_accept_stream = true;
  op->set_accept_stream_fn = accept_stream;
  op->set_accept_stream_user_data = chand;
  op->on_connectivity_state_change = &chand->channel_connectivity_changed;
  op->connectivity_state = &chand->connectivity_state;
  if (gpr_atm_acq_load(&s->shutdown_flag) != 0) {
    op->disconnect_with_error =
        GRPC_ERROR_CREATE_FROM_STATIC_STRING("Server shutdown");
  }
  grpc_transport_perform_op(exec_ctx, transport, op);
}

void done_published_shutdown(grpc_exec_ctx* exec_ctx, void* done_arg,
                             grpc_cq_completion* storage) {
  (void)done_arg;
  gpr_free(storage);
}

static void listener_destroy_done(grpc_exec_ctx* exec_ctx, void* s,
                                  grpc_error* error) {
  grpc_server* server = (grpc_server*)s;
  gpr_mu_lock(&server->mu_global);
  server->listeners_destroyed++;
  maybe_finish_shutdown(exec_ctx, server);
  gpr_mu_unlock(&server->mu_global);
}

void grpc_server_shutdown_and_notify(grpc_server* server,
                                     grpc_completion_queue* cq, void* tag) {
  listener* l;
  shutdown_tag* sdt;
  channel_broadcaster broadcaster;
  grpc_exec_ctx exec_ctx = GRPC_EXEC_CTX_INIT;

  GRPC_API_TRACE("grpc_server_shutdown_and_notify(server=%p, cq=%p, tag=%p)", 3,
                 (server, cq, tag));

  /* wait for startup to be finished: locks mu_global */
  gpr_mu_lock(&server->mu_global);
  while (server->starting) {
    gpr_cv_wait(&server->starting_cv, &server->mu_global,
                gpr_inf_future(GPR_CLOCK_REALTIME));
  }

  /* stay locked, and gather up some stuff to do */
  GPR_ASSERT(grpc_cq_begin_op(cq, tag));
  if (server->shutdown_published) {
    grpc_cq_end_op(&exec_ctx, cq, tag, GRPC_ERROR_NONE, done_published_shutdown,
                   nullptr,
                   (grpc_cq_completion*)gpr_malloc(sizeof(grpc_cq_completion)));
    gpr_mu_unlock(&server->mu_global);
    goto done;
  }
  server->shutdown_tags = (shutdown_tag*)gpr_realloc(
      server->shutdown_tags,
      sizeof(shutdown_tag) * (server->num_shutdown_tags + 1));
  sdt = &server->shutdown_tags[server->num_shutdown_tags++];
  sdt->tag = tag;
  sdt->cq = cq;
  if (gpr_atm_acq_load(&server->shutdown_flag)) {
    gpr_mu_unlock(&server->mu_global);
    goto done;
  }

  server->last_shutdown_message_time = gpr_now(GPR_CLOCK_REALTIME);

  channel_broadcaster_init(server, &broadcaster);

  gpr_atm_rel_store(&server->shutdown_flag, 1);

  /* collect all unregistered then registered calls */
  gpr_mu_lock(&server->mu_call);
  kill_pending_work_locked(
      &exec_ctx, server,
      GRPC_ERROR_CREATE_FROM_STATIC_STRING("Server Shutdown"));
  gpr_mu_unlock(&server->mu_call);

  maybe_finish_shutdown(&exec_ctx, server);
  gpr_mu_unlock(&server->mu_global);

  /* Shutdown listeners */
  for (l = server->listeners; l; l = l->next) {
    GRPC_CLOSURE_INIT(&l->destroy_done, listener_destroy_done, server,
                      grpc_schedule_on_exec_ctx);
    l->destroy(&exec_ctx, server, l->arg, &l->destroy_done);
  }

  channel_broadcaster_shutdown(&exec_ctx, &broadcaster, true /* send_goaway */,
                               GRPC_ERROR_NONE);

done:
  grpc_exec_ctx_finish(&exec_ctx);
}

void grpc_server_cancel_all_calls(grpc_server* server) {
  channel_broadcaster broadcaster;
  grpc_exec_ctx exec_ctx = GRPC_EXEC_CTX_INIT;

  GRPC_API_TRACE("grpc_server_cancel_all_calls(server=%p)", 1, (server));

  gpr_mu_lock(&server->mu_global);
  channel_broadcaster_init(server, &broadcaster);
  gpr_mu_unlock(&server->mu_global);

  channel_broadcaster_shutdown(
      &exec_ctx, &broadcaster, false /* send_goaway */,
      GRPC_ERROR_CREATE_FROM_STATIC_STRING("Cancelling all calls"));
  grpc_exec_ctx_finish(&exec_ctx);
}

void grpc_server_destroy(grpc_server* server) {
  listener* l;
  grpc_exec_ctx exec_ctx = GRPC_EXEC_CTX_INIT;

  GRPC_API_TRACE("grpc_server_destroy(server=%p)", 1, (server));

  gpr_mu_lock(&server->mu_global);
  GPR_ASSERT(gpr_atm_acq_load(&server->shutdown_flag) || !server->listeners);
  GPR_ASSERT(server->listeners_destroyed == num_listeners(server));

  while (server->listeners) {
    l = server->listeners;
    server->listeners = l->next;
    gpr_free(l);
  }

  gpr_mu_unlock(&server->mu_global);

  server_unref(&exec_ctx, server);
  grpc_exec_ctx_finish(&exec_ctx);
}

void grpc_server_add_listener(
    grpc_exec_ctx* exec_ctx, grpc_server* server, void* arg,
    void (*read_cb)(grpc_exec_ctx*, void*, grpc_error*),
    void (*start)(void (*)(grpc_exec_ctx*, void*, grpc_error*),
                  grpc_exec_ctx* exec_ctx, grpc_server* server, void* arg,
                  grpc_pollset** pollsets, size_t npollsets),
    void(*destroy)(grpc_exec_ctx* exec_ctx, grpc_server* server, void* arg,
                   grpc_closure* on_done)) {

  listener* l = (listener*)gpr_malloc(sizeof(listener));
  l->arg = arg;
  l->start = start;
  l->destroy = destroy;
  l->on_read = read_cb;
  l->next = server->listeners;
  server->listeners = l;
}

static grpc_call_error queue_call_request(grpc_exec_ctx* exec_ctx,
                                          grpc_server* server, size_t cq_idx,
                                          requested_call* rc) {
  call_data* calld = nullptr;
  request_matcher* rm = nullptr;
  if (gpr_atm_acq_load(&server->shutdown_flag)) {
    fail_call(exec_ctx, server, cq_idx, rc,
              GRPC_ERROR_CREATE_FROM_STATIC_STRING("Server Shutdown"));
    return GRPC_CALL_OK;
  }
  switch (rc->type) {
    case BATCH_CALL:
      rm = &server->unregistered_request_matcher;
      break;
    case REGISTERED_CALL:
      rm = &rc->data.registered.method->matcher;
      break;
  }
  if (gpr_locked_mpscq_push(&rm->requests_per_cq[cq_idx], &rc->request_link)) {
    /* this was the first queued request: we need to lock and start
       matching calls */
    gpr_mu_lock(&server->mu_call);
    while ((calld = rm->pending_head) != nullptr) {
      rc = (requested_call*)gpr_locked_mpscq_pop(&rm->requests_per_cq[cq_idx]);
      if (rc == nullptr) break;
      rm->pending_head = calld->pending_next;
      gpr_mu_unlock(&server->mu_call);
      if (!gpr_atm_full_cas(&calld->state, PENDING, ACTIVATED)) {
        // Zombied Call
        GRPC_CLOSURE_INIT(
            &calld->kill_zombie_closure, kill_zombie,
            grpc_call_stack_element(grpc_call_get_call_stack(calld->call), 0),
            grpc_schedule_on_exec_ctx);
        GRPC_CLOSURE_SCHED(exec_ctx, &calld->kill_zombie_closure,
                           GRPC_ERROR_NONE);
      } else {
        publish_call(exec_ctx, server, calld, cq_idx, rc);
      }
      gpr_mu_lock(&server->mu_call);
    }
    gpr_mu_unlock(&server->mu_call);
  }
  return GRPC_CALL_OK;
}

grpc_call_error grpc_server_request_call(
    grpc_server* server, grpc_call** call, grpc_call_details* details,
    grpc_metadata_array* initial_metadata,
    grpc_completion_queue* cq_bound_to_call,
    grpc_completion_queue* cq_for_notification, void* tag) {
  grpc_call_error error;
  grpc_exec_ctx exec_ctx = GRPC_EXEC_CTX_INIT;
  requested_call* rc = (requested_call*)gpr_malloc(sizeof(*rc));
  GRPC_STATS_INC_SERVER_REQUESTED_CALLS(&exec_ctx);
  GRPC_API_TRACE(
      "grpc_server_request_call("
      "server=%p, call=%p, details=%p, initial_metadata=%p, "
      "cq_bound_to_call=%p, cq_for_notification=%p, tag=%p)",
      7,
      (server, call, details, initial_metadata, cq_bound_to_call,
       cq_for_notification, tag));
  size_t cq_idx;
  for (cq_idx = 0; cq_idx < server->cq_count; cq_idx++) {
    if (server->cqs[cq_idx] == cq_for_notification) {
      break;
    }
  }
  if (cq_idx == server->cq_count) {
    gpr_free(rc);
    error = GRPC_CALL_ERROR_NOT_SERVER_COMPLETION_QUEUE;
    goto done;
  }
  if (grpc_cq_begin_op(cq_for_notification, tag) == false) {
    gpr_free(rc);
    error = GRPC_CALL_ERROR_COMPLETION_QUEUE_SHUTDOWN;
    goto done;
  }
  details->reserved = nullptr;
  rc->cq_idx = cq_idx;
  rc->type = BATCH_CALL;
  rc->server = server;
  rc->tag = tag;
  rc->cq_bound_to_call = cq_bound_to_call;
  rc->call = call;
  rc->data.batch.details = details;
  rc->initial_metadata = initial_metadata;
  error = queue_call_request(&exec_ctx, server, cq_idx, rc);
done:
  grpc_exec_ctx_finish(&exec_ctx);
  return error;
}

grpc_call_error grpc_server_request_registered_call(
    grpc_server* server, void* rmp, grpc_call** call, gpr_timespec* deadline,
    grpc_metadata_array* initial_metadata, grpc_byte_buffer** optional_payload,
    grpc_completion_queue* cq_bound_to_call,
    grpc_completion_queue* cq_for_notification, void* tag) {
  grpc_call_error error;
  grpc_exec_ctx exec_ctx = GRPC_EXEC_CTX_INIT;
  requested_call* rc = (requested_call*)gpr_malloc(sizeof(*rc));
  registered_method* rm = (registered_method*)rmp;
  GRPC_STATS_INC_SERVER_REQUESTED_CALLS(&exec_ctx);
  GRPC_API_TRACE(
      "grpc_server_request_registered_call("
      "server=%p, rmp=%p, call=%p, deadline=%p, initial_metadata=%p, "
      "optional_payload=%p, cq_bound_to_call=%p, cq_for_notification=%p, "
      "tag=%p)",
      9,
      (server, rmp, call, deadline, initial_metadata, optional_payload,
       cq_bound_to_call, cq_for_notification, tag));

  size_t cq_idx;
  for (cq_idx = 0; cq_idx < server->cq_count; cq_idx++) {
    if (server->cqs[cq_idx] == cq_for_notification) {
      break;
    }
  }
  if (cq_idx == server->cq_count) {
    gpr_free(rc);
    error = GRPC_CALL_ERROR_NOT_SERVER_COMPLETION_QUEUE;
    goto done;
  }
  if ((optional_payload == nullptr) !=
      (rm->payload_handling == GRPC_SRM_PAYLOAD_NONE)) {
    gpr_free(rc);
    error = GRPC_CALL_ERROR_PAYLOAD_TYPE_MISMATCH;
    goto done;
  }
  if (grpc_cq_begin_op(cq_for_notification, tag) == false) {
    gpr_free(rc);
    error = GRPC_CALL_ERROR_COMPLETION_QUEUE_SHUTDOWN;
    goto done;
  }
  rc->cq_idx = cq_idx;
  rc->type = REGISTERED_CALL;
  rc->server = server;
  rc->tag = tag;
  rc->cq_bound_to_call = cq_bound_to_call;
  rc->call = call;
  rc->data.registered.method = rm;
  rc->data.registered.deadline = deadline;
  rc->initial_metadata = initial_metadata;
  rc->data.registered.optional_payload = optional_payload;
  error = queue_call_request(&exec_ctx, server, cq_idx, rc);
done:
  grpc_exec_ctx_finish(&exec_ctx);
  return error;
}

static void fail_call(grpc_exec_ctx* exec_ctx, grpc_server* server,
                      size_t cq_idx, requested_call* rc, grpc_error* error) {
  *rc->call = nullptr;
  rc->initial_metadata->count = 0;
  GPR_ASSERT(error != GRPC_ERROR_NONE);

  grpc_cq_end_op(exec_ctx, server->cqs[cq_idx], rc->tag, error,
                 done_request_event, rc, &rc->completion);
}

const grpc_channel_args* grpc_server_get_channel_args(grpc_server* server) {
  return server->channel_args;
}

int grpc_server_has_open_connections(grpc_server* server) {
  int r;
  gpr_mu_lock(&server->mu_global);
  r = server->root_channel_data.next != &server->root_channel_data;
  gpr_mu_unlock(&server->mu_global);
  return r;
}
