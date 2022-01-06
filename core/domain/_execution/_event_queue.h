// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_EXECUTION_EVENT_LOOP_H_
#define MUMBA_DOMAIN_EXECUTION_EVENT_LOOP_H_

#include "base/macros.h"
#include "base/containers/circular_deque.h"
#include "base/single_thread_task_runner.h"
#include "base/synchronization/waitable_event.h"
//#include "rpc/surface/completion_queue.h"

namespace domain {

enum class OperationType {
  /** Send initial metadata: one and only one instance MUST be sent for each
      call, unless the call was cancelled - in which case this can be skipped.
      This op completes after all bytes of metadata have been accepted by
      outgoing flow control. */
  kSEND_INITIAL_METADATA = 0,
  /** Send a message: 0 or more of these operations can occur for each call.
      This op completes after all bytes for the message have been accepted by
      outgoing flow control. */
  kSEND_MESSAGE,
  /** Send a close from the client: one and only one instance MUST be sent from
      the client, unless the call was cancelled - in which case this can be
      skipped. This op completes after all bytes for the call
      (including the close) have passed outgoing flow control. */
  kSEND_CLOSE_FROM_CLIENT,
  /** Send status from the server: one and only one instance MUST be sent from
      the server unless the call was cancelled - in which case this can be
      skipped. This op completes after all bytes for the call
      (including the status) have passed outgoing flow control. */
  kSEND_STATUS_FROM_SERVER,
  /** Receive initial metadata: one and only one MUST be made on the client,
      must not be made on the server.
      This op completes after all initial metadata has been read from the
      peer. */
  kRECV_INITIAL_METADATA,
  /** Receive a message: 0 or more of these operations can occur for each call.
      This op completes after all bytes of the received message have been
      read, or after a half-close has been received on this call. */
  kRECV_MESSAGE,
  /** Receive status on the client: one and only one must be made on the client.
      This operation always succeeds, meaning ops paired with this operation
      will also appear to succeed, even though they may not have. In that case
      the status will indicate some failure.
      This op completes after all activity on the call has completed. */
  kRECV_STATUS_ON_CLIENT,
  /** Receive close on the server: one and only one must be made on the
      server. This op completes after the close has been received by the
      server. This operation always succeeds, meaning ops paired with
      this operation will also appear to succeed, even though they may not
      have. */
  kRECV_CLOSE_ON_SERVER
};

/*
 * Operations are embbeded in Events
 */
class Operation {
public:
  Operation(OperationType type);
  ~Operation();

  OperationType type() const {
    return type_;
  }

private:

  OperationType type_;
};

enum class EventType : int {
// call messages 
  kCALL_BEGIN = 0,
  kCALL_UNARY_READ = 1,
  kCALL_STREAM_READ = 2,
  kCALL_STREAM_SEND_INIT_METADATA = 3,
  kCALL_STREAM_WRITE = 4,
  kCALL_END = 5,
  // Control messages
  kCONTROL_OP_COMPLETE = 20,
  kCONTROL_QUEUE_TIMEOUT = 21,
  kCONTROL_QUEUE_SHUTDOWN = 22,
};  

class Event {
public:
  Event(EventType type);
  ~Event();

  EventType type() const {
    return type_;
  }

  // when event_type == CONTROL_OP_COMPLETE
  Operation* operation() const {
    return operation_.get();
  }

  void set_operation(Operation* operation) {
    operation_.reset(operation);
  }
  
private:
  EventType type_;

  std::unique_ptr<Operation> operation_;

  DISALLOW_COPY_AND_ASSIGN(Event);
};

class EventQueue {
public:
  EventQueue(scoped_refptr<base::SingleThreadTaskRunner> task_runner);
  ~EventQueue();

  scoped_refptr<base::SingleThreadTaskRunner> task_runner() const {
    return task_runner_;
  }

  base::WaitableEvent* wait_event() {
    return &wait_event_;
  }

  // need to be scheduled on 'task_runner()'
  Event* Next();

  void Push(Event* event);

  void Shutdown();

private:

  scoped_refptr<base::SingleThreadTaskRunner> task_runner_;
  base::circular_deque<Event *> queue_;
  base::WaitableEvent wait_event_;
  mutable bool shutting_down_;
  base::Lock mutex_;
  base::Lock next_mutex_;

  DISALLOW_COPY_AND_ASSIGN(EventQueue);
};

}

#endif