// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/tracing/trace_message_filter.h"

#include "base/bind.h"
#include "base/bind_helpers.h"
#include "components/tracing/common/tracing_messages.h"
#include "core/host/tracing/background_tracing_manager_impl.h"
#include "core/shared/common/child_process_host_impl.h"
#include "core/host/host_thread.h"

namespace host {

TraceMessageFilter::TraceMessageFilter(int child_process_id)
    : HostMessageFilter(TracingMsgStart),
      has_child_(false),
      tracing_process_id_(
          common::ChildProcessHostImpl::ChildProcessUniqueIdToTracingProcessId(
              child_process_id)) {}

TraceMessageFilter::~TraceMessageFilter() {}

void TraceMessageFilter::OnChannelConnected(int32_t peer_pid) {
  Send(new TracingMsg_SetTracingProcessId(tracing_process_id_));
}

void TraceMessageFilter::OnChannelClosing() {
  if (has_child_) {
    HostThread::PostTask(HostThread::UI, FROM_HERE,
                            base::BindOnce(&TraceMessageFilter::Unregister,
                                           base::RetainedRef(this)));
  }
}

bool TraceMessageFilter::OnMessageReceived(const IPC::Message& message) {
  // Always on IO thread (HostMessageFilter guarantee).
  bool handled = true;
  IPC_BEGIN_MESSAGE_MAP(TraceMessageFilter, message)
    IPC_MESSAGE_HANDLER(TracingHostMsg_ChildSupportsTracing,
                        OnChildSupportsTracing)
    IPC_MESSAGE_HANDLER(TracingHostMsg_TriggerBackgroundTrace,
                        OnTriggerBackgroundTrace)
    IPC_MESSAGE_HANDLER(TracingHostMsg_AbortBackgroundTrace,
                        OnAbortBackgroundTrace)
    IPC_MESSAGE_UNHANDLED(handled = false)
  IPC_END_MESSAGE_MAP()
  return handled;
}

void TraceMessageFilter::OnChildSupportsTracing() {
  has_child_ = true;
  HostThread::PostTask(
      HostThread::UI, FROM_HERE,
      base::BindOnce(&TraceMessageFilter::Register, base::RetainedRef(this)));
}

void TraceMessageFilter::Register() {
  BackgroundTracingManagerImpl::GetInstance()->AddTraceMessageFilter(this);
}

void TraceMessageFilter::Unregister() {
  BackgroundTracingManagerImpl::GetInstance()->RemoveTraceMessageFilter(this);
}

void TraceMessageFilter::OnTriggerBackgroundTrace(const std::string& name) {
  BackgroundTracingManagerImpl::GetInstance()->OnHistogramTrigger(name);
}

void TraceMessageFilter::OnAbortBackgroundTrace() {
  BackgroundTracingManagerImpl::GetInstance()->AbortScenario();
}

}  // namespace host
