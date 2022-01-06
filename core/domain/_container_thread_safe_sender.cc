// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/domain/domain_thread_safe_sender.h"

#include "base/threading/thread_task_runner_handle.h"
#include "core/domain/domain_main_thread.h"
#include "ipc/ipc_sync_message_filter.h"

namespace domain {

DomainThreadSafeSender::DomainThreadSafeSender(
    const scoped_refptr<base::SingleThreadTaskRunner>& main_task_runner,
    const scoped_refptr<IPC::SyncMessageFilter>& sync_filter)
    : main_task_runner_(main_task_runner), sync_filter_(sync_filter) {
}

DomainThreadSafeSender::~DomainThreadSafeSender() {
 
}

bool DomainThreadSafeSender::Send(IPC::Message* msg) {
  if (main_task_runner_->BelongsToCurrentThread())
    return DomainMainThread::current()->Send(msg);
  return sync_filter_->Send(msg);
}

}