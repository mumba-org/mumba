// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "IPCThreadSafeSender.h"

#include "base/single_thread_task_runner.h"
#include "IPCClientThread.h"
#include "ipc/ipc_sync_message_filter.h"

IPCThreadSafeSender::IPCThreadSafeSender(
    const scoped_refptr<base::SingleThreadTaskRunner>& main_task_runner,
    const scoped_refptr<IPC::SyncMessageFilter>& sync_filter)
    : main_task_runner_(main_task_runner), sync_filter_(sync_filter) {
}

IPCThreadSafeSender::~IPCThreadSafeSender() {
 
}

bool IPCThreadSafeSender::Send(IPC::Message* msg) {
  if (main_task_runner_->BelongsToCurrentThread())
    return IPCClientThread::current()->Send(msg);
  return sync_filter_->Send(msg);
}
