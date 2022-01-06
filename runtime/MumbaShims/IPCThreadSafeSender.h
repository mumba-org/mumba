// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_RUNTIME_MUMBA_SHIMS_IPC_THREAD_SAFE_SENDER_H__
#define MUMBA_RUNTIME_MUMBA_SHIMS_IPC_THREAD_SAFE_SENDER_H__

#include "base/gtest_prod_util.h"
#include "base/memory/ref_counted.h"
#include "ipc/ipc_sender.h"

namespace base {
class SingleThreadTaskRunner;
}

namespace IPC {
class SyncMessageFilter;
}

class IPCClientThread;

// The class of Sender returned by ChildThread::thread_safe_sender().
class IPCThreadSafeSender
    : public IPC::Sender,
      public base::RefCountedThreadSafe<IPCThreadSafeSender> {
 public:
  bool Send(IPC::Message* msg) override;

 private:
  friend class IPCClientThread;  // for construction
  friend class base::RefCountedThreadSafe<IPCThreadSafeSender>;

  IPCThreadSafeSender(const scoped_refptr<base::SingleThreadTaskRunner>& main_task_runner,
                   const scoped_refptr<IPC::SyncMessageFilter>& sync_filter);
  ~IPCThreadSafeSender() override;

  scoped_refptr<base::SingleThreadTaskRunner> main_task_runner_;
  scoped_refptr<IPC::SyncMessageFilter> sync_filter_;

  DISALLOW_COPY_AND_ASSIGN(IPCThreadSafeSender);
};

#endif  // COMMAND_OMMON_THREAD_SAFE_SENDER_H_
