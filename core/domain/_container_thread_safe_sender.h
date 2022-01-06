// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_DOMAIN_DOMAIN_THREAD_SAFE_SENDER_H__
#define MUMBA_DOMAIN_DOMAIN_DOMAIN_THREAD_SAFE_SENDER_H__

#include "base/template_util.h"
#include "base/gtest_prod_util.h"
#include "base/memory/ref_counted.h"
#include "ipc/ipc_sender.h"

namespace base {
class SingleThreadTaskRunner;
}

namespace IPC {
class SyncMessageFilter;
}

namespace domain {
	
class DomainMainThread;

// The class of Sender returned by ChildThread::thread_safe_sender().
class DomainThreadSafeSender
    : public IPC::Sender,
      public base::RefCountedThreadSafe<DomainThreadSafeSender> {
 public:
  bool Send(IPC::Message* msg) override;

 private:
  friend class DomainMainThread;  // for construction
  friend class base::RefCountedThreadSafe<DomainThreadSafeSender>;

  DomainThreadSafeSender(const scoped_refptr<base::SingleThreadTaskRunner>& main_task_runner,
                      const scoped_refptr<IPC::SyncMessageFilter>& sync_filter);
  
  ~DomainThreadSafeSender() override;

  scoped_refptr<base::SingleThreadTaskRunner> main_task_runner_;
  scoped_refptr<IPC::SyncMessageFilter> sync_filter_;

  DISALLOW_COPY_AND_ASSIGN(DomainThreadSafeSender);
};

}

#endif  // MUMBA_DOMAIN_DOMAIN_DOMAIN_THREAD_SAFE_SENDER_H__
