// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/host_subthread.h"

#include "base/threading/thread_restrictions.h"
#include "core/host/notification_service.h"
#include "core/host/notification_service_impl.h"
#include "core/host/host_thread.h"
#include "core/host/host_child_process_host_impl.h"

namespace host {

HostSubThread::HostSubThread(HostThread::ID id): 
 HostThread(id) {

}

HostSubThread::HostSubThread(HostThread::ID id, scoped_refptr<base::SingleThreadTaskRunner> task_runner): 
 HostThread(id, std::move(task_runner)) {

}

HostSubThread::~HostSubThread() {

}

void HostSubThread::Init() {
 notification_service_.reset(new NotificationServiceImpl());

 HostThread::Init();

 if (HostThread::CurrentlyOn(HostThread::IO)) {
  // Though this thread is called the "IO" thread, it actually just routes
  // messages around; it shouldn't be allowed to perform any blocking disk
  // I/O.
  base::ThreadRestrictions::SetIOAllowed(false);
  base::ThreadRestrictions::DisallowWaiting();
 }
}

void HostSubThread::CleanUp() {
 if (HostThread::CurrentlyOn(HostThread::IO))
  IOThreadPreCleanUp();

 HostThread::CleanUp();

 notification_service_.reset();
}

void HostSubThread::IOThreadPreCleanUp() {
 HostChildProcessHostImpl::TerminateAll();
}

}