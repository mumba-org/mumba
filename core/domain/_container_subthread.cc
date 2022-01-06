// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/domain/domain_subthread.h"

#include "base/threading/thread_restrictions.h"
#include "core/domain/notification_service.h"
#include "core/domain/notification_service_impl.h"
#include "core/domain/domain_thread.h"
//#include "core/domain/domain_child_process_host.h"

namespace domain {

DomainSubThread::DomainSubThread(DomainThread::ID id): 
 DomainThread(id) {

}

DomainSubThread::~DomainSubThread() {

}

void DomainSubThread::Init() {
 notification_service_.reset(new NotificationServiceImpl());

 DomainThread::Init();

 // if (DomainThread::CurrentlyOn(DomainThread::V8)) {
 //  // Though this thread is called the "IO" thread, it actually just routes
 //  // messages around; it shouldn't be allowed to perform any blocking disk
 //  // I/O.
 //  base::ThreadRestrictions::SetIOAllowed(false);
 //  base::ThreadRestrictions::DisallowWaiting();
 // }
}

void DomainSubThread::CleanUp() {
 DomainThread::CleanUp();

 notification_service_.reset();
}

}