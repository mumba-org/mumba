// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_HOST_SUBTHREAD_H__
#define MUMBA_HOST_HOST_SUBTHREAD_H__

#include "core/host/host_thread.h"

namespace host {
class NotificationService;

class HostSubThread : public HostThread {
public:
 HostSubThread(HostThread::ID id);
 HostSubThread(HostThread::ID id, scoped_refptr<base::SingleThreadTaskRunner> task_runner);
 ~HostSubThread() override;

protected:
 void Init() override;
 void CleanUp() override;

private:
 // These methods encapsulate cleanup that needs to happen on the IO thread
 // before we call the embedder's CleanUp function.
 void IOThreadPreCleanUp();

 // Each specialized thread has its own notification service.
 std::unique_ptr<NotificationService> notification_service_;

 DISALLOW_COPY_AND_ASSIGN(HostSubThread);
};

}

#endif