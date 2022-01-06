// Copyright (c) 2017 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_DOMAIN_SUBTHREAD_H__
#define MUMBA_DOMAIN_DOMAIN_SUBTHREAD_H__

#include "core/domain/domain_thread.h"

namespace domain {
class NotificationService;

class DomainSubThread : public DomainThread {
public:
  
 explicit DomainSubThread(DomainThread::ID id);
 ~DomainSubThread() override;

protected:
 void Init() override;
 void CleanUp() override;

private:
 // These methods encapsulate cleanup that needs to happen on the IO thread
 // before we call the embedder's CleanUp function.
 //void V8ThreadPreCleanUp();

 // Each specialized thread has its own notification service.
 std::unique_ptr<NotificationService> notification_service_;

 DISALLOW_COPY_AND_ASSIGN(DomainSubThread);
};

}

#endif