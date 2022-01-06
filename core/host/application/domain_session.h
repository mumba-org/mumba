// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_APPLICATION_DOMAIN_SESSION_H_
#define MUMBA_HOST_APPLICATION_DOMAIN_SESSION_H_

#include <inttypes.h>

#include "base/macros.h"
#include "base/time/time.h"

namespace host {
class DomainProcessHost;
// when 
class DomainSession {
public:
 DomainSession(uint32_t id, base::TimeTicks started_time);
 ~DomainSession();

 uint32_t id() const { return id_; }

 base::TimeTicks started_time() const { return started_time_; }
 
 // associated process. not owned
 DomainProcessHost* domain_process() const {
   return domain_process_;
 }

 void set_domain_process(DomainProcessHost* domain_process) {
   domain_process_ = domain_process;
 }

private:
 
 uint32_t id_;

 base::TimeTicks started_time_;

 DomainProcessHost* domain_process_;

 DISALLOW_COPY_AND_ASSIGN(DomainSession);
};

}

#endif