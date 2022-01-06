// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/application/domain_session.h"

namespace host {

DomainSession::DomainSession(uint32_t id, base::TimeTicks started_time):
  id_(id),
  started_time_(started_time),
  domain_process_(nullptr) {
  
}

DomainSession::~DomainSession() {

}

}