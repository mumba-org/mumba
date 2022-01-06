// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_DATABASE_POLICY_H_
#define MUMBA_HOST_DATABASE_POLICY_H_

namespace host {

enum class DatabasePolicy {
  AlwaysOpen,
  OpenClose
};

class DatabasePolicyObserver {
public:
  virtual ~DatabasePolicyObserver() {} 	
  virtual void OnDatabasePolicyChanged(DatabasePolicy new_policy) {}
};

}
#endif