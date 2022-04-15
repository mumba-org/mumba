// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_SESSION_SESSION_H_
#define MUMBA_HOST_SESSION_SESSION_H_

#include <memory>

#include "base/macros.h"
#include "base/uuid.h"
#include "core/common/proto/objects.pb.h"
#include "core/host/serializable.h"
#include "core/host/data/resource.h"

namespace host {
class CredentialKey;
class Credential;
class Domain;
class Identity;
/*
 * Session is the universal access token whenever a user or application
 * needs to consume any resources exposed by the platform
 */

// two types of sessions:
//  user or app
// application sessions are created for the domains
// and all the running applications underneath the domain
// will use the same session, working on behalf of the domain

enum class SessionType {
   kSESSION_TYPE_USER_ = 0,
   kSESSION_TYPE_APPLICATION = 1,
};

class Session : public Resource {
public:
  static char kClassName[];
  static std::unique_ptr<Session> Deserialize(net::IOBuffer* buffer, int size);
  
  ~Session() override;

  // associated credential
  Credential* credential() const {
    return credential_;
  }

  // associated key -> from credential
  CredentialKey* credential_key() const;

  const base::UUID& id() const override {
    return id_;
  }

  const std::string& name() const override {
    return id_.to_string();
  }

  bool is_managed() const override {
    return false;
  }

  SessionType type() const {
    return type_;
  }

  base::TimeTicks started_time() const {
    return started_;
  }

  base::TimeTicks finished_time() const {
    return finished_;
  }

  // if this is a user session, points to the user identity
  Identity* identity() const {
    return identity_;
  }

  // if this is a application session, points to the domain
  Domain* domain() const {
    return domain_;
  }
    
private:
  
  Credential* credential_;
  Identity* identity_;
  Domain* domain_;
  base::UUID id_;
  SessionType type_;
  base::TimeTicks started_;
  base::TimeTicks finished_;

  DISALLOW_COPY_AND_ASSIGN(Session);
};

}

#endif