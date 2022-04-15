// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_IDENTITY_IDENTITY_H_
#define MUMBA_HOST_IDENTITY_IDENTITY_H_

#include <memory>

#include "base/macros.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "base/strings/string_piece.h"
#include "base/uuid.h"
#include "core/host/data/resource.h"
#include "core/common/proto/objects.pb.h"
#include "core/host/serializable.h"

namespace host {
class Credential;
class IdentityManager;

class Identity : public Resource {
public:
  static char kClassName[];
  static std::unique_ptr<Identity> Deserialize(net::IOBuffer* buffer, int size);
  
  ~Identity() override;

  const base::UUID& id() const override {
    return id_;
  }

  const std::string& name() const override;
  const std::string& login() const;
  const std::string& description() const;
  
  bool is_managed() const override {
    return managed_;
  }

  void set_managed(bool managed) {
    managed_ = managed;
  }

  std::vector<Credential*> GetCredentials();
  Credential* GetCredential(base::UUID& credential_id);
  Credential* GetCredential(const std::string& identifier);
  void AddCredential(std::unique_ptr<Credential> credential);
  void RemoveCredential(base::UUID& credential_id);
  void RemoveCredential(const std::string& identifier);
  
  scoped_refptr<net::IOBufferWithSize> Serialize() const override;

private:
  Identity();
  Identity(protocol::Identity identity_proto);
  
  void AddCredentialToProto(Credential* credential);
  void RemoveCredentialFromProtoByUUID(const std::string& uuid);
  void RemoveCredentialFromProtoByIdentifier(const std::string& identifier);

  base::Lock credentials_lock_;

  base::UUID id_;

  protocol::Identity identity_proto_;

  std::vector<std::unique_ptr<Credential>> credentials_;

  bool managed_;

  DISALLOW_COPY_AND_ASSIGN(Identity);
};

}

#endif