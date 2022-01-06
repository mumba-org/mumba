// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_IDENTITY_CREDENTIAL_KEY_H_
#define MUMBA_HOST_IDENTITY_CREDENTIAL_KEY_H_

#include <memory>

#include "base/macros.h"
#include "base/uuid.h"
#include "core/common/proto/objects.pb.h"
#include "core/host/serializable.h"

namespace host {
class Credential;

/*
 * CredentialKey is a public cryptographic key pair that is persisted and associated and with a Credential
 */
class CredentialKey : public Serializable {
public:
  static char kClassName[];
  static std::unique_ptr<CredentialKey> Deserialize(net::IOBuffer* buffer, int size);
  
  ~CredentialKey() override;

  Credential* credential() const {
    return credential_;
  }

  const base::UUID& id() const {
    return id_;
  }

  // public key raw bytes
  const std::string& public_key() const;
  // eg. ed25519
  const std::string& public_key_type() const;
  // eg. base64
  const std::string& public_key_encoding() const;

  bool is_managed() const {
    return managed_;
  }

  void set_managed(bool managed) {
    managed_ = managed;
  }

  scoped_refptr<net::IOBufferWithSize> Serialize() const override;
    
private:

  CredentialKey();
  CredentialKey(protocol::CredentialKey credential_proto);

  Credential* credential_;
  base::UUID id_;
  protocol::CredentialKey credential_key_proto_;
  bool managed_;

  DISALLOW_COPY_AND_ASSIGN(CredentialKey);
};

}

#endif