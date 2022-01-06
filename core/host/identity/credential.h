// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_IDENTITY_CREDENTIAL_H_
#define MUMBA_HOST_IDENTITY_CREDENTIAL_H_

#include <memory>

#include "base/macros.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "base/strings/string_piece.h"
#include "base/uuid.h"
#include "core/common/proto/objects.pb.h"
#include "core/host/serializable.h"

namespace host {
class Identity;
class CredentialKey;
/*
 * Its a one-to-many relationship with identities
 * 1 identity - M credentials
 * Credentials are tied to third-party entities (banks, social networks, etc..)
 *
 * Every identity have at least one Credential
 * which is the Credential associated with Mumba
 *
 * The mumba credential is the one used to identify
 * the DHT slot/signature used to publish the applications
 */
class Credential : public Serializable {
public:
  static char kClassName[];
  static std::unique_ptr<Credential> Deserialize(net::IOBuffer* buffer, int size);
  
  ~Credential() override;

  const base::UUID& id() const {
    return id_;
  }

  protocol::CredentialType type() const;

  const std::string& identifier() const;
  const std::string& user() const;
  const std::string& login() const;
  const std::string& password() const; // sha256
  const std::string& provider() const;
  const std::string& description() const;

  CredentialKey* credential_key() const {
    return credential_key_.get();
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
  friend class Identity; // for credential_proto

  Credential();
  Credential(protocol::Credential credential_proto);

  base::UUID id_;

  protocol::Credential credential_proto_;

  std::unique_ptr<CredentialKey> credential_key_;

  bool managed_;

  DISALLOW_COPY_AND_ASSIGN(Credential);
};

}

#endif