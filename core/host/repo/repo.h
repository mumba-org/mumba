// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_REPO_REPO_H_
#define MUMBA_HOST_REPO_REPO_H_

#include <memory>

#include "base/macros.h"
#include "base/uuid.h"
#include "core/host/serializable.h"
#include "core/shared/common/mojom/repo.mojom.h"
#include "core/common/proto/objects.pb.h"
#include "core/host/data/resource.h"

namespace host {

enum class RepoState {
  kINVALID,
  kSYNCING_METADATA,
  kVALID,
};

class Repo : public Resource {
public:
  static char kClassName[];
  static std::unique_ptr<Repo> Deserialize(net::IOBuffer* buffer, int size);
  static std::unique_ptr<Repo> FromRepoEntry(common::mojom::RepoEntryPtr entry);

  Repo();
  Repo(protocol::Repo repo_proto);
  ~Repo() override;

  const base::UUID& id() const override {
    return id_;
  }

  const std::string& name() const override;
  void set_name(const std::string& name);
  protocol::RepoType type() const;
  void set_type(protocol::RepoType type);
  const std::string& address() const;
  void set_address(const std::string& url);
  protocol::AddressFormat address_format() const;
  void set_address_format(protocol::AddressFormat format);
  const std::string& address_format_version() const;
  void set_address_format_version(const std::string& address_format_version);
  const std::string& public_key() const;
  void set_public_key(const std::string& key);
  protocol::PKCryptoFormat pk_crypto_format() const;
  void set_pk_crypto_format(protocol::PKCryptoFormat format);
  const base::UUID& root_tree() const;
  void set_root_tree(base::UUID& root_tree);
  const std::string& creator() const;
  void set_creator(const std::string& creator);

  RepoState state() const {
    return state_;
  }

  bool is_managed() const override {
    return managed_;
  }

  void set_managed(bool managed) {
    managed_ = managed;
  }

  void mark_sync();

  scoped_refptr<net::IOBufferWithSize> Serialize() const override;
  
  common::mojom::RepoEntryPtr ToRepoEntry();
  void Clone(common::mojom::RepoEntryPtr entry);
  
private:
  base::UUID id_;
  base::UUID root_tree_;
  protocol::Repo repo_proto_;
  bool managed_;
  bool should_sync_;
  RepoState state_;

  DISALLOW_COPY_AND_ASSIGN(Repo);
};

}

#endif
