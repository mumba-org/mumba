// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_MARKET_ACCOUNT_H_
#define MUMBA_HOST_MARKET_ACCOUNT_H_

#include <memory>

#include "base/macros.h"
#include "base/uuid.h"
#include "base/callback.h"
#include "base/strings/string_piece.h"
#include "core/host/serializable.h"
#include "core/common/proto/objects.pb.h"

namespace host {
class AccountBalance;

class Account : public Serializable {
public:
  
  static char kClassName[];
  static std::unique_ptr<Account> Deserialize(net::IOBuffer* buffer, int size);

  Account();
  ~Account() override;

  const base::UUID& id() const {
    return id_;
  }

  bool is_managed() const {
    return managed_;
  }

  void set_managed(bool managed) {
    managed_ = managed;
  }

  scoped_refptr<net::IOBufferWithSize> Serialize() const override;
  void GetBalance(base::Callback<void(std::unique_ptr<AccountBalance> balance)> completion);
  
private:
  
  base::UUID id_;
  //protocol::Account account_proto_;
  bool managed_;

  DISALLOW_COPY_AND_ASSIGN(Account);
};

}

#endif