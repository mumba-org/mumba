// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/market/account.h"

#include "core/common/protocol/message_serialization.h"
#include "base/strings/string_util.h"


namespace host {

char Account::kClassName[] = "account";

// static 
std::unique_ptr<Account> Account::Deserialize(net::IOBuffer* buffer, int size) {
  // protocol::Account account_proto;
  // protocol::CompoundBuffer cbuffer;
  // cbuffer.Append(buffer, size);
  // cbuffer.Lock();
  // protocol::CompoundBufferInputStream stream(&cbuffer);
  
  // if (!account_proto.ParseFromZeroCopyStream(&stream)) {
  //   return {};
  // }
  // return std::unique_ptr<Account>(new Account(std::move(account_proto)));
  return std::unique_ptr<Account>();
}

Account::Account()://protocol::Account account_proto):
  //id_(reinterpret_cast<const uint8_t *>(account_proto.uuid().data())),
  //account_proto_(std::move(account_proto)),
  managed_(false) {
  
}

Account::~Account() {
  
}


void Account::GetBalance(base::Callback<void(std::unique_ptr<AccountBalance> balance)> completion) {
  
}

scoped_refptr<net::IOBufferWithSize> Account::Serialize() const {
  //return protocol::SerializeMessage(account_proto_);
  return scoped_refptr<net::IOBufferWithSize>();
}

}
