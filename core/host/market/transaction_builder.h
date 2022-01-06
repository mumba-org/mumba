// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_MARKET_TRANSACTION_BUILDER_H_
#define MUMBA_HOST_MARKET_TRANSACTION_BUILDER_H_

#include <memory>

#include "base/macros.h"
#include "base/uuid.h"

namespace host {
class Transaction;

class TransactionBuilder {
public:
  TransactionBuilder();  
  ~TransactionBuilder();

  std::unique_ptr<Transaction> Build();
  
private:
  
  std::vector<std::unique_ptr<Operation>> operations_;

  DISALLOW_COPY_AND_ASSIGN(TransactionBuilder);
};

}

#endif