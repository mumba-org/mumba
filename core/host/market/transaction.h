// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_MARKET_TRANSACTION_H_
#define MUMBA_HOST_MARKET_TRANSACTION_H_

#include <memory>

#include "base/macros.h"
#include "base/uuid.h"
#include "core/host/market/operation.h"

namespace host {
class TransactionBuilder;

class Transaction {
public:
  Transaction();  
  ~Transaction();

  std::vector<Operation*> ListOperations();
  std::vector<Operation*> ListOperationsByType(OperationType type);
  
private:
  friend class TransactionBuilder;

  Transaction(std::vector<std::unique_ptr<Operation>> operations);

  // cached operations
  std::vector<std::unique_ptr<Operation>> operations_;

  DISALLOW_COPY_AND_ASSIGN(Transaction);
};

}

#endif