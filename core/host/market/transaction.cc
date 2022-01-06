// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/market/transaction.h"

namespace host {

Transaction::Transaction() {
  
}

Transaction::~Transaction() {
  
}

Transaction::Transaction(std::vector<std::unique_ptr<Operation>> operations) {
  
}

std::vector<Operation*> Transaction::ListOperations() {
  return std::vector<Operation*>();
}

std::vector<Operation*> Transaction::ListOperationsByType(OperationType type) {
  return std::vector<Operation*>();   
}

}