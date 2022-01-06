// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_MARKET_TRANSACTION_MODEL_H_
#define MUMBA_HOST_MARKET_TRANSACTION_MODEL_H_

#include <memory>

#include "base/macros.h"
#include "base/uuid.h"

namespace host {

class TransactionModel {
public:
  TransactionModel();  
  ~TransactionModel();
  
private:
    
  DISALLOW_COPY_AND_ASSIGN(TransactionModel);
};

}

#endif