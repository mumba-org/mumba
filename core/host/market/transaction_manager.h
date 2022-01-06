// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_MARKET_TRANSACTION_MANAGER_H_
#define MUMBA_HOST_MARKET_TRANSACTION_MANAGER_H_

#include <memory>

#include "base/macros.h"
#include "base/uuid.h"

namespace host {
class MarketManager;

class TransactionManager {
public:
  TransactionManager(MarketManager* market_manager);  
  ~TransactionManager();

  MarketManager* market_manager() const {
    return market_manager_;
  }
  
private:

  MarketManager* market_manager_;
    
  DISALLOW_COPY_AND_ASSIGN(TransactionManager);
};

}

#endif