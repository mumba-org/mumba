// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_MARKET_MARKET_H_
#define MUMBA_HOST_MARKET_MARKET_H_

#include <memory>

#include "base/macros.h"
#include "base/uuid.h"
#include "core/host/market/asset.h"

namespace host {

/*
 * market ops on the ledger
 * See if its better to have sliced markets 
 * focused on coin and tokens, or if we use this
 * as a major point for all of them
 */
class Market {
public:
  Market();
  ~Market();

private:

  DISALLOW_COPY_AND_ASSIGN(Market);  
};

}

#endif