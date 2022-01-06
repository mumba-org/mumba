// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_MARKET_MARKET_DISPATCHER_H_
#define MUMBA_HOST_MARKET_MARKET_DISPATCHER_H_

#include <memory>

#include "base/macros.h"
#include "base/uuid.h"
#include "core/shared/common/mojom/market.mojom.h"

namespace host {

/*
 *  IPC interface between applications and market related ops
 */
class MarketDispatcher : public common::mojom::MarketDispatcher {
public:
  MarketDispatcher();
  ~MarketDispatcher() override;

  void Info(InfoCallback callback) override;
  void SetCursor(const std::string& id, int cursor, SetCursorCallback callback) override;
  void SubmitTransaction(const std::string& envelope, SubmitTransactionCallback callback) override;
  
private:
  DISALLOW_COPY_AND_ASSIGN(MarketDispatcher);
};

}

#endif