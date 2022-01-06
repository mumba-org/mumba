// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_MARKET_ORDER_H_
#define MUMBA_HOST_MARKET_ORDER_H_

#include <memory>

#include "base/macros.h"
#include "base/uuid.h"

namespace host {

enum class OrderType : int32_t {
  BUY = 0,
  SELL = 1
};

class Order {
public:
  virtual ~Order();

  OrderType type() const {
    return type_;
  }
  
protected:
  Order(OrderType type); 
private:
  
  OrderType type_;

  DISALLOW_COPY_AND_ASSIGN(Order);
};

class BuyOrder : public Order {
public:
  BuyOrder();
  ~BuyOrder() override;

private:

};

class SellOrder : public Order {
public:
  SellOrder();
  ~SellOrder() override;
  
private:

};

}

#endif