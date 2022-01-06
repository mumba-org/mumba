// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/market/order.h"

namespace host {

Order::Order(OrderType type): type_(type) {

}

Order::~Order() {

}

BuyOrder::BuyOrder(): Order(OrderType::BUY) {

}

BuyOrder::~BuyOrder() {

}

SellOrder::SellOrder(): Order(OrderType::SELL) {

}

SellOrder::~SellOrder() {

}

}