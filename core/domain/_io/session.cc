// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/domain/io/session.h"

#include "core/domain/io/connection.h"

namespace domain {

Session::Session(std::unique_ptr<Connection> connection): 
  id_(0),
  connection_(std::move(connection)) {

}

Session::~Session() {

}

void Session::AddSubscription(const std::string& name) {
  
}

void Session::RemoveSubscription(const std::string& name) {

}

}