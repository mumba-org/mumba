// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/domain/place/place.h"

#include "core/domain/place/place_handler.h"

namespace domain {

Place::Place(PlaceHandler* handler, const std::string& key): 
  handler_(handler),
  key_(key) {

}

Place::~Place() {

}

void Place::HandleLoad(const std::string& key, base::StringPiece data) {
  handler_->OnLoad(key, data);
}

void Place::HandleUnload(const std::string& key) {
  handler_->OnUnload(key);
}
  
}