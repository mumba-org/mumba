// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_PLACE_PLACE_HANDLER_H_
#define MUMBA_DOMAIN_PLACE_PLACE_HANDLER_H_

#include "base/macros.h"
#include "base/uuid.h"

namespace domain {

class PlaceHandler {
public:
  virtual ~PlaceHandler() {}
  virtual void OnLoad(const std::string& key, base::StringPiece data) = 0;
  virtual void OnUnload(const std::string& key) = 0;
};

}

#endif