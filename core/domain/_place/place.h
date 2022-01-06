// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_PLACE_PLACE_H_
#define MUMBA_DOMAIN_PLACE_PLACE_H_

#include "base/macros.h"
#include "base/uuid.h"
#include "base/memory/ref_counted.h"
#include "core/shared/common/mojom/place.mojom.h"

namespace domain {
class PlaceHandler;

class Place {
public:
  Place(PlaceHandler* handler, const std::string& key);
  ~Place();

  const std::string& key() const {
    return key_;
  }

  void HandleLoad(const std::string& key, base::StringPiece data);
  void HandleUnload(const std::string& key);
  
private:  
  PlaceHandler* handler_;

  std::string key_;

  DISALLOW_COPY_AND_ASSIGN(FileStorage);
};

}

#endif