// Copyright 2017 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_COMMON_DATA_DATA_SOURCE_H_
#define MUMBA_COMMON_DATA_DATA_SOURCE_H_

#include <string>

#include "base/macros.h"

namespace common {

class DataSource {
public:
  virtual ~DataSource(){}
  virtual size_t row_count() const = 0;
  virtual size_t column_count() const = 0;
  virtual bool Encode(std::string* out) = 0;
};
  
}

#endif