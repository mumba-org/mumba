// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_ID_GENERATOR_H_
#define MUMBA_DOMAIN_ID_GENERATOR_H_

#include <string>

#include "base/uuid.h"

namespace domain {

//std::string GenerateRandomUniqueID();

base::UUID GenerateRandomUniqueID();
  
}

#endif