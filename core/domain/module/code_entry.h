// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DOMAIN_EXECUTION_CODE_ENTRY_H_
#define DOMAIN_EXECUTION_CODE_ENTRY_H_

#include <string>

namespace domain {

typedef uintptr_t Address;
static const Address kNullAddress = 0;

struct CodeEntry {
  std::string name;
  Address entry = kNullAddress;
};

}

#endif