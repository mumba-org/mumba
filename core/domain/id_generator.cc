// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/domain/id_generator.h"

#include "base/rand_util.h"
#include "base/strings/string_util.h"
#include "components/base32/base32.h"

namespace domain {

//const int kRandomByteSize = 12;

base::UUID GenerateRandomUniqueID() {
  //std::string random_bytes = base::RandBytesAsString(kRandomByteSize);
  //return base::ToLowerASCII(base32::Base32Encode(random_bytes, base32::Base32EncodePolicy::OMIT_PADDING));
  return base::UUID::generate();
}

}