// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/io_status.h"

namespace host {

const char* IOStatusToString(IOStatus st) {
 if (st == IOStatus::Ok)
  return "Ok";
 else if (st == IOStatus::IOError)
  return "IO Error";
 else if (st == IOStatus::Corrupt)
  return "Corrupt";
 else if (st == IOStatus::NotFound)
  return "Not Found";

 return 0;
}

}