// Copyright (c) 2018 Mutante. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TOOLS_GN_SWIFT_OUTPUT_MAP_WRITER_WRITER_H_
#define TOOLS_GN_SWIFT_OUTPUT_MAP_WRITER_WRITER_H_

#include "base/macros.h"
#include "gen/target.h"

class SwiftOutputMapWriter {
public:
  
  static bool WriteFile(scoped_refptr<Target> target);
  
  SwiftOutputMapWriter() {}
  ~SwiftOutputMapWriter() = default;

private:

  DISALLOW_COPY_AND_ASSIGN(SwiftOutputMapWriter);
};

#endif