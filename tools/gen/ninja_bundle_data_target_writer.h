// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TOOLS_GN_NINJA_BUNDLE_DATA_TARGET_WRITER_H_
#define TOOLS_GN_NINJA_BUNDLE_DATA_TARGET_WRITER_H_

#include "base/macros.h"
#include "gen/ninja_target_writer.h"

// Writes a .ninja file for a bundle_data target type.
class NinjaBundleDataTargetWriter : public NinjaTargetWriter {
 public:
  NinjaBundleDataTargetWriter(scoped_refptr<Target> target, std::ostream& out);
  ~NinjaBundleDataTargetWriter() override;

  void Run() override;

 private:
  DISALLOW_COPY_AND_ASSIGN(NinjaBundleDataTargetWriter);
};

#endif  // TOOLS_GN_NINJA_BUNDLE_DATA_TARGET_WRITER_H_
