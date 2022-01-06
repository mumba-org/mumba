// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_BUNDLE_UTILS_H_
#define MUMBA_HOST_BUNDLE_UTILS_H_

#include <memory>

#include "base/macros.h"
#include "base/uuid.h"
#include "base/strings/string_piece.h"
#include "base/files/file_path.h"
#include "third_party/msix/src/inc/public/AppxPackaging.hpp"

namespace host {
class Bundle;

class BundleUtils {
public:
  ~BundleUtils() {}

  /*
   * Get the output path of a given package
   */
  static std::string GetPackageUnpackPath(const base::FilePath& package);
  static std::unique_ptr<Bundle> CreateBundleFromBundleFile(const base::FilePath& package);


private:

  static std::string GetPackageFullName(IAppxPackageReader* package_reader);

  BundleUtils() {}

  DISALLOW_COPY_AND_ASSIGN(BundleUtils);
};

}

#endif