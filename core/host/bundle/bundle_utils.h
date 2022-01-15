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
#include "core/host/bundle/bundle_info.h"
#include "third_party/msix/src/inc/public/AppxPackaging.hpp"

namespace host {
class Bundle;
class BundlePackage;

const char kBIN_PATH[] = "bin";
const char kAPPS_PATH[] = "apps";
const char kAPP_PATH[] = "app";
const char kSERVICE_PATH[] = "service";
const char kRESOURCES_PATH[] = "resources";
const char kPROTO_PATH[] = "proto";
const char kDATABASES_PATH[] = "databases";
const char kSHARES_PATH[] = "shares";
const char kFILES_PATH[] = "files";

const char kBUNDLE_EXT[] = ".bundle";
const char kAPP_EXT[] = ".appx";
const char kBUILD_FILE[] = "BUILD.gn";

const char kWORLD_BUNDLE[] = "world";
const char kBUNDLE_MANIFEST[] = "AppxManifest.xml";

class BundleUtils {
public:
  ~BundleUtils() {}

  /*
   * Get the output path of a given package
   */
  static std::string GetPackageUnpackPath(const base::FilePath& package);
  static std::unique_ptr<Bundle> CreateBundleFromBundleFile(const base::FilePath& package);
  static std::unique_ptr<BundlePackage> CreateBundlePackageFromPackageFile(const base::FilePath& package, BundlePackageType type, uint64_t size);
  static bool UnpackBundle(const base::FilePath& src, const base::FilePath& dest);
  // sign the collection of bundle files, with the same signature
  static bool SignBundle(const base::FilePath& bundle_file, const std::vector<uint8_t>& public_signature);
  static bool GetBundleSignature(const base::FilePath& bundle_file, std::vector<uint8_t>* public_signature);
  static bool ValidateBundleSignature(const base::FilePath& bundle_file);

private:

  static std::string GetPackageFullName(IAppxPackageReader* package_reader);

  BundleUtils() {}

  DISALLOW_COPY_AND_ASSIGN(BundleUtils);
};

}

#endif