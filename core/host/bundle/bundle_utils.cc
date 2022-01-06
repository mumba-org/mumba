// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/bundle/bundle_utils.h"

#include "core/host/bundle/bundle.h"
#include "third_party/msix/src/inc/public/AppxPackaging.hpp"
#include "third_party/msix/src/inc/shared/ComHelper.hpp"
#include "third_party/msix/src/inc/internal/StringStream.hpp"
#include "third_party/msix/src/inc/internal/VectorStream.hpp"
#include "third_party/msix/src/inc/internal/AppxPackageObject.hpp"
#include "third_party/msix/src/inc/internal/ZipObjectReader.hpp"

namespace host {

namespace {
  LPVOID STDMETHODCALLTYPE MyAllocate(SIZE_T cb) { return std::malloc(cb); }
  void STDMETHODCALLTYPE MyFree(LPVOID pv) { std::free(pv); }
}

// static 
std::string BundleUtils::GetPackageUnpackPath(const base::FilePath& package) {
  MSIX::ComPtr<IStream> package_stream;
  MSIX::ComPtr<IAppxFactory> factory;
  MSIX::ComPtr<IAppxManifestReader> manifest_reader;
  
  if (CoCreateAppxFactoryWithHeap(
        MyAllocate,
        MyFree,
        MSIX_VALIDATION_OPTION::MSIX_VALIDATION_OPTION_SKIPSIGNATURE,
        &factory) != 0) {
     DLOG(INFO) << "CoCreateAppxFactoryWithHeap failed";
     return std::string();
  }

  if (CreateStreamOnFile(const_cast<char *>(package.value().c_str()), true, &package_stream) != 0) {
    DLOG(INFO) << "CreateStreamOnFile failed";
    return std::string();
  }

  auto zip = MSIX::ComPtr<IStorageObject>::Make<MSIX::ZipObjectReader>(package_stream.Get());
  MSIX::ComPtr<IAppxPackageReader> package_reader = MSIX::ComPtr<IAppxPackageReader>::Make<MSIX::AppxPackageObject>(
    static_cast<MSIX::AppxFactory *>(factory.Get()), 
    MSIX_VALIDATION_OPTION::MSIX_VALIDATION_OPTION_SKIPSIGNATURE, 
    MSIX_APPLICABILITY_OPTIONS::MSIX_APPLICABILITY_OPTION_FULL, 
    zip);

  
  return BundleUtils::GetPackageFullName(package_reader.Get());
}

// static 
std::unique_ptr<Bundle> BundleUtils::CreateBundleFromBundleFile(const base::FilePath& package) {
  MSIX::ComPtr<IStream> package_stream;
  MSIX::ComPtr<IAppxFactory> factory;
  std::unique_ptr<Bundle> result;
  
  if (CoCreateAppxFactoryWithHeap(
        MyAllocate,
        MyFree,
        MSIX_VALIDATION_OPTION::MSIX_VALIDATION_OPTION_SKIPSIGNATURE,
        &factory) != 0) {
     DLOG(INFO) << "CoCreateAppxFactoryWithHeap failed";
     return result;
  }

  if (CreateStreamOnFile(const_cast<char *>(package.value().c_str()), true, &package_stream) != 0) {
    DLOG(INFO) << "CreateStreamOnFile failed";
    return result;
  }

  auto zip = MSIX::ComPtr<IStorageObject>::Make<MSIX::ZipObjectReader>(package_stream.Get());
  MSIX::ComPtr<IAppxPackageReader> package_reader = MSIX::ComPtr<IAppxPackageReader>::Make<MSIX::AppxPackageObject>(
    static_cast<MSIX::AppxFactory *>(factory.Get()), 
    MSIX_VALIDATION_OPTION::MSIX_VALIDATION_OPTION_SKIPSIGNATURE, 
    MSIX_APPLICABILITY_OPTIONS::MSIX_APPLICABILITY_OPTION_FULL, 
    zip);

  return result;
}

// static 
std::string BundleUtils::GetPackageFullName(IAppxPackageReader* package_reader) {
  MSIX::ComPtr<IAppxManifestReader> manifest_reader;
  MSIX::AppxPackageObject* package_object = static_cast<MSIX::AppxPackageObject *>(package_reader);
  package_object->GetManifest(&manifest_reader);
  MSIX::ComPtr<IAppxManifestPackageId> packageId;
  manifest_reader->GetPackageId(&packageId);
  return packageId.As<IAppxManifestPackageIdInternal>()->GetPackageFullName();
}

}