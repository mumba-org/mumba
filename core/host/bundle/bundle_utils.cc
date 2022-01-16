// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/bundle/bundle_utils.h"

#include "base/strings/utf_string_conversions.h"
#include "core/host/bundle/bundle.h"
#include "core/host/bundle/bundle_package.h"
#include "third_party/msix/src/inc/public/AppxPackaging.hpp"
#include "third_party/msix/src/inc/shared/ComHelper.hpp"
#include "third_party/msix/src/inc/internal/AppxBundleManifest.hpp"
#include "third_party/msix/src/inc/internal/StringStream.hpp"
#include "third_party/msix/src/inc/internal/VectorStream.hpp"
#include "third_party/msix/src/inc/internal/AppxPackageObject.hpp"
#include "third_party/msix/src/inc/internal/ZipObjectReader.hpp"
#include "third_party/msix/src/inc/public/AppxPackaging.hpp"
#include "third_party/msix/src/inc/shared/ComHelper.hpp"
#include "third_party/msix/sample/inc/Helpers.hpp"

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
  MSIX::ComPtr<IAppxPackageReader> package_reader;
  
  try {  
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
    package_reader = MSIX::ComPtr<IAppxPackageReader>::Make<MSIX::AppxPackageObject>(
      static_cast<MSIX::AppxFactory *>(factory.Get()), 
      MSIX_VALIDATION_OPTION::MSIX_VALIDATION_OPTION_SKIPSIGNATURE, 
      MSIX_APPLICABILITY_OPTIONS::MSIX_APPLICABILITY_OPTION_FULL, 
      zip);
  } catch (std::exception const& ex) {
    return std::string();
  }
  return BundleUtils::GetPackageFullName(package_reader.Get());
}

// static 
std::unique_ptr<Bundle> BundleUtils::CreateBundleFromBundleFile(const base::FilePath& package) {
  MSIX::ComPtr<IStream> package_stream;
  MSIX::ComPtr<IAppxFactory> factory;
  MSIX::ComPtr<IAppxBundleFactory> bundleFactory;
        
  MSIX::ComPtr<IAppxBundleReader> bundleReader;
  MSIX::ComPtr<IAppxBundleManifestReader> bundleManifestReader;
  MSIX::ComPtr<IAppxBundleManifestPackageInfoEnumerator> bundleManifestPackageInfoEnumerator;
  
  MSIX::ComPtr<IAppxManifestPackageId> packageId;
  MSIX::ComPtr<IAppxManifestPackageId> properties;
  std::string bundle_name;
  std::string bundle_path;

  std::unique_ptr<Bundle> result = std::make_unique<Bundle>();
  
  try { 
    if (CoCreateAppxBundleFactoryWithHeap(
              MyAllocate,
              MyFree,
              MSIX_VALIDATION_OPTION::MSIX_VALIDATION_OPTION_SKIPSIGNATURE,
              static_cast<MSIX_APPLICABILITY_OPTIONS>(MSIX_APPLICABILITY_OPTIONS::MSIX_APPLICABILITY_OPTION_SKIPPLATFORM |
                                                      MSIX_APPLICABILITY_OPTIONS::MSIX_APPLICABILITY_OPTION_SKIPLANGUAGE),
              &bundleFactory) != 0) {
      return {};
    }
  
    if (CreateStreamOnFile(const_cast<char *>(package.value().c_str()), true, &package_stream) != 0) {
      DLOG(INFO) << "CreateStreamOnFile failed";
      return {};
    }
    
    bundleFactory->CreateBundleReader(package_stream.Get(), &bundleReader);
    
    // get manifest reader
    if (bundleReader->GetManifest(&bundleManifestReader) != 0) {
      DLOG(INFO) << "bundle reader get manifest failed";
      return {};
    }

    if (bundleManifestReader->GetPackageId(&packageId)) {
      DLOG(INFO) << "bundle manifest reader get package id failed";
      return {};
    }

    // MsixSample::Helper::Text<wchar_t> name;
    // packageId->GetName(&name);
    
    // std::string bundle_name;
    // base::WideToUTF8(name.Get(), wcslen(name.Get()), &bundle_name);

    bundle_path = packageId.As<IAppxManifestPackageIdInternal>()->GetPackageFullName();
    //std::string bundle_src_path = packageId.As<IAppxBundleManifestPackageInfoInternal>()->GetFileName();
    bundle_name = packageId.As<IAppxManifestPackageIdInternal>()->GetName();

    if (bundleManifestReader->GetPackageInfoItems(&bundleManifestPackageInfoEnumerator) != 0) {
      DLOG(INFO) << "bundle manifest reader GetPackageInfoItems failed";
      return {};
    }

    BOOL hasCurrent = FALSE;
    if (bundleManifestPackageInfoEnumerator->GetHasCurrent(&hasCurrent) != 0) {
      DLOG(INFO) << "bundle manifest reader GetHasCurrent failed";
      return {};
    }

    while (hasCurrent)
    {
        std::unique_ptr<BundlePackage> bundle_package;
        MSIX::ComPtr<IAppxBundleManifestPackageInfo> bundleManifestPackageInfo;
        bundleManifestPackageInfoEnumerator->GetCurrent(&bundleManifestPackageInfo);

        MsixSample::Helper::Text<char> fileName;
        MSIX::ComPtr<IAppxBundleManifestPackageInfoUtf8> bundleManifestPackageInfoUtf8;
        bundleManifestPackageInfo->QueryInterface(UuidOfImpl<IAppxBundleManifestPackageInfoUtf8>::iid, reinterpret_cast<void**>(&bundleManifestPackageInfoUtf8));
        bundleManifestPackageInfoUtf8->GetFileName(&fileName);
        
        APPX_BUNDLE_PAYLOAD_PACKAGE_TYPE type;
        bundleManifestPackageInfo->GetPackageType(&type);
        
        UINT64 size;
        bundleManifestPackageInfo->GetSize(&size);
        
        bundle_package = BundleUtils::CreateBundlePackageFromPackageFile(package.DirName().AppendASCII(fileName.Get()), static_cast<BundlePackageType>(type), size);
        DCHECK(bundle_package);

        result->AddPackage(std::move(bundle_package));

        bundleManifestPackageInfoEnumerator->MoveNext(&hasCurrent);
    }

  } catch (std::exception const& ex) {
    return {};
  }

  // TODO: add bundle information: name, path, etc
  bundle_name = base::ToLowerASCII(bundle_name);
  size_t offset = bundle_name.find_last_of(".");
  if (offset != std::string::npos) {
    bundle_name = bundle_name.substr(offset+1);
  }
  result->set_name(bundle_name);
  result->set_path(bundle_path);
  result->set_src_path(package.BaseName().value());
  return result;
}

// static 
std::unique_ptr<BundlePackage> BundleUtils::CreateBundlePackageFromPackageFile(const base::FilePath& package, BundlePackageType type, uint64_t size) {
  MSIX::ComPtr<IStream> package_stream;
  MSIX::ComPtr<IAppxFactory> factory;
  MSIX::ComPtr<IAppxManifestReader> manifest_reader;
  MSIX::ComPtr<IAppxManifestPackageId> packageId;
  MSIX::ComPtr<IAppxManifestProperties> properties;
  APPX_PACKAGE_ARCHITECTURE architecture;

  std::unique_ptr<BundlePackage> result;

  try { 
  
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

    // get manifest reader
    if (package_reader->GetManifest(&manifest_reader) != 0) {
      DLOG(INFO) << "package reader get manifest failed";
      return result;
    }

    if (manifest_reader->GetPackageId(&packageId) != 0) {
      DLOG(INFO) << "manifest reader get package id failed";
      return result;
    }

    if (manifest_reader->GetProperties(&properties) != 0) {
      DLOG(INFO) << "manifest reader get package properties failed";
      return result;
    }
    
    packageId->GetArchitecture(&architecture);

    std::string path = packageId.As<IAppxManifestPackageIdInternal>()->GetPackageFullName();
   
    //std::string src_path = package_reader.As<IAppxBundleManifestPackageInfoInternal>()->GetFileName();
    std::string src_path = package.BaseName().value();
    MsixSample::Helper::Text<wchar_t> name;
    std::wstring input_name;
    base::UTF8ToWide("DisplayName", strlen("DisplayName"), &input_name);
    properties->GetStringValue(input_name.data(), &name);
    std::string name_str;
    base::WideToUTF8(name.Get(), wcslen(name.Get()), &name_str);
    // the int codes are the same, so this is safe
    BundleArchitecture arch = static_cast<BundleArchitecture>(architecture);
    // FIXME
    BundlePlatform platform = BundlePlatform::LINUX;
    result = std::make_unique<BundlePackage>(name_str, path, src_path, platform, arch, type, size);
  } catch (std::exception const& ex) {
    return result;
  }
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

// static 
bool BundleUtils::PackBundle(const base::FilePath& input_dir, const base::FilePath& dest) {
  try {  
    MSIX_BUNDLE_OPTIONS options = (MSIX_BUNDLE_OPTIONS)(MSIX_BUNDLE_OPTIONS::MSIX_OPTION_VERBOSE | MSIX_BUNDLE_OPTIONS::MSIX_OPTION_OVERWRITE | MSIX_BUNDLE_OPTIONS::MSIX_BUNDLE_OPTION_FLATBUNDLE);
    if (::PackBundle(
        options,    
        const_cast<char*>(input_dir.value().c_str()),
        const_cast<char*>(dest.value().c_str()),
        nullptr,
        nullptr) != 0) {
      printf("error: failed while creating bundle\n");
      return false; 
    }
  } catch(std::exception const& ex) {
    printf("error: exception while creating %s\n", dest.value().c_str());
    return false;
  }
  return true;
}

// static 
bool BundleUtils::PackPackage(const base::FilePath& input_dir, const base::FilePath& dest) {
  try {  
    if (::PackPackage(
            MSIX_PACKUNPACK_OPTION::MSIX_PACKUNPACK_OPTION_NONE,
            MSIX_VALIDATION_OPTION::MSIX_VALIDATION_OPTION_FULL,
            const_cast<char*>(input_dir.value().c_str()),
            const_cast<char*>(dest.value().c_str())) != 0) {
    
      return false; 
    }
  } catch(std::exception const& ex) {
    printf("error: exception while creating %s\n", dest.value().c_str());
    return false;
  }
  return true;
}  

// static
bool BundleUtils::UnpackBundle(const base::FilePath& src, const base::FilePath& dest) {
  MSIX_VALIDATION_OPTION validation = MSIX_VALIDATION_OPTION_SKIPSIGNATURE;
  MSIX_PACKUNPACK_OPTION packUnpack = MSIX_PACKUNPACK_OPTION_NONE;
  MSIX_APPLICABILITY_OPTIONS applicability = MSIX_APPLICABILITY_OPTION_FULL;

  int r = ::UnpackBundle(packUnpack,
                         validation,
                         applicability,
                         const_cast<char*>(src.value().c_str()),
                         const_cast<char*>(dest.value().c_str()));
  return r == 0;
}

// static 
bool BundleUtils::SignBundle(const base::FilePath& bundle_file, const std::vector<uint8_t>& public_signature) {
  MSIX::ComPtr<IStream> package_stream;
  MSIX::ComPtr<IAppxBundleFactory> factory;
  MSIX::ComPtr<IAppxBundleWriter> bundleWriter;
  
  if (CoCreateAppxBundleFactoryWithHeap(
            MyAllocate,
            MyFree,
            MSIX_VALIDATION_OPTION::MSIX_VALIDATION_OPTION_SKIPSIGNATURE,
            static_cast<MSIX_APPLICABILITY_OPTIONS>(MSIX_APPLICABILITY_OPTIONS::MSIX_APPLICABILITY_OPTION_SKIPPLATFORM |
                                                    MSIX_APPLICABILITY_OPTIONS::MSIX_APPLICABILITY_OPTION_SKIPLANGUAGE),
            &factory) != 0) {
    return false;
  }

  DLOG(INFO) << "CreateStreamOnFile: '" << bundle_file.value() << "'";
  if (CreateStreamOnFile(const_cast<char *>(bundle_file.value().c_str()), true, &package_stream) != 0) {
    DLOG(INFO) << "CreateStreamOnFile failed";
    return false;
  }

  if (factory->CreateBundleWriter(package_stream.Get(), 0, &bundleWriter) != 0) {
    DLOG(INFO) << "CreateBundleWriter failed";
    return false;
  }

  std::vector<uint8_t> signature_data = public_signature;
  auto signature_stream = MSIX::ComPtr<IStream>::Make<MSIX::VectorStream>(&signature_data);

  // get it back to the beginning
  LARGE_INTEGER li{{ 0 }};    
  if (signature_stream->Seek(li, MSIX::StreamBase::Reference::START, nullptr) != 0) {
    DLOG(INFO) << "VectorStream Seek failed";
  }

  std::wstring signature_file;
  base::UTF8ToWide(APPXSIGNATURE_P7X, strlen(APPXSIGNATURE_P7X), &signature_file);

  if (bundleWriter->AddPayloadPackage(signature_file.data(), signature_stream.Get())) {
    DLOG(INFO) << "AddPayloadPackage failed";
    return false;
  }

  return true;
}

// static 
bool BundleUtils::GetBundleSignature(const base::FilePath& bundle_file, std::vector<uint8_t>* public_signature) {
  return false;
}

// static 
bool BundleUtils::ValidateBundleSignature(const base::FilePath& bundle_file) {
  return false;
}

}