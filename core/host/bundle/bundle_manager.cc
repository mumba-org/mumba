// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/bundle/bundle_manager.h"

#include "base/sha1.h"
#include "base/task_scheduler/post_task.h"
#include "base/base_paths.h"
#include "base/path_service.h"
#include "base/command_line.h"
#include "base/at_exit.h"
#include "base/files/file_util.h"
#include "base/rand_util.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "core/host/workspace/workspace.h"
#include "core/host/bundle/bundle_model.h"
#include "core/host/bundle/bundle_utils.h"
#include "core/host/share/share_database.h"
#include "core/host/bundle/bundle.h"
#include "storage/storage_utils.h"
#include "base/sha1.h"
#include "third_party/msix/src/inc/public/AppxPackaging.hpp"
#include "third_party/msix/src/inc/shared/ComHelper.hpp"
#include "third_party/msix/src/inc/internal/StringStream.hpp"
#include "third_party/msix/src/inc/internal/VectorStream.hpp"

namespace host {

namespace {

std::string SanitizeName(const std::string& name) {
  std::string real_name = name;
  size_t offset = real_name.find_first_of(".");
  if (offset != std::string::npos) {
    real_name = real_name.substr(0, offset);
  }
  return real_name;
}

std::vector<std::string> libraries = {
  "natives_blob.bin",
  "snapshot_blob.bin",
  "icudtl.dat",
  "icudtl55.dat",
};

const char kDEFAULT_BIN_MANIFEST[] = R"(<?xml version="1.0" encoding="utf8" ?>
<Package xmlns="http://schemas.microsoft.com/appx/2010/manifest">
  <Identity Name="__NAME__" 
     Version="0.0.0.1" 
     Publisher="CN=__NAME__, O=__NAME__, L=SanFrancisco, S=California, C=US" 
     ProcessorArchitecture="x64"/>
  <Properties>
    <DisplayName>__NAME__</DisplayName>
    <PublisherDisplayName>__NAME__</PublisherDisplayName>
    <Logo>images\icon-180x180.png</Logo>
  </Properties>
  <Prerequisites>
    <OSMinVersion></OSMinVersion>
    <OSMaxVersionTested></OSMaxVersionTested>
  </Prerequisites>
  <Resources>
    <Resource Language="en-us" />
  </Resources>
   <Dependencies>
    <TargetDeviceFamily Name="Linux.All" MinVersion="0.0.0.0" MaxVersionTested="0.0.0.0"/>
  </Dependencies>
  <Applications>
  <Application Id="__NAME__" Executable="__NAME__" StartPage="/">
    <VisualElements DisplayName="__NAME__" Description="application" 
         Logo="images\apple-icon-180x180.png" ForegroundText="dark" BackgroundColor="#FFFFFF" >
      <SplashScreen Image="images\splash.png" />
    </VisualElements>
  </Application>
</Applications>
</Package>)";

}

BundleManager::BundleManager(Workspace* workspace): 
  workspace_(workspace) {
  
}

BundleManager::~BundleManager() {
  
}

void BundleManager::Init(scoped_refptr<ShareDatabase> db, DatabasePolicy policy) {
  model_.reset(new BundleModel(db, policy));
  model_->Load(base::Bind(&BundleManager::OnLoad, base::Unretained(this)));
}

void BundleManager::AddObserver(BundleManagerObserver* observer) {
  observers_.push_back(observer);
}

void BundleManager::RemoveObserver(BundleManagerObserver* observer) {
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    if (observer == *it) {
      observers_.erase(it);
      return;
    }
  }
}

bool BundleManager::IsBundleInstalled(const std::string& name) const {
  // fixme: the BundleModel must be the real oracle about that now
  //return base::DirectoryExists(path);
  return model_->HaveBundle(name);
}

bool BundleManager::HaveBundle(const base::UUID& id) {
  return model_->HaveBundle(id);
}

bool BundleManager::HaveBundle(const std::string& name) {
  return model_->HaveBundle(name);
}

Bundle* BundleManager::GetBundle(const base::UUID& id) {
  return model_->GetBundle(id);
}

Bundle* BundleManager::GetBundle(const std::string& name) {
  return model_->GetBundle(name);
}

void BundleManager::PackBundle(const std::string& name, const base::FilePath& src, bool no_frontend, base::OnceCallback<void(int)> callback) {
  base::PostTaskWithTraits(
    FROM_HERE,
    { base::WithBaseSyncPrimitives(), base::MayBlock() },
    base::BindOnce(
      &BundleManager::PackBundleImpl, 
      base::Unretained(this), 
      name,
      src,
      no_frontend,
      base::Passed(std::move(callback))));
}

void BundleManager::UnpackBundle(const std::string& name, const base::FilePath& src, base::OnceCallback<void(bool)> callback) {
  base::FilePath dest = GetOutputPath();
  
  base::PostTaskWithTraits(
    FROM_HERE,
    { base::WithBaseSyncPrimitives(), base::MayBlock() },
    base::BindOnce(
      &BundleManager::UnpackBundleImpl, 
      base::Unretained(this), 
      name,
      src,
      dest,
      base::Passed(std::move(callback))));
}

void BundleManager::UnpackBundleFromContents(const std::string& name, base::StringPiece contents, base::OnceCallback<void(bool)> callback) {
  base::FilePath dest = GetOutputPath();
  
  base::PostTaskWithTraits(
    FROM_HERE,
    { base::WithBaseSyncPrimitives(), base::MayBlock() },
    base::BindOnce(
      &BundleManager::UnpackBundleFromContentsImpl, 
      base::Unretained(this), 
      name,
      base::Passed(std::move(contents)),
      dest,
      base::Passed(std::move(callback))));
}

void BundleManager::SignBundle(const base::FilePath& src, const std::vector<uint8_t>& signature, base::OnceCallback<void(int)> callback) {
   base::PostTaskWithTraits(
    FROM_HERE,
    { base::WithBaseSyncPrimitives(), base::MayBlock() },
    base::BindOnce(
      &BundleManager::SignBundleImpl, 
      base::Unretained(this), 
      src,
      signature,
      base::Passed(std::move(callback))));
}

void BundleManager::InitBundle(const std::string& name, const base::FilePath& src, base::OnceCallback<void(int)> callback) {
  base::PostTaskWithTraits(
    FROM_HERE,
    { base::WithBaseSyncPrimitives(), base::MayBlock() },
    base::BindOnce(
      &BundleManager::InitBundleImpl, 
      base::Unretained(this), 
      name,
      src,
      base::Passed(std::move(callback))));
}

void BundleManager::UnpackBundleSync(const std::string& name, const base::FilePath& src, base::OnceCallback<void(bool)> callback) {
  base::FilePath dest = GetOutputPath();
  UnpackBundleImpl(name, src, dest, std::move(callback));
}

void BundleManager::UnpackBundleFromContentsSync(const std::string& name, base::StringPiece contents, base::OnceCallback<void(bool)> callback) {
  base::FilePath dest = GetOutputPath();
  UnpackBundleFromContentsImpl(name, contents, dest, std::move(callback));
}

void BundleManager::UnpackBundleImpl(const std::string& name, const base::FilePath& src, const base::FilePath& dest, base::OnceCallback<void(bool)> callback) {
  std::string real_name = SanitizeName(name);
  
  if (!ValidateBundleBeforeUnpack(src)) {
    std::move(callback).Run(false);
    return;
  }
  
  if (!BeforeBundleUnpack(dest)) {
    std::move(callback).Run(false);
    return;
  }

  if (!BundleUtils::UnpackBundle(src, dest)) {
    DLOG(ERROR) << "BundleManager::UnpackBundle: failed to unpack on " << dest;
    std::move(callback).Run(false);
    return;  
  }

  std::unique_ptr<Bundle> bundle_info = BundleUtils::CreateBundleFromBundleFile(src);
  DCHECK(bundle_info);
  
  base::FilePath unpacked_exe_dest = dest.AppendASCII(bundle_info->application_path());
  
  if (!AfterBundleUnpack(real_name, unpacked_exe_dest)) {
    std::move(callback).Run(false);
    return;
  }

  model_->AddBundle(std::move(bundle_info));

  std::move(callback).Run(true);
}

void BundleManager::UnpackBundleFromContentsImpl(const std::string& name, base::StringPiece contents, const base::FilePath& dest, base::OnceCallback<void(bool)> callback) {
  // uint32_t written = 0;
  // std::vector<std::uint8_t> stream_vector;
  // //LARGE_INTEGER start = {{ 0 }};

  // if (!BeforeBundleUnpack(dest)) {
  //   std::move(callback).Run(false);
  //   return;
  // }
  
  // MSIX::ComPtr<IStream> stream = MSIX::ComPtr<IStream>::Make<MSIX::VectorStream>(&stream_vector);
  // stream->Write(contents.data(), contents.size(), &written);

  // if (written != static_cast<uint32_t>(contents.size())) {
  //   DLOG(ERROR) << "BundleManager::UnpackBundleFromContents: failed to write raw contents to output stream";
  //   std::move(callback).Run(false);
  //   return;
  // }

  // // int r = UnpackPackageFromStream(MSIX_PACKUNPACK_OPTION::MSIX_PACKUNPACK_OPTION_NONE,
  // //                                 MSIX_VALIDATION_OPTION::MSIX_VALIDATION_OPTION_SKIPSIGNATURE, 
  // //                                 stream.Get(), 
  // //                                 const_cast<char*>(dest.value().c_str()));

  // MSIX_VALIDATION_OPTION validation = MSIX_VALIDATION_OPTION_SKIPSIGNATURE;
  // MSIX_PACKUNPACK_OPTION packUnpack = MSIX_PACKUNPACK_OPTION_NONE;
  // MSIX_APPLICABILITY_OPTIONS applicability = MSIX_APPLICABILITY_OPTION_FULL;

  // int r = UnpackBundleFromStream(
  //   packUnpack,
  //   validation,
  //   applicability,
  //   stream.Get(),
  //   const_cast<char*>(dest.value().c_str()));
  
  // if (r != 0) {
  //   DLOG(ERROR) << "BundleManager::UnpackBundleFromContents: failed to unpack on " << dest;
  //   std::move(callback).Run(false);
  //   return;  
  // }

  // std::string real_name = SanitizeName(name);
  // if (!AfterBundleUnpack(real_name, dest)) {
  //   std::move(callback).Run(false);
  //   return;
  // }

  // DISABLED: we dont need to pack in a chrome bundle if its a bundle in itself
  //           we only need to make sure the bundle is available in the mumba installation directory  

  DCHECK(false);
  std::move(callback).Run(true);
}

bool BundleManager::BeforeBundleUnpack(const base::FilePath& dest) const {
  if (!base::DirectoryExists(dest)) {
    if (!base::CreateDirectory(dest)) {
      DLOG(ERROR) << "failed while creating dir " << dest;
      return false;
    }
  }
  return true;
}

bool BundleManager::ValidateBundleBeforeUnpack(const base::FilePath& src) {
  // We need to validate the bundle before unpack like, signature
  // if we have a host os and architecture build too

  // if the host mumba deploy is on windows and the bundle only have
  // linux builds we need to deny installation here
  
  // the first check is to see if the file is really there
  if (!base::PathExists(src)) {
    DLOG(INFO) << "bundle installation failed: bundle file " << src << " is not there";
    return false;
  }

  return true;
}

void BundleManager::OnLoad(int r, int count) {
  NotifyBundlesLoad(r, count);
}

bool BundleManager::AfterBundleUnpack(const std::string& name, const base::FilePath& dest) const {
  // get the executable bundle directory
  // NOTE: we need a Bundle index with each bundle and
  //       we need to fix this path in there so we can reuse it
  //       for now is this
  
  // now we need to set the correct executable flips
  // at least on posix
#if defined(OS_POSIX)
  base::FilePath service_out_file = dest.Append(storage::GetPathForArchitecture(name + "_service", storage::GetHostArchitecture(), storage_proto::LIBRARY));
  base::FilePath app_out_file = dest.Append(storage::GetPathForArchitecture(name + "_app", storage::GetHostArchitecture(), storage_proto::PROGRAM));
  int current_perm = 0;
  if (!base::GetPosixFilePermissions(service_out_file, &current_perm)) {
    printf("error while getting file permission for %s\n", service_out_file.value().c_str());
    return false;
  }
  current_perm = current_perm | 
    base::FILE_PERMISSION_EXECUTE_BY_USER |
    base::FILE_PERMISSION_EXECUTE_BY_GROUP |
    base::FILE_PERMISSION_EXECUTE_BY_OTHERS;
  if (!base::SetPosixFilePermissions(service_out_file, current_perm)) {
    printf("error while setting file permission for %s\n", service_out_file.value().c_str());
    return false;
  }

  if (!base::GetPosixFilePermissions(app_out_file, &current_perm)) {
    printf("error while getting file permission for %s\n", app_out_file.value().c_str());
    return false;
  }
  
  current_perm = current_perm | 
    base::FILE_PERMISSION_EXECUTE_BY_USER |
    base::FILE_PERMISSION_EXECUTE_BY_GROUP |
    base::FILE_PERMISSION_EXECUTE_BY_OTHERS;
  
  if (!base::SetPosixFilePermissions(app_out_file, current_perm)) {
    printf("error while setting file permission for %s\n", app_out_file.value().c_str());
    return false;
  }
#endif
  return true;
}

base::FilePath BundleManager::GetOutputPath() const {
  base::FilePath out_path = workspace_->tmp_dir();
  return out_path.AppendASCII("app" + base::IntToString(base::RandInt(0, std::numeric_limits<int16_t>::max())));
}

void BundleManager::SignBundleImpl(const base::FilePath& src, const std::vector<uint8_t>& signature, base::OnceCallback<void(int)> callback) {
  // TODO: not really working yet
  bool result = false;//BundleUtils::SignBundle(src, signature);
  std::move(callback).Run(result ? net::OK : net::ERR_FAILED);
}

void BundleManager::PackBundleImpl(const std::string& name, const base::FilePath& src, bool no_frontend, base::OnceCallback<void(int)> callback) {
  base::FilePath home_path;
  base::FilePath binary_out_path;

  if (!base::PathService::Get(base::DIR_HOME, &home_path)) {
    DLOG(ERROR) << "error while getting home path";
    std::move(callback).Run(net::ERR_FAILED);
    return;
  }
  
  if (!base::PathService::Get(base::DIR_EXE, &binary_out_path)) {
    DLOG(ERROR) << "error while getting executable path";
    std::move(callback).Run(net::ERR_FAILED);
    return;
  }

  base::FilePath temp_dir = home_path.AppendASCII("tmp" + base::IntToString(base::RandInt(0, std::numeric_limits<int16_t>::max()))); 
  
  if (!PackCreateBaseDirectories(name, temp_dir, no_frontend)) {
    std::move(callback).Run(net::ERR_FAILED);
    return;
  }

  if (!PackCopyFiles(name, src, binary_out_path, temp_dir, no_frontend)) {
    std::move(callback).Run(net::ERR_FAILED);
    return;
  }

  base::FilePath mumba_out_dir = home_path.AppendASCII("mumba_out");

  if (!base::PathExists(mumba_out_dir)) {
    base::CreateDirectory(mumba_out_dir);
  }

  if (!PackDirectory(name, temp_dir, mumba_out_dir, no_frontend)) {
    DLOG(ERROR) << "error while creating drop file";
    std::move(callback).Run(net::ERR_FAILED);
    return;
  }

  base::DeleteFile(temp_dir, true);
  std::move(callback).Run(net::OK);
}

bool BundleManager::PackCreateBaseDirectories(const std::string& identifier, const base::FilePath& base_dir, bool no_frontend) {
  base::FilePath bin_path = base_dir.AppendASCII("bin");
  base::FilePath applications_path = base_dir.AppendASCII("apps");
  base::FilePath application_path = applications_path.AppendASCII("app");
  base::FilePath service_path = applications_path.AppendASCII("service");
  base::FilePath resources_path = base_dir.AppendASCII("resources");
  base::FilePath proto_path = resources_path.AppendASCII("proto");
  base::FilePath databases_path = resources_path.AppendASCII("databases");
  base::FilePath shares_path = resources_path.AppendASCII("shares");
  base::FilePath files_path = resources_path.AppendASCII("files");

  if (!base::CreateDirectory(base_dir)) {
    printf("error while creating temporary directory\n");
    return false;
  }

  if (!no_frontend) {
    if (!base::CreateDirectory(bin_path)) {
      printf("error while creating temporary directory 'bin'\n");
      return false;
    }
  }
  if (!base::CreateDirectory(applications_path)) {
    printf("error while creating temporary directory 'apps'\n");
    return false;
  }
  if (!base::CreateDirectory(application_path)) {
    printf("error while creating temporary directory 'apps/app'\n");
    return false;
  }
  if (!base::CreateDirectory(service_path)) {
    printf("error while creating temporary directory 'apps/service'\n");
    return false;
  }
  if (!base::CreateDirectory(resources_path)) {
    printf("error while creating temporary directory 'resources'\n");
    return false;
  }
  if (!base::CreateDirectory(proto_path)) {
    printf("error while creating temporary directory 'resources/proto'\n");
    return false;
  }
  if (!base::CreateDirectory(databases_path)) {
    printf("error while creating temporary directory 'resources/databases'\n");
    return false;
  }
  if (!base::CreateDirectory(shares_path)) {
    printf("error while creating temporary directory 'resources/shares'\n");
    return false;
  }
  if (!base::CreateDirectory(files_path)) {
    printf("error while creating temporary directory 'resources/files'\n");
    return false;
  }
  
  std::string target_arch = storage::GetIdentifierForHostOS();

  if (!base::CreateDirectory(bin_path.AppendASCII(target_arch))) {
    printf("error while creating temporary directory 'bin/%s'\n", target_arch.c_str());
    return false;
  }

  if (!base::CreateDirectory(application_path.AppendASCII(target_arch))) {
    printf("error while creating temporary directory 'apps/app/%s'\n", target_arch.c_str());
    return false;
  }

  if (!base::CreateDirectory(service_path.AppendASCII(target_arch))) {
    printf("error while creating temporary directory 'apps/service/%s'\n", target_arch.c_str());
    return false;
  }

  return true;
}

bool BundleManager::PackCopyFiles(const std::string& identifier, const base::FilePath& app_base_path, const base::FilePath& input_dir, const base::FilePath& base_dir, bool no_frontend) {
  base::FilePath bin_out_dir = base_dir.AppendASCII("bin");
  base::FilePath app_out_dir = base_dir.AppendASCII("apps").AppendASCII("app");
  base::FilePath service_out_dir = base_dir.AppendASCII("apps").AppendASCII("service");
  base::FilePath resources_out_dir = base_dir.AppendASCII("resources");
  base::FilePath schema_out_dir = resources_out_dir.AppendASCII("proto");
  
  base::FilePath bin_out_file = bin_out_dir.AppendASCII(storage::GetIdentifierForHostOS()).AppendASCII(identifier);

  base::FilePath service_out_file = service_out_dir.Append(storage::GetPathForArchitecture(identifier + "_service", storage::GetHostArchitecture(), storage_proto::LIBRARY));
  base::FilePath app_out_file = app_out_dir.Append(storage::GetPathForArchitecture(identifier + "_app", storage::GetHostArchitecture(), storage_proto::PROGRAM));
  base::FilePath schema_out_file = schema_out_dir.AppendASCII(identifier + ".proto");

  base::FilePath bin_in_file = input_dir.AppendASCII(identifier);
  base::FilePath service_in_file = input_dir.Append(storage::GetFilePathForArchitecture(identifier + "_service", storage::GetHostArchitecture(), storage_proto::LIBRARY));
  base::FilePath app_in_file = input_dir.Append(storage::GetFilePathForArchitecture(identifier + "_app", storage::GetHostArchitecture(), storage_proto::PROGRAM));
  
  std::string camel_case_identifier = std::string(base::ToUpperASCII(identifier[0]) + identifier.substr(1));
  
  base::FilePath schema_in_file = app_base_path.AppendASCII(identifier).
                                                AppendASCII("resources").
                                                AppendASCII("proto").
                                                AppendASCII("Sources").
                                                AppendASCII("Api").
                                                AppendASCII(camel_case_identifier + ".proto");

  base::FilePath app_manifest_in_file = app_base_path.AppendASCII(identifier).AppendASCII("app").AppendASCII("AppxManifest.xml");
  base::FilePath service_manifest_in_file = app_base_path.AppendASCII(identifier).AppendASCII("service").AppendASCII("AppxManifest.xml");
  base::FilePath resources_manifest_in_file = app_base_path.AppendASCII(identifier).AppendASCII("resources").AppendASCII("AppxManifest.xml");
  
  base::FilePath bin_manifest_out_file = bin_out_dir.AppendASCII("AppxManifest.xml");
  base::FilePath app_manifest_out_file = app_out_dir.AppendASCII("AppxManifest.xml");
  base::FilePath service_manifest_out_file = service_out_dir.AppendASCII("AppxManifest.xml");
  base::FilePath resources_manifest_out_file = resources_out_dir.AppendASCII("AppxManifest.xml");

  if (!no_frontend) {
    if (!base::CopyFile(bin_in_file, bin_out_file)) {
      printf("error while copying bin file\n");
      return false;
    }
  }

  if (!base::CopyFile(service_in_file, service_out_file)) {
    printf("error while copying service files\n");
    return false;
  }

  if (!base::CopyFile(app_in_file, app_out_file)) {
    printf("error while copying app files\n");
    return false;
  }

  for (size_t i = 0; i < libraries.size(); ++i) {
    base::FilePath in_lib_file = input_dir.AppendASCII(libraries[i]);
    base::FilePath out_lib_file = app_out_dir.AppendASCII(storage::GetIdentifierForHostOS()).AppendASCII(libraries[i]);
    if (!base::CopyFile(in_lib_file, out_lib_file)) {
      printf("error while copying app files\n");
      return false;
    }
  }

  if (!base::CopyFile(schema_in_file, schema_out_file)) {
    printf("error while copying schema files\n");
    return false;
  }

  base::FilePath resource_files = app_base_path.AppendASCII(identifier).AppendASCII("resources").AppendASCII("files"); 
  base::FilePath resource_files_out = resources_out_dir;
  
  if (!base::CopyDirectory(
        resource_files,
        resource_files_out,
        true)) {
    printf("error while copying resources/files\n");
    return false;
  }

  base::FilePath resource_databases = app_base_path.AppendASCII(identifier).AppendASCII("resources").AppendASCII("databases");
  base::FilePath resource_databases_out = resources_out_dir;
  
  if (!base::CopyDirectory(
        resource_databases,
        resource_databases_out,
        true)) {
    printf("error while copying resources/files\n");
    return false;
  }

  base::FilePath resource_shares = app_base_path.AppendASCII(identifier).AppendASCII("resources").AppendASCII("shares");
  base::FilePath resource_shares_out = resources_out_dir;
  
  if (!base::CopyDirectory(
        resource_shares,
        resource_shares_out,
        true)) {
    printf("error while copying resources/shares\n");
    return false;
  }

  if (!no_frontend) {
    std::string bin_manifest_data(kDEFAULT_BIN_MANIFEST);
    size_t offset = bin_manifest_data.find("__NAME__");
    while (offset != std::string::npos) {
      bin_manifest_data = bin_manifest_data.replace(offset, 8, identifier);
      offset = bin_manifest_data.find("__NAME__");
    }

    int wrote_len = base::WriteFile(bin_manifest_out_file, bin_manifest_data.data(), bin_manifest_data.size());
    if (wrote_len != static_cast<int>(bin_manifest_data.size())) {
      printf("error while creating bin manifest file\n");
      return false;
    }
  }

  if (!base::CopyFile(app_manifest_in_file, app_manifest_out_file)) {
    printf("error while copying manifest file\n");
    return false;
  }

  if (!base::CopyFile(service_manifest_in_file, service_manifest_out_file)) {
    printf("error while copying manifest file\n");
    return false;
  }

  if (!base::CopyFile(resources_manifest_in_file, resources_manifest_out_file)) {
    printf("error while copying manifest file\n");
    return false;
  }

#if defined(OS_POSIX)
  int current_perm = 0;
  if (!base::GetPosixFilePermissions(service_out_file, &current_perm)) {
    printf("error while getting file permission for %s\n", service_out_file.value().c_str());
    return false;
  }
  current_perm = current_perm | 
    base::FILE_PERMISSION_EXECUTE_BY_USER |
    base::FILE_PERMISSION_EXECUTE_BY_GROUP |
    base::FILE_PERMISSION_EXECUTE_BY_OTHERS;
  if (!base::SetPosixFilePermissions(service_out_file, current_perm)) {
    printf("error while setting file permission for %s\n", service_out_file.value().c_str());
    return false;
  }

  if (!base::GetPosixFilePermissions(app_out_file, &current_perm)) {
    printf("error while getting file permission for %s\n", app_out_file.value().c_str());
    return false;
  }
  
  current_perm = current_perm | 
    base::FILE_PERMISSION_EXECUTE_BY_USER |
    base::FILE_PERMISSION_EXECUTE_BY_GROUP |
    base::FILE_PERMISSION_EXECUTE_BY_OTHERS;
  
  if (!base::SetPosixFilePermissions(app_out_file, current_perm)) {
    printf("error while setting file permission for %s\n", app_out_file.value().c_str());
    return false;
  }

#endif

  return true;
}

bool BundleManager::PackDirectory(const std::string& identifier, const base::FilePath& src_path, const base::FilePath& output_dir, bool no_frontend) {
  base::FilePath bundle_out_dir = output_dir.AppendASCII(identifier);
  
  if (base::PathExists(bundle_out_dir)) {
    base::DeleteFile(bundle_out_dir, true);
  }

  if (!base::CreateDirectory(bundle_out_dir)) {
    printf("error: failed while creating directory %s\n", bundle_out_dir.value().c_str());
    return false;
  }

  //std::string host_arch = storage::GetIdentifierForArchitecture(storage::GetHostArchitecture());
  std::string host_os = storage::GetIdentifierForHostOS();

  base::FilePath bin_in_dir = src_path.AppendASCII("bin");
  base::FilePath bin_out_file = bundle_out_dir.AppendASCII(identifier + "_bin-" + host_os + ".appx");
  if (base::PathExists(bin_out_file)) {
    base::DeleteFile(bin_out_file, false);
  }

  base::FilePath app_in_dir = src_path.AppendASCII("apps").AppendASCII("app");
  base::FilePath app_out_file = bundle_out_dir.AppendASCII(identifier + "_app-" + host_os + ".appx");
  if (base::PathExists(app_out_file)) {
    base::DeleteFile(app_out_file, false);
  }

  base::FilePath service_in_dir = src_path.AppendASCII("apps").AppendASCII("service");
  base::FilePath service_out_file = bundle_out_dir.AppendASCII(identifier + "_service-" + host_os + ".appx");
  if (base::PathExists(service_out_file)) {
    base::DeleteFile(service_out_file, false);
  }

  base::FilePath resource_in_dir = src_path.AppendASCII("resources");
  base::FilePath resource_out_file = bundle_out_dir.AppendASCII(identifier + "_resources.appx");
  if (base::PathExists(resource_out_file)) {
    base::DeleteFile(resource_out_file, false);
  }

  base::FilePath bundle_out_file = output_dir.AppendASCII(identifier + ".bundle");
  if (base::PathExists(bundle_out_file)) {
    base::DeleteFile(bundle_out_file, false);
  }

  // special case for the 'world' bundle
  if (!no_frontend) {
    // bin
    if (::PackPackage(
          MSIX_PACKUNPACK_OPTION::MSIX_PACKUNPACK_OPTION_NONE,
          MSIX_VALIDATION_OPTION::MSIX_VALIDATION_OPTION_FULL,
          const_cast<char*>(bin_in_dir.value().c_str()),
          const_cast<char*>(bin_out_file.value().c_str())) != 0) {
      printf("error: failed while creating %s package\n", bin_out_file.value().c_str());
      return false; 
    }
  }

  // app
  if (::PackPackage(
        MSIX_PACKUNPACK_OPTION::MSIX_PACKUNPACK_OPTION_NONE,
        MSIX_VALIDATION_OPTION::MSIX_VALIDATION_OPTION_FULL,
        const_cast<char*>(app_in_dir.value().c_str()),
        const_cast<char*>(app_out_file.value().c_str())) != 0) {
    printf("error: failed while creating %s package\n", app_out_file.value().c_str());
    return false; 
  }

  // service
  if (::PackPackage(
        MSIX_PACKUNPACK_OPTION::MSIX_PACKUNPACK_OPTION_NONE,
        MSIX_VALIDATION_OPTION::MSIX_VALIDATION_OPTION_FULL,
        const_cast<char*>(service_in_dir.value().c_str()),
        const_cast<char*>(service_out_file.value().c_str())) != 0) {
    printf("error: failed while creating %s package\n", service_out_file.value().c_str());
    return false; 
  }

  // resource
  if (::PackPackage(
        MSIX_PACKUNPACK_OPTION::MSIX_PACKUNPACK_OPTION_NONE,
        MSIX_VALIDATION_OPTION::MSIX_VALIDATION_OPTION_FULL,
        const_cast<char*>(resource_in_dir.value().c_str()),
        const_cast<char*>(resource_out_file.value().c_str())) != 0) {
    printf("error: failed while creating %s package\n", resource_out_file.value().c_str());
    return false; 
  }

  // bundle
  MSIX_BUNDLE_OPTIONS options = (MSIX_BUNDLE_OPTIONS)(MSIX_BUNDLE_OPTIONS::MSIX_OPTION_VERBOSE | MSIX_BUNDLE_OPTIONS::MSIX_OPTION_OVERWRITE | MSIX_BUNDLE_OPTIONS::MSIX_BUNDLE_OPTION_FLATBUNDLE);
  if (::PackBundle(
      options,    
      const_cast<char*>(bundle_out_dir.value().c_str()),
      const_cast<char*>(bundle_out_file.value().c_str()),
      nullptr,
      nullptr) != 0) {
    printf("error: failed while creating bundle\n");
    return false; 
  }

  base::FilePath move_bundle_to = bundle_out_dir.AppendASCII(identifier + ".bundle");
  if (!base::Move(bundle_out_file, move_bundle_to)) {
    printf("error: failed while moving bundle file\n");
    return false;
  }

   // special case for the 'world' bundle
  if (identifier == "world") {
    base::FilePath asset_path;
    base::PathService::Get(base::DIR_ASSETS, &asset_path);
    base::CopyFile(move_bundle_to, asset_path.Append(move_bundle_to.BaseName()));
    base::CopyFile(app_out_file, asset_path.Append(app_out_file.BaseName()));
    base::CopyFile(service_out_file, asset_path.Append(service_out_file.BaseName()));
    base::CopyFile(resource_out_file, asset_path.Append(resource_out_file.BaseName()));
  }

  return true; 
}

void BundleManager::InitBundleImpl(const std::string& name, const base::FilePath& src, base::OnceCallback<void(int)> callback) {
  std::move(callback).Run(net::ERR_FAILED);
}

void BundleManager::NotifyBundleAdded(Bundle* bundle) {
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    BundleManagerObserver* observer = *it;
    observer->OnBundleAdded(bundle);
  }
}

void BundleManager::NotifyBundleRemoved(Bundle* bundle) {
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    BundleManagerObserver* observer = *it;
    observer->OnBundleRemoved(bundle);
  }
}

void BundleManager::NotifyBundlesLoad(int r, int count) {
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    BundleManagerObserver* observer = *it;
    observer->OnBundlesLoad(r, count);
  }
}

}