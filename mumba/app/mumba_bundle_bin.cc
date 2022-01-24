// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stdio.h>
#include <string>

#include "base/base_paths.h"
#include "base/path_service.h"
#include "base/command_line.h"
#include "base/at_exit.h"
#include "base/files/file_util.h"
#include "base/rand_util.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "storage/storage_utils.h"
#include "third_party/msix/src/inc/public/AppxPackaging.hpp"

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

bool CreateBaseDirectories(const std::string& identifier, const base::FilePath& base_dir, bool no_frontend) {
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

bool CopyFiles(const std::string& identifier, const base::FilePath& app_base_path, const base::FilePath& input_dir, const base::FilePath& base_dir, bool no_frontend) {
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

bool PackDirectory(const std::string& identifier, const base::FilePath& src_path, const base::FilePath& output_dir, bool no_frontend) {
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
    if (PackPackage(
          MSIX_PACKUNPACK_OPTION::MSIX_PACKUNPACK_OPTION_NONE,
          MSIX_VALIDATION_OPTION::MSIX_VALIDATION_OPTION_FULL,
          const_cast<char*>(bin_in_dir.value().c_str()),
          const_cast<char*>(bin_out_file.value().c_str())) != 0) {
      printf("error: failed while creating %s package\n", bin_out_file.value().c_str());
      return false; 
    }
  }

  // app
  if (PackPackage(
        MSIX_PACKUNPACK_OPTION::MSIX_PACKUNPACK_OPTION_NONE,
        MSIX_VALIDATION_OPTION::MSIX_VALIDATION_OPTION_FULL,
        const_cast<char*>(app_in_dir.value().c_str()),
        const_cast<char*>(app_out_file.value().c_str())) != 0) {
    printf("error: failed while creating %s package\n", app_out_file.value().c_str());
    return false; 
  }

  // service
  if (PackPackage(
        MSIX_PACKUNPACK_OPTION::MSIX_PACKUNPACK_OPTION_NONE,
        MSIX_VALIDATION_OPTION::MSIX_VALIDATION_OPTION_FULL,
        const_cast<char*>(service_in_dir.value().c_str()),
        const_cast<char*>(service_out_file.value().c_str())) != 0) {
    printf("error: failed while creating %s package\n", service_out_file.value().c_str());
    return false; 
  }

  // resource
  if (PackPackage(
        MSIX_PACKUNPACK_OPTION::MSIX_PACKUNPACK_OPTION_NONE,
        MSIX_VALIDATION_OPTION::MSIX_VALIDATION_OPTION_FULL,
        const_cast<char*>(resource_in_dir.value().c_str()),
        const_cast<char*>(resource_out_file.value().c_str())) != 0) {
    printf("error: failed while creating %s package\n", resource_out_file.value().c_str());
    return false; 
  }

  // bundle
  MSIX_BUNDLE_OPTIONS options = (MSIX_BUNDLE_OPTIONS)(MSIX_BUNDLE_OPTIONS::MSIX_OPTION_VERBOSE | MSIX_BUNDLE_OPTIONS::MSIX_OPTION_OVERWRITE | MSIX_BUNDLE_OPTIONS::MSIX_BUNDLE_OPTION_FLATBUNDLE);
  if (PackBundle(
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

int main(int argc, char** argv) {
  base::AtExitManager at_exit;
  base::FilePath home_path;
  
  if (!base::CommandLine::Init(argc, argv)) {
    printf("error: failed creating command line\n");
    return 1;  
  }

 if (argc < 3) {
  printf("error: not enough arguments. missing identifier and/or app base path\n");
  return 1;
 }

 base::CommandLine* cmd = base::CommandLine::ForCurrentProcess();

 std::string identifier(argv[1]);
 base::FilePath app_base_path(argv[2]);
 bool no_frontend = cmd->HasSwitch("no-frontend");

 if (!base::PathService::Get(base::DIR_HOME, &home_path)) {
    printf("error while getting home path\n");
    return 1;
 }
 base::FilePath binary_out_path;
 if (!base::PathService::Get(base::DIR_EXE, &binary_out_path)) {
    printf("error while getting executable path\n");
    return 1;
 }
 base::FilePath temp_dir = home_path.AppendASCII("tmp" + base::IntToString(base::RandInt(0, std::numeric_limits<int16_t>::max()))); 
 if (!CreateBaseDirectories(identifier, temp_dir, no_frontend)) {
   return 1;
 }
 if (!CopyFiles(identifier, app_base_path, binary_out_path, temp_dir, no_frontend)) {
   return 1;
 }

 base::FilePath mumba_out_dir = home_path.AppendASCII("mumba_out");

 if (!base::PathExists(mumba_out_dir)) {
  base::CreateDirectory(mumba_out_dir);
 }

 if (!PackDirectory(identifier, temp_dir, mumba_out_dir, no_frontend)) {
   printf("error while creating drop file\n");
   return 1;
 }

  base::DeleteFile(temp_dir, true);
  return 0;
}