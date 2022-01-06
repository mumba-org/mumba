// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stdio.h>
#include <string>

#include "base/base_paths.h"
#include "base/path_service.h"
#include "base/files/file_util.h"
#include "base/rand_util.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "storage/storage_utils.h"
#include "third_party/msix/src/inc/public/AppxPackaging.hpp"

bool CreateBaseDirectories(const base::FilePath& base_dir) {
  base::FilePath applications_path = base_dir.AppendASCII("apps");
  base::FilePath application_path = applications_path.AppendASCII("app");
  base::FilePath service_path = applications_path.AppendASCII("service");
  base::FilePath resources_path = base_dir.AppendASCII("resources");
  base::FilePath proto_path = resources_path.AppendASCII("proto");
  base::FilePath databases_path = resources_path.AppendASCII("databases");
  base::FilePath files_path = resources_path.AppendASCII("files");

  if (!base::CreateDirectory(base_dir)) {
    printf("error while creating temporary directory\n");
    return false;
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
  if (!base::CreateDirectory(files_path)) {
    printf("error while creating temporary directory 'resources/files'\n");
    return false;
  }
  
  std::string target_arch = storage::GetIdentifierForHostOS();
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

bool CopyFiles(const std::string& identifier, const base::FilePath& app_base_path, const base::FilePath& input_dir, const base::FilePath& base_dir) {
  //std::string target_arch = storage::GetIdentifierForHostOS();
  base::FilePath app_out_dir = base_dir.AppendASCII("apps").AppendASCII("app");
  base::FilePath service_out_dir = base_dir.AppendASCII("apps").AppendASCII("service");
  base::FilePath resources_out_dir = base_dir.AppendASCII("resources");
  base::FilePath schema_out_dir = resources_out_dir.AppendASCII("proto");
  
  base::FilePath service_out_file = service_out_dir.Append(storage::GetPathForArchitecture(identifier + "_service", storage::GetHostArchitecture(), storage_proto::LIBRARY));
  base::FilePath app_out_file = app_out_dir.Append(storage::GetPathForArchitecture(identifier + "_app", storage::GetHostArchitecture(), storage_proto::PROGRAM));
  base::FilePath schema_out_file = schema_out_dir.AppendASCII(identifier + ".proto");

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
  
  base::FilePath app_manifest_out_file = app_out_dir.AppendASCII("AppxManifest.xml");
  base::FilePath service_manifest_out_file = service_out_dir.AppendASCII("AppxManifest.xml");
  base::FilePath resources_manifest_out_file = resources_out_dir.AppendASCII("AppxManifest.xml");

  printf("copying service: %s to %s ...\n", service_in_file.value().c_str(), service_out_file.value().c_str());
  if (!base::CopyFile(service_in_file, service_out_file)) {
    printf("error while copying service files\n");
    return false;
  }

  printf("copying app: %s to %s ...\n", app_in_file.value().c_str(), app_out_file.value().c_str());
  if (!base::CopyFile(app_in_file, app_out_file)) {
    printf("error while copying app files\n");
    return false;
  }

  printf("copying schema:  %s to %s ...\n", schema_in_file.value().c_str(), schema_out_file.value().c_str());
  if (!base::CopyFile(schema_in_file, schema_out_file)) {
    printf("error while copying schema files\n");
    return false;
  }

  base::FilePath resource_files = app_base_path.AppendASCII(identifier).AppendASCII("resources").AppendASCII("files"); 
  base::FilePath resource_files_out = resources_out_dir;
  printf("copying resources/files: %s to %s ..\n", resource_files.value().c_str(), resource_files_out.value().c_str());
  if (!base::CopyDirectory(
        resource_files,
        resource_files_out,
        true)) {
    printf("error while copying resources/files\n");
    return false;
  }

  base::FilePath resource_databases = app_base_path.AppendASCII(identifier).AppendASCII("resources").AppendASCII("databases");
  base::FilePath resource_databases_out = resources_out_dir;
  printf("copying resources/databases: %s to %s ..\n", resource_databases.value().c_str(), resource_databases_out.value().c_str());
  if (!base::CopyDirectory(
        resource_databases,
        resource_databases_out,
        true)) {
    printf("error while copying resources/files\n");
    return false;
  }

  printf("copying app manifest:  %s to %s ...\n", app_manifest_in_file.value().c_str(), app_manifest_out_file.value().c_str());
  if (!base::CopyFile(app_manifest_in_file, app_manifest_out_file)) {
    printf("error while copying manifest file\n");
    return false;
  }

  printf("copying service manifest:  %s to %s ...\n", service_manifest_in_file.value().c_str(), service_manifest_out_file.value().c_str());
  if (!base::CopyFile(service_manifest_in_file, service_manifest_out_file)) {
    printf("error while copying manifest file\n");
    return false;
  }

  printf("copying resources manifest:  %s to %s ...\n", resources_manifest_in_file.value().c_str(), resources_manifest_out_file.value().c_str());
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

bool PackDirectory(const std::string& identifier, const base::FilePath& src_path, const base::FilePath& output_dir) {
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

  printf("packing app: %s to %s ...\n", app_in_dir.value().c_str(), app_out_file.value().c_str());

  if (PackPackage(
        MSIX_PACKUNPACK_OPTION::MSIX_PACKUNPACK_OPTION_NONE,
        MSIX_VALIDATION_OPTION::MSIX_VALIDATION_OPTION_FULL,
        const_cast<char*>(app_in_dir.value().c_str()),
        const_cast<char*>(app_out_file.value().c_str())) != 0) {
    printf("error: failed while creating app package\n");
    return false; 
  }

  printf("packing service: %s to %s ...\n", service_in_dir.value().c_str(), service_out_file.value().c_str());
  if (PackPackage(
        MSIX_PACKUNPACK_OPTION::MSIX_PACKUNPACK_OPTION_NONE,
        MSIX_VALIDATION_OPTION::MSIX_VALIDATION_OPTION_FULL,
        const_cast<char*>(service_in_dir.value().c_str()),
        const_cast<char*>(service_out_file.value().c_str())) != 0) {
    printf("error: failed while creating service package\n");
    return false; 
  }

  printf("packing resources: %s to %s ...\n", resource_in_dir.value().c_str(), resource_out_file.value().c_str());
  if (PackPackage(
        MSIX_PACKUNPACK_OPTION::MSIX_PACKUNPACK_OPTION_NONE,
        MSIX_VALIDATION_OPTION::MSIX_VALIDATION_OPTION_FULL,
        const_cast<char*>(resource_in_dir.value().c_str()),
        const_cast<char*>(resource_out_file.value().c_str())) != 0) {
    printf("error: failed while creating resource package\n");
    return false; 
  }

  MSIX_BUNDLE_OPTIONS options = (MSIX_BUNDLE_OPTIONS)(MSIX_BUNDLE_OPTIONS::MSIX_OPTION_VERBOSE | MSIX_BUNDLE_OPTIONS::MSIX_OPTION_OVERWRITE | MSIX_BUNDLE_OPTIONS::MSIX_BUNDLE_OPTION_FLATBUNDLE);
  printf("packing bundle: %s to %s ...\n", bundle_out_dir.value().c_str(), bundle_out_file.value().c_str());
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
  printf("moving bundle: %s to %s ...\n", bundle_out_file.value().c_str(), move_bundle_to.value().c_str());
  if (!base::Move(bundle_out_file, move_bundle_to)) {
    printf("error: failed while moving bundle file\n");
    return false;
  }

   // special case for the 'world' bundle
  if (identifier == "world") {
    base::FilePath asset_path;
    base::PathService::Get(base::DIR_ASSETS, &asset_path);
    printf("world. copying %s to %s\n", move_bundle_to.value().c_str(), asset_path.value().c_str());
    base::CopyFile(move_bundle_to, asset_path.Append(move_bundle_to.BaseName()));
    printf("world. copying %s to %s\n", app_out_file.value().c_str(), asset_path.value().c_str());
    base::CopyFile(app_out_file, asset_path.Append(app_out_file.BaseName()));
    printf("world. copying %s to %s\n", service_out_file.value().c_str(), asset_path.value().c_str());
    base::CopyFile(service_out_file, asset_path.Append(service_out_file.BaseName()));
    printf("world. copying %s to %s\n", resource_out_file.value().c_str(), asset_path.value().c_str());
    base::CopyFile(resource_out_file, asset_path.Append(resource_out_file.BaseName()));
  }

  return true; 
}

int main(int argc, char** argv) {
 base::FilePath home_path;

 if (argc < 3) {
  printf("error: not enough arguments. missing identifier and/or app base path\n");
  return 1;
 }

 std::string identifier(argv[1]);
 base::FilePath app_base_path(argv[2]);

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
 if (!CreateBaseDirectories(temp_dir)) {
   return 1;
 }
 if (!CopyFiles(identifier, app_base_path, binary_out_path, temp_dir)) {
   return 1;
 }

 base::FilePath mumba_out_dir = home_path.AppendASCII("mumba_out");

 if (!base::PathExists(mumba_out_dir)) {
  base::CreateDirectory(mumba_out_dir);
 }

 if (!PackDirectory(identifier, temp_dir, mumba_out_dir)) {
   printf("error while creating drop file\n");
   return 1;
 }

 
  base::DeleteFile(temp_dir, true);

  printf("done.\n");
 
  return 0;
}