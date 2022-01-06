// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/domain/storage/namespace_builder.h"

#include "base/files/file_util.h"
#include "core/shared/domain/storage/namespace.h"
//#include "core/shared/domain/storage/sqlite/btree_database_creator.h"
#include "core/shared/domain/storage/cache/cache_filesystem_creator.h"
#include "core/domain/id_generator.h"

namespace domain {

NamespaceBuilder::NamespaceBuilder(const base::FilePath& root_path):
 root_path_(root_path) {

}  

NamespaceBuilder::~NamespaceBuilder() {

}

bool NamespaceBuilder::Init() {
  
  id_ = base::UUID::generate();//GenerateRandomUniqueID();

  if (!base::DirectoryExists(root_path_)) {
    if (!base::CreateDirectory(root_path_)) {
      return false;
    }
  }

  base::FilePath namespace_path = root_path_.AppendASCII(id_.to_string());
 
  if (!base::DirectoryExists(namespace_path)) {
    if (!base::CreateDirectory(namespace_path)) {
      return false;
    }
  }

  base::FilePath fs_path = namespace_path.AppendASCII("fs");
 
  if (!base::DirectoryExists(fs_path)) {
    if (!base::CreateDirectory(fs_path)) {
      return false;
    }
  }

  return true;
}

bool NamespaceBuilder::CreateDatabase(bool in_memory) {
  //BtreeDatabaseCreator creator;
  //BtreeDatabaseCreator::Options options;
  //base::FilePath db_path = Namespace::GetDatabasePath(root_path_, id_);
  //return creator.Create(db_path, options);
  return true;
}

bool NamespaceBuilder::CreateFilesystem(bool in_memory) {
  //CacheFilesystemImageCreator creator;
  //CacheFilesystemImageCreator::Options options;
  //base::FilePath image_path = Namespace::GetFilesystemPath(root_path_, id_);
  return true;//creator.Create(image_path, options);
}

std::unique_ptr<Namespace> NamespaceBuilder::Build(NamespaceManager* manager, bool in_memory) {
  std::unique_ptr<Namespace> builded(new Namespace(manager, id_, in_memory));
  return builded;
}

}