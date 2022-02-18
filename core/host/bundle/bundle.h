// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_BUNDLE_BUNDLE_H_
#define MUMBA_HOST_BUNDLE_BUNDLE_H_

#include <memory>

#include "base/macros.h"
#include "base/uuid.h"
#include "base/strings/string_piece.h"
#include "base/synchronization/lock.h"
#include "core/host/serializable.h"
#include "core/common/proto/objects.pb.h"
#include "core/host/bundle/bundle_info.h"
#include "core/host/bundle/bundle_package.h"
#include "core/shared/common/mojom/bundle.mojom.h"
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wsign-compare"
#pragma clang diagnostic ignored "-Wignored-qualifiers"
#include "third_party/zetasql/parser/parse_tree.h"
#include "third_party/zetasql/parser/ast_node_kind.h"
#include "third_party/zetasql/parser/parser.h"
#include "third_party/zetasql/public/parse_resume_location.h"
#include "third_party/zetasql/base/status.h"
#pragma clang diagnostic pop

namespace host {
class Workspace;
class Share;
/*
 *
 * Get the whole bundle manifest info from msix
 * and populate this with information
 *
 * For instance: how many package this bundle have
 * and how they look like? what their own manifest?
 *
 * we need a BundlePackage type where a bundle will
 * have one or more of them
 *
 * we need them ALL serialized in the database after they are installed
 */

class Bundle : public Serializable {
public:
  static char kClassName[];
  static std::unique_ptr<Bundle> Deserialize(net::IOBuffer* buffer, int size);

  // FIXME: We need to have BundlePackage objects, each one with their own directory
  //        and add them to the bundle.  
  Bundle(const std::string& name, const std::string& path, const std::string& executable_path, const std::string& resources_path);
  Bundle();
  Bundle(protocol::Bundle bundle_proto);
  ~Bundle() override;

  const base::UUID& id() const {
    return id_;
  }

  const std::string& name() const;
  void set_name(const std::string& name);

  const std::string& path() const;
  void set_path(const std::string& path);

  const std::string& src_path() const;
  void set_src_path(const std::string& path);

  const std::string& application_path();
  const std::string& resources_path();

  bool is_managed() const {
    return managed_;
  }

  void set_managed(bool managed) {
    managed_ = managed;
  }

  const std::vector<std::unique_ptr<BundlePackage>>& packages() const {
    return packages_;
  }

  void AddPackage(std::unique_ptr<BundlePackage> package);

  scoped_refptr<net::IOBufferWithSize> Serialize() const override;

  // FIXME: maybe to be on a BundleController instead of Bundle
  void PostUnpackActions(scoped_refptr<Workspace> workspace, const base::FilePath& path);

private:
  
  struct DatabaseCreationInfo {
    int type; // 0 = KEY-VALUE, 1 = SQL
    std::string database_name;
    // keyspaces or table names
    // lifetime: as long as parser_output_ is live these statements will be ok
    //std::vector<const zetasql::ASTCreateTableStatement*> create_table_stmts;
    std::vector<std::string> create_table_stmts;
  };

  void ResolvePackages();
  void ResolveResourcePackage();
  void ResolveApplicationPackage();

  void InstallSchemaAfterBundleUnpack(scoped_refptr<Workspace> workspace, const base::FilePath& path);
  void InstallLibrariesAfterBundleUnpack(scoped_refptr<Workspace> workspace, const base::FilePath& path);
  void InjectCoreMethods(std::string* proto) const;

  void CreateFileset(scoped_refptr<Workspace> workspace, const base::FilePath& files_dir);
  void CreateDatabases(scoped_refptr<Workspace> workspace, const base::FilePath& db_file);
  void CreateDatabase(scoped_refptr<Workspace> workspace, DatabaseCreationInfo* creation);
  void CreateShare(scoped_refptr<Workspace> workspace, const base::FilePath& share_file);

  void OnResourceCached(const base::FilePath& input_dir, const std::string& name, const base::UUID& uuid, int64_t result);
  void OnShareAdded(scoped_refptr<Workspace> workspace, const base::UUID& uuid, const std::string& infohash, const std::string& name, int64_t result);
  void OnDatabaseCreated(scoped_refptr<Workspace> workspace, const std::string& db_name, int64_t result);

  BundlePackage* resource_package_;
  BundlePackage* application_package_;
  base::UUID id_;
  protocol::Bundle bundle_proto_;
  // fixme: should be added to the proto
  std::vector<std::unique_ptr<BundlePackage>> packages_;
  // keep it here so the lifetime outlives the parsing method
  std::unique_ptr<zetasql::ParserOutput> parser_output_;
  
  bool managed_;

  DISALLOW_COPY_AND_ASSIGN(Bundle);
};

}

#endif