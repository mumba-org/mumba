// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/schema/schema_registry.h"

#include "base/path_service.h"
#include "base/base_paths.h"
#include "base/files/file_util.h"
#include "base/task_scheduler/post_task.h"
#include "core/shared/common/paths.h"
#include "core/host/host_thread.h"
#include "core/host/schema/schema.h"
#include "core/host/schema/schema_model.h"
#include "core/host/share/share_database.h"
#include "core/host/workspace/workspace.h"
#include "storage/torrent.h"

namespace host {

//namespace {
//  const char kSCHEMAS_DIR[] = "schemas";
  //const char kDATABASE_FILE[] = "INDEX";
//}

SchemaRegistry::SchemaRegistry():
  descriptor_pool_(new google::protobuf::DescriptorPool()), 
  weak_factory_(this) {
  
}

SchemaRegistry::~SchemaRegistry() {

}

void SchemaRegistry::Init(scoped_refptr<ShareDatabase> db, DatabasePolicy policy, const base::FilePath& root_path) {
  root_path_ = root_path;
  schemas_ = std::make_unique<SchemaModel>(db, policy);

  // base::PostTaskWithTraits(
  //   FROM_HERE,
  //   { base::MayBlock(), 
  //     base::WithBaseSyncPrimitives(),
  //     base::TaskPriority::USER_BLOCKING},
  //   base::Bind(
  //     &SchemaRegistry::InitImpl,
  //       weak_factory_.GetWeakPtr(),
  //       root_path));

  InitImpl(root_path);
}

void SchemaRegistry::Shutdown() {
  //base::PostTaskWithTraits(
  //  FROM_HERE,
  //  {base::MayBlock(), base::WithBaseSyncPrimitives(), base::TaskPriority::USER_BLOCKING},
  //  base::Bind(
  //    &SchemaRegistry::ShutdownImpl,
  //      weak_factory_.GetWeakPtr()));
  ShutdownImpl();
}

void SchemaRegistry::InitImpl(const base::FilePath& root_path) {
  //base::FilePath schemadb_dir = root_path.AppendASCII(kSCHEMAS_DIR);
  //if (!base::DirectoryExists(schemadb_dir)) {
  //  if (!base::CreateDirectory(schemadb_dir)) {
  //    LOG(ERROR) << "failed to create schema dir at " << schemadb_dir;
  //    return;
  //  }
  //}
  //base::FilePath schemadb_path = schemadb_dir.AppendASCII(kDATABASE_FILE);
  //std::unique_ptr<SchemaDatabase> db = std::make_unique<SchemaDatabase>();
  //if (!db->Open(schemadb_path)) {
  //  LOG(ERROR) << "failed to open schema db at " << schemadb_path;
  //  return;
  //}
  schemas_->Load(this, base::Bind(&SchemaRegistry::OnLoad, base::Unretained(this)));
}


void SchemaRegistry::ShutdownImpl() {
  //schemas_->Close();
  schemas_.reset();
}

const std::vector<Schema *>& SchemaRegistry::schemas() const {
  return schemas_->schemas();
}

const google::protobuf::FileDescriptor* SchemaRegistry::BuildFile(const google::protobuf::FileDescriptorProto& schema) {
  base::AutoLock auto_lock(descriptor_lock_);
  const google::protobuf::FileDescriptor* result = descriptor_pool_->BuildFile(schema);
  return result;
}

Schema* SchemaRegistry::GetSchemaByName(const std::string& name) const {
  Schema* result = nullptr;
  for (auto it = schemas().begin(); it != schemas().end(); ++it) {
    if ((*it)->name() == name) {
      result = *it;
    }
  }
  return result;
}

void SchemaRegistry::InsertSchema(std::unique_ptr<Schema> schema, bool persist) {
  Schema* schema_ref = schema.release();
  schemas_->InsertSchema(schema_ref->id(), schema_ref, persist);
  NotifySchemaAdded(schema_ref);
}

void SchemaRegistry::RemoveSchema(Schema* schema) {
  NotifySchemaRemoved(schema);
  schemas_->RemoveSchema(schema->id());
}

void SchemaRegistry::RemoveSchema(const base::UUID& uuid) {
  Schema* schema = schemas_->GetSchemaById(uuid);
  if (schema) {
    NotifySchemaRemoved(schema);
    schemas_->RemoveSchema(uuid);
  }
}

void SchemaRegistry::AddObserver(Observer* observer) {
  observers_.push_back(observer);
}

void SchemaRegistry::RemoveObserver(Observer* observer) {
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    if (observer == *it) {
      observers_.erase(it);
      return;
    }
  }
}

void SchemaRegistry::OnLoad(int r, int count) {
  NotifySchemasLoad(r, count);
}

void SchemaRegistry::NotifySchemaAdded(Schema* schema) {
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    Observer* observer = *it;
    observer->OnSchemaAdded(schema);
  }
}

void SchemaRegistry::NotifySchemaRemoved(Schema* schema) {
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    Observer* observer = *it;
    observer->OnSchemaRemoved(schema);
  }
}

void SchemaRegistry::NotifySchemasLoad(int r, int count) {
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    Observer* observer = *it;
    observer->OnSchemasLoad(r, count);
  }
}

}