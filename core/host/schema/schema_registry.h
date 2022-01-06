// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_SCHEMA_SCHEMA_REGISTRY_H_
#define MUMBA_HOST_SCHEMA_SCHEMA_REGISTRY_H_

#include <memory>

#include "base/macros.h"
#include "base/synchronization/lock.h"
#include "base/memory/ref_counted.h"
#include "base/files/file_path.h"
#include "base/atomic_sequence_num.h"
#include "base/memory/weak_ptr.h"
#include "base/single_thread_task_runner.h"
#include "base/uuid.h"
#include "core/host/database_policy.h"
#include "third_party/protobuf/src/google/protobuf/descriptor.h"

namespace host {
class SchemaModel;
class Schema;
class ShareDatabase;

class SchemaRegistry {
public:
  class Observer {
  public:
    virtual ~Observer(){}
    virtual void OnSchemasLoad(int r, int count) {}
    virtual void OnSchemaAdded(Schema* schema) {}
    virtual void OnSchemaRemoved(Schema* schema) {}
  };
  SchemaRegistry();
  ~SchemaRegistry();

  SchemaModel* model() const {
    return schemas_.get();
  }

  const std::vector<Schema *>& schemas() const;

  google::protobuf::DescriptorPool* descriptor_pool() const {
    return descriptor_pool_.get();
  }

  const google::protobuf::FileDescriptor* BuildFile(const google::protobuf::FileDescriptorProto& schema);

  void Init(scoped_refptr<ShareDatabase> db, DatabasePolicy policy, const base::FilePath& root_path);
  void Shutdown();
 
  Schema* GetSchemaByName(const std::string& name) const;
  void InsertSchema(std::unique_ptr<Schema> schema, bool persist = true);
  void RemoveSchema(Schema* schema);
  void RemoveSchema(const base::UUID& uuid);

  void AddObserver(Observer* observer);
  void RemoveObserver(Observer* observer);

private:

  void InitImpl(const base::FilePath& root_path);
  void ShutdownImpl();

  void OnLoad(int r, int count);

  void NotifySchemaAdded(Schema* schema);
  void NotifySchemaRemoved(Schema* schema);
  void NotifySchemasLoad(int r, int count);

  base::Lock descriptor_lock_;
  base::FilePath root_path_;
  std::unique_ptr<google::protobuf::DescriptorPool> descriptor_pool_;
  std::unique_ptr<SchemaModel> schemas_;
  std::vector<Observer *> observers_;
  base::WeakPtrFactory<SchemaRegistry> weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(SchemaRegistry);
};

}

#endif