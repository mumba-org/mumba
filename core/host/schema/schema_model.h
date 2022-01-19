// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_SCHEMA_SCHEMA_MODEL_H_
#define MUMBA_HOST_SCHEMA_SCHEMA_MODEL_H_

#include <memory>

#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/uuid.h"
#include "net/base/io_buffer.h"
#include "core/host/database_policy.h"

namespace host {
class Schema;
class SchemaRegistry;
class ShareDatabase;

class SchemaModel : public DatabasePolicyObserver {
public:
  SchemaModel(scoped_refptr<ShareDatabase> db, DatabasePolicy policy);
  ~SchemaModel();

  const std::vector<Schema *>& schemas() const {
    return schemas_;
  }

  std::vector<Schema *>& schemas() {
    return schemas_;
  }

  void Load(SchemaRegistry* registry, base::Callback<void(int, int)> cb);
  bool SchemaExists(Schema* schema);
  bool SchemaExists(const std::string& hash, base::UUID* id);
  bool SchemaExists(const std::string& hash);
  Schema* GetSchemaById(const base::UUID& id);
  Schema* GetSchemaByHash(const std::string& hash);
  Schema* GetSchemaByName(const std::string& name);
  Schema* GetSchemaWithService(const std::string& package, const std::string& service_name);
  void InsertSchema(const base::UUID& id, Schema* schema, bool persist = true);
  void RemoveSchema(const base::UUID& id);
 
  void Close();

private:
  
  void InsertSchemaInternal(const base::UUID& id, Schema* schema, bool persist);
  void RemoveSchemaInternal(const base::UUID& id);

  void InsertSchemaToDB(const base::UUID& id, Schema* schema);
  void RemoveSchemaFromDB(Schema* schema);

  void AddToCache(const base::UUID& id, Schema* schema);
  void RemoveFromCache(const base::UUID& id, bool should_delete = true);
  void RemoveFromCache(Schema* schema, bool should_delete = true);

  void LoadSchemasFromDB(SchemaRegistry* registry, base::Callback<void(int, int)> cb);

  void MaybeOpen();
  void MaybeClose();

  void OnDatabasePolicyChanged(DatabasePolicy new_policy) override;

  DatabasePolicy policy_;
  scoped_refptr<ShareDatabase> db_;
  
  base::Lock schemas_vector_lock_;
  std::vector<Schema *> schemas_;

private:

 DISALLOW_COPY_AND_ASSIGN(SchemaModel);
};

}

#endif