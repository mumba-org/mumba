// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/schema/schema_model.h"

#include "base/task_scheduler/post_task.h"
#include "core/host/schema/schema.h"
#include "core/host/share/share_database.h"
#include "core/host/workspace/workspace.h"
#include "storage/torrent.h"
#include "storage/db/db.h"

namespace host {

SchemaModel::SchemaModel(scoped_refptr<ShareDatabase> db, DatabasePolicy policy):
 policy_(policy),
 db_(db) {
  
}

SchemaModel::~SchemaModel() {
  base::AutoLock lock(schemas_vector_lock_);
  for (auto it = schemas_.begin(); it != schemas_.end(); ++it) {
    delete *it;
  }
  schemas_.clear();
  db_ = nullptr;
}

void SchemaModel::Load(SchemaRegistry* registry, base::Callback<void(int, int)> cb) {
  //db_context_->io_task_runner()->PostTask(
  //  FROM_HERE,
  //  base::Bind(
  //     &SchemaModel::LoadSchemasFromDB,
  //      base::Unretained(this),
  //      base::Unretained(registry)));
  LoadSchemasFromDB(registry, std::move(cb));
}

bool SchemaModel::SchemaExists(Schema* schema) {
  base::AutoLock lock(schemas_vector_lock_);
  for (auto it = schemas_.begin(); it != schemas_.end(); ++it) {
    if ((*it)->name() == schema->name()) {
      return true;
    }
  }
  return false; 
}

bool SchemaModel::SchemaExists(const std::string& hash, base::UUID* id) {
  base::AutoLock lock(schemas_vector_lock_);
  for (auto it = schemas_.begin(); it != schemas_.end(); ++it) {
    if ((*it)->root_hash() == hash) {
      *id = (*it)->id();
      return true;
    }
  }
  return false; 
}

bool SchemaModel::SchemaExists(const std::string& hash) {
  base::AutoLock lock(schemas_vector_lock_);
  for (auto it = schemas_.begin(); it != schemas_.end(); ++it) {
    if ((*it)->root_hash() == hash) {
      return true;
    }
  }
  return false;
}

Schema* SchemaModel::GetSchemaById(const base::UUID& id) {
  base::AutoLock lock(schemas_vector_lock_);
  for (auto it = schemas_.begin(); it != schemas_.end(); ++it) {
    if ((*it)->id() == id) {
      return *it;
    }
  }
  return nullptr;
}

Schema* SchemaModel::GetSchemaByHash(const std::string& hash) {
  base::AutoLock lock(schemas_vector_lock_);
  for (auto it = schemas_.begin(); it != schemas_.end(); ++it) {
    if ((*it)->root_hash() == hash) {
      return *it;
    }
  }
  return nullptr;
}

Schema* SchemaModel::GetSchemaByName(const std::string& name) {
  base::AutoLock lock(schemas_vector_lock_);
  for (auto it = schemas_.begin(); it != schemas_.end(); ++it) {
    if ((*it)->package() == name) {
      return *it;
    }
  }
  return nullptr;
}

Schema* SchemaModel::GetSchemaWithService(const std::string& package, const std::string& service_name) {
  base::AutoLock lock(schemas_vector_lock_);
  for (auto it = schemas_.begin(); it != schemas_.end(); ++it) {
    Schema* schema = *it;
    //DLOG(INFO) << "SchemaModel: looking up in '" << schema->name() << "'";
    for(size_t i = 0; i < schema->service_count(); i++) {
      const auto* service = schema->service_at(i);
      //DLOG(INFO) << "SchemaModel: " << schema->name() << " service " << service->name() << 
      //  "\n comparing " << package << " with " << schema->package() << " AND " << service_name << " with " << service->name();
      if (base::LowerCaseEqualsASCII(package, schema->package()) && service_name == service->name()) {
        return schema;
      }
    }
  }
  return nullptr;
}

void SchemaModel::InsertSchema(const base::UUID& id, Schema* schema, bool persist) {
  //table_->Run(base::Bind(
  //      &SchemaModel::InsertSchemaInternal,
  //        base::Unretained(this),
  //        id,
  //        base::Unretained(schema)));
  InsertSchemaInternal(id, schema, persist);
}

void SchemaModel::RemoveSchema(const base::UUID& id) {
  //table_->Run(
  //  base::Bind(
  //      &SchemaModel::RemoveSchemaInternal,
  //        base::Unretained(this),
  //        id));
  RemoveSchemaInternal(id);
}

void SchemaModel::InsertSchemaInternal(const base::UUID& id, Schema* schema, bool persist) {
  if (!SchemaExists(schema)) {
    //if (InsertSchemaToDB(id, schema)) {
      if (persist) {
        InsertSchemaToDB(id, schema);
      }
      AddToCache(id, schema);
    //} else {
    //  LOG(ERROR) << "Failed to add schema " << id.to_string() << " to DB";
    //}
  } else {
    LOG(ERROR) << "Failed to add schema " << id.to_string() << " to DB. Already exists";
  }
}

void SchemaModel::RemoveSchemaInternal(const base::UUID& id) {
  Schema* schema = GetSchemaById(id);
  if (schema) {
    //if (RemoveSchemaFromDB(schema)) {
    RemoveSchemaFromDB(schema);
    RemoveFromCache(schema);
    //} else {
    //  LOG(ERROR) << "Failed to remove schema from DB. id " << id.to_string() << ".";
    //}
  } else {
    LOG(ERROR) << "Failed to remove schema. Schema with id " << id.to_string() << " not found.";
  }
}
 
void SchemaModel::InsertSchemaToDB(const base::UUID& id, Schema* schema) {
  //bool result = false;
  scoped_refptr<net::IOBufferWithSize> data = schema->Serialize();
  if (data) {
    MaybeOpen();
    //LOG(INFO) << "inserting schema " << schema->name() << " '" << data->data() << "'";
    storage::Transaction* trans = db_->Begin(true);
    bool ok = db_->Put(trans, Schema::kClassName, schema->name(), base::StringPiece(data->data(), data->size()));
    ok ? trans->Commit() : trans->Rollback();
    MaybeClose();
    //
    //LOG(INFO) << "result of insert: " << result;
  }
  //return result;
}

void SchemaModel::RemoveSchemaFromDB(Schema* schema) {
  //return db_->Remove(schema->name());
  MaybeOpen();
  storage::Transaction* trans = db_->Begin(true);
  bool ok = db_->Delete(trans, Schema::kClassName, schema->name());//, base::Bind(&SchemaModel::OnRemoveReply, base::Unretained(this)));
  ok ? trans->Commit() : trans->Rollback();
  MaybeClose();
  //
}

void SchemaModel::AddToCache(const base::UUID& id, Schema* schema) {
  schemas_.push_back(schema);
  schema->set_managed(true);
}

void SchemaModel::RemoveFromCache(const base::UUID& id, bool should_delete) {
  base::AutoLock lock(schemas_vector_lock_);
  Schema* found = nullptr;
  for (auto it = schemas_.begin(); it != schemas_.end(); ++it) {
    if ((*it)->id() == id) {
      found = *it;
      found->set_managed(false);
      schemas_.erase(it);
      break;
    }
  }
  if (found && should_delete) {
    delete found;
  }
}

void SchemaModel::RemoveFromCache(Schema* schema, bool should_delete) {
  base::AutoLock lock(schemas_vector_lock_);
  for (auto it = schemas_.begin(); it != schemas_.end(); ++it) {
    if (*it == schema) {
      (*it)->set_managed(false);
      schemas_.erase(it);
      break;
    }
  }
  if (should_delete) {
    delete schema;
  }
}

void SchemaModel::LoadSchemasFromDB(SchemaRegistry* registry, base::Callback<void(int, int)> cb) {
  size_t count = 0;
  MaybeOpen();
  storage::Transaction* trans = db_->Begin(false);
  storage::Cursor* it = trans->CreateCursor(Schema::kClassName);
  if (!it) {
    DLOG(ERROR) << "SchemaModel::LoadSchemasFromDB: creating cursor for 'schema' failed.";
    std::move(cb).Run(net::ERR_FAILED, 0);
    return;
  }
  it->First();
  while (it->IsValid()) {
    bool valid = false;
    storage::KeyValuePair kv = storage::DbDecodeKV(it->GetData(), &valid);
    if (valid) {
      scoped_refptr<net::StringIOBuffer> buffer = new net::StringIOBuffer(kv.second.as_string());
      std::unique_ptr<Schema> p = Schema::Deserialize(registry, buffer.get(), kv.second.size());
      if (p) {
        p->set_managed(true);
        schemas_vector_lock_.Acquire();
        schemas_.push_back(p.release());
        schemas_vector_lock_.Release();
      } else {
        LOG(ERROR) << "failed to deserialize schema";
      }
    } else {
      LOG(ERROR) << "failed to deserialize schema: it->GetValue() returned nothing";
    }
    it->Next();
    count++;
  }
  trans->Commit();
  MaybeClose();
  std::move(cb).Run(net::OK, count);
  //
}

void SchemaModel::Close() {
  //db_->Close();
}

void SchemaModel::OnInsertReply(bool result) {
  //DLOG(INFO) << "inserting schema on db: " << (result ? "true" : "false");
}

void SchemaModel::OnRemoveReply(bool result) {
  //DLOG(INFO) << "removing schema on db: " << (result ? "true" : "false");
}

void SchemaModel::MaybeOpen() {
  if (policy_ != DatabasePolicy::OpenClose) {
    return;
  }
  if (!db_->is_open()) {
    db_->Open();
  }
}

void SchemaModel::MaybeClose() {
  if (policy_ != DatabasePolicy::OpenClose) {
    return;
  }
  if (db_->is_open()) {
    db_->Close();
  }
}

void SchemaModel::OnDatabasePolicyChanged(DatabasePolicy new_policy) {
  policy_ = new_policy;
}

}
