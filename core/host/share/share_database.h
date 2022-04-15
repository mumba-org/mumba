// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_CORE_SHARE_DATABASE_
#define MUMBA_CORE_SHARE_DATABASE_

#include "base/memory/ref_counted.h"
#include "storage/db/db.h"

namespace host {
class Share;

enum class ShareDatabaseType {
  kKEY_VALUE = 0,
  kSQL = 1
};

class ShareDatabase : public base::RefCountedThreadSafe<ShareDatabase> {
public:
  class Delegate {
  public:
    virtual ~Delegate() {}
    virtual const scoped_refptr<storage::Torrent>& torrent() const = 0;
    virtual const std::string& name() const = 0;
    virtual void OpenDatabaseSync(bool key_value) = 0;
  };
  
  static scoped_refptr<ShareDatabase> Open(Delegate* delegate, bool key_value);
  static scoped_refptr<ShareDatabase> Create(Delegate* delegate, const std::vector<std::string>& keyspaces, bool key_value, bool in_memory);

  ShareDatabase(Delegate* delegate, std::unique_ptr<storage::Database> db, bool in_memory);
  ShareDatabase(Delegate* delegate, storage::Database* db, bool in_memory);
  
  Delegate* delegate() const {
    return delegate_;
  }

  const std::string& name() const {
    return delegate_->name();
  }

  ShareDatabaseType type() const {
    return type_;
  }
  
  bool readonly() const;
  bool is_open() const {
    return !is_closed();
  }
  bool is_closed() const;
  bool in_memory() const {
    return in_memory_;
  }
  const base::UUID& id() const;
  int table_count() const;
  storage::Database* db() const {
    return impl_;
  }
  
  bool Init(bool key_value);
  bool CreateTables(const std::vector<std::string>& keyspaces);
  void Open(bool key_value);
  void Close();

  storage::Transaction* Begin(bool write);
  storage::Transaction* BeginRead();
  storage::Transaction* BeginWrite();

  bool Get(storage::Transaction* tr, const std::string& keyspace, base::StringPiece key, std::string* value);
  bool Put(storage::Transaction* tr, const std::string& keyspace, base::StringPiece key, base::StringPiece value);
  bool Delete(storage::Transaction* tr, const std::string& keyspace, base::StringPiece key);

  bool ExecuteStatement(const std::string& stmt);
  csqlite_stmt* ExecuteQuery(const std::string& query, int* rc);
  
  bool EraseAll(storage::Transaction* tr);
  bool Check();

  int CountItems(storage::Transaction* tr, const std::string& keyspace);
  bool CreateKeyspace(const std::string& keyspace);
  bool DropKeyspace(const std::string& keyspace);
  void GetKeyspaceList(std::vector<std::string>* out, bool include_hidden = false);

  bool Checkpoint(int* result_code);
  
private:
  friend class base::RefCountedThreadSafe<ShareDatabase>;

  ~ShareDatabase();

  Delegate* delegate_;
  std::unique_ptr<storage::Database> owned_impl_;
  storage::Database* impl_;
  ShareDatabaseType type_;
  bool in_memory_;
  
  DISALLOW_COPY_AND_ASSIGN(ShareDatabase);
};

}

#endif
