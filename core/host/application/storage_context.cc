// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/application/storage_context.h"

#include "base/strings/string_number_conversions.h"
#include "base/strings/utf_string_conversions.h"
#include "base/task_scheduler/post_task.h"
#include "base/threading/thread_task_runner_handle.h"
#include "base/sequenced_task_runner.h"
#include "core/host/host_thread.h"
#include "core/host/workspace/workspace.h"
#include "core/host/volume/volume.h"
#include "core/host/volume/volume_manager.h"
#include "core/host/volume/volume_model.h"
#include "core/host/workspace/volume_storage.h"
#include "core/host/application/domain.h"
#include "core/host/application/domain_process_host.h"
#include "storage/storage_manager.h"
#include "storage/storage.h"
#include "core/host/share/share.h"
#include "core/host/share/share_database.h"
#include "core/host/share/share_manager.h"
#include "storage/proto/storage.pb.h"
#include "storage/db/sqlite3.h"

// forward decl

extern "C" void csqlitePCacheSetDefault(void);

namespace host {

namespace {

storage_proto::InfoKind ToInfoKind(common::mojom::StorageType mojo_type) {
  switch(mojo_type) {
    case common::mojom::StorageType::kRaw:
      return storage_proto::INFO_RAW;
    case common::mojom::StorageType::kData:
      return storage_proto::INFO_KVDB;
    case common::mojom::StorageType::kFile:
      return storage_proto::INFO_FILE;
  }
  return storage_proto::INFO_FILE;
}

common::mojom::DomainStatus ToStorageStatus(int64_t net_status) {
  return net_status == net::OK ? common::mojom::DomainStatus::kOk : common::mojom::DomainStatus::kError;
}

// void OnDatabaseOpen(int64_t* out_result, base::WaitableEvent* event, int64_t result) {
//   *out_result = result;
//   if (event) {
//     event->Signal();
//   }
// }

} // namespace

StorageDataCursor::StorageDataCursor(storage::Transaction* transaction, bool write):
 transaction_(transaction),
 cursor_(nullptr),
 is_write_(write) {
  DCHECK(transaction_);
}

StorageDataCursor::~StorageDataCursor()  {
  
}

bool StorageDataCursor::is_write() const {
  return is_write_;
}

bool StorageDataCursor::Init(const std::string& keyspace, storage::Order order) {
  cursor_ = transaction_->CreateCursor(keyspace, order);
  return cursor_ != nullptr;
}

void StorageDataCursor::IsValid(IsValidCallback callback) {
  ////DLOG(INFO) << "StorageDataCursor::IsValid";
  if (!cursor_) {
    std::move(callback).Run(false);
    return;  
  }
  bool valid = cursor_->IsValid();
  std::move(callback).Run(valid);
}

void StorageDataCursor::First(FirstCallback callback) {
  ////DLOG(INFO) << "StorageDataCursor::First";
  if (!cursor_) {
    std::move(callback).Run(net::ERR_FAILED);
    return;  
  }
  bool r = cursor_->First();
  std::move(callback).Run(r ? net::OK : net::ERR_FAILED);
}

void StorageDataCursor::Last(LastCallback callback) {
  ////DLOG(INFO) << "StorageDataCursor::Last";
  if (!cursor_) {
    std::move(callback).Run(net::ERR_FAILED);
    return;  
  }
  bool r = cursor_->Last();
  std::move(callback).Run(r ? net::OK : net::ERR_FAILED);
}

void StorageDataCursor::Previous(PreviousCallback callback) {
  ////DLOG(INFO) << "StorageDataCursor::Previous";
  if (!cursor_) {
    std::move(callback).Run(net::ERR_FAILED);
    return;  
  }
  bool r = cursor_->Previous();
  std::move(callback).Run(r ? net::OK : net::ERR_FAILED);
}

void StorageDataCursor::Next(NextCallback callback) {
  ////DLOG(INFO) << "StorageDataCursor::Next";
  if (!cursor_) {
    std::move(callback).Run(net::ERR_FAILED);
    return;  
  }
  bool r = cursor_->Next();
  std::move(callback).Run(r ? net::OK : net::ERR_FAILED);
}

void StorageDataCursor::SeekTo(const std::vector<uint8_t>& key, common::mojom::Seek seek, SeekToCallback callback) {
  if (!cursor_) {
    std::move(callback).Run(net::ERR_FAILED, false);
    return;  
  }
  bool match = false;
  base::StringPiece key_str(reinterpret_cast<const char*>(key.data()), key.size());
  int r = cursor_->SeekTo(key_str, static_cast<storage::Seek>(seek), &match);
  std::move(callback).Run(r, match);
}

void StorageDataCursor::DataSize(DataSizeCallback callback) {
  ////DLOG(INFO) << "StorageDataCursor::DataSize";
  if (!cursor_) {
    std::move(callback).Run(net::ERR_FAILED, -1);
    return;  
  }
  int size = cursor_->DataSize();
  std::move(callback).Run(net::OK, size); 
}

void StorageDataCursor::Count(CountCallback callback) {
  if (!cursor_) {
    std::move(callback).Run(net::ERR_FAILED, -1);
    return;  
  }
  int count = cursor_->Count();
  std::move(callback).Run(net::OK, count);
}

void StorageDataCursor::GetData(GetDataCallback callback) {
  ////DLOG(INFO) << "StorageDataCursor::GetData";
  std::vector<uint8_t> data;
  if (!cursor_) {
    std::move(callback).Run(net::ERR_FAILED, std::move(data));
    return;  
  }
  base::StringPiece data_view = cursor_->GetData();
  if (!data_view.empty()) {
    data.reserve(data_view.size());
    std::memcpy(data.data(), data_view.data(), data_view.size());
    std::move(callback).Run(net::OK, std::move(data));
  } else {
    std::move(callback).Run(net::ERR_FAILED, std::move(data));
  }
}

void StorageDataCursor::GetKeyValue(GetKeyValueCallback callback) {
  ////DLOG(INFO) << "StorageDataCursor::GetKeyValue";
  //std::vector<uint8_t> key;
  //std::vector<uint8_t> value;
  common::mojom::KeyValuePtr kv_obj = common::mojom::KeyValue::New();

  if (!cursor_) {
    std::move(callback).Run(net::ERR_FAILED, std::move(kv_obj));
    return;  
  }
  storage::KeyValuePair kv = cursor_->GetKV();
  
  if (kv.first.size() > 0) {
    kv_obj->key.reserve(kv.first.size());
    if (kv.second.size() > 0)
      kv_obj->value.reserve(kv.second.size());
  
    //std::copy(reinterpret_cast<const uint8_t *>(kv.first.data()), reinterpret_cast<const uint8_t *>(kv.first.data() + kv.first.size()), std::back_inserter(kv_obj->key));
    kv_obj->key.insert(kv_obj->key.end(), reinterpret_cast<const uint8_t *>(kv.first.data()), reinterpret_cast<const uint8_t *>(kv.first.data() + kv.first.size()));
    if (kv.second.size() > 0) {
      kv_obj->value.insert(kv_obj->value.end(), reinterpret_cast<const uint8_t *>(kv.second.data()), reinterpret_cast<const uint8_t *>(kv.second.data()) + kv.second.size());
      //std::copy(reinterpret_cast<const uint8_t *>(kv.second.data()), reinterpret_cast<const uint8_t *>(kv.second.data()) + kv.second.size(), std::back_inserter(kv_obj->value)); 
    }
    std::move(callback).Run(net::OK, std::move(kv_obj));
  } else {
    std::move(callback).Run(net::ERR_FAILED, std::move(kv_obj));
  }
}

void StorageDataCursor::Get(const std::vector<uint8_t>& key, GetCallback callback) {
  ////DLOG(INFO) << "StorageDataCursor::Get";
  common::mojom::KeyValuePtr kv_obj = common::mojom::KeyValue::New();
  storage::KeyValuePair kv;

  if (!cursor_) {
    std::move(callback).Run(net::ERR_FAILED, std::move(kv_obj));
    return;  
  }
  base::StringPiece key_str(reinterpret_cast<const char *>(key.data()), key.size());
  if (!cursor_->Get(key_str, &kv)) {
    ////DLOG(INFO) << "StorageDataCursor::Get: cursor->Get() for " << key_str << " returned false";
    std::move(callback).Run(net::ERR_FAILED, std::move(kv_obj));
    return;  
  }
  
  kv_obj->key.reserve(kv.first.size());
  kv_obj->key.insert(kv_obj->key.end(), reinterpret_cast<const uint8_t *>(kv.first.data()), reinterpret_cast<const uint8_t *>(kv.first.data()) + kv.first.size());
 
  kv_obj->value.reserve(kv.second.size());
  kv_obj->value.insert(kv_obj->value.end(), reinterpret_cast<const uint8_t *>(kv.second.data()), reinterpret_cast<const uint8_t *>(kv.second.data()) + kv.second.size());
  
  std::move(callback).Run(net::OK, std::move(kv_obj));
}

void StorageDataCursor::Insert(common::mojom::KeyValuePtr kv, InsertCallback callback) {
  if (!cursor_) {
    std::move(callback).Run(net::ERR_FAILED);
    return;  
  }
  storage::KeyValuePair kv_local;
  kv_local.first = base::StringPiece(reinterpret_cast<const char *>(kv->key.data()), kv->key.size());
  kv_local.second = base::StringPiece(reinterpret_cast<const char *>(kv->value.data()), kv->value.size());
  bool r = cursor_->Insert(kv_local);
  std::move(callback).Run(r ? net::OK : net::ERR_FAILED);
}

void StorageDataCursor::Delete(DeleteCallback callback) {
  ////DLOG(INFO) << "StorageDataCursor::Delete";
  if (!cursor_) {
    std::move(callback).Run(net::ERR_FAILED);
    return;  
  }
  bool r = cursor_->Delete();
  std::move(callback).Run(r ? net::OK : net::ERR_FAILED);
}

void StorageDataCursor::Commit(CommitCallback callback) {
  //DLOG(INFO) << "StorageDataCursor::Commit";
  if (!cursor_) {
    std::move(callback).Run(net::ERR_FAILED);
    return;  
  }
  bool r = transaction_->Commit();
  cursor_ = nullptr;
  std::move(callback).Run(r ? net::OK : net::ERR_FAILED);
}

void StorageDataCursor::Rollback(RollbackCallback callback) {
  if (!cursor_) {
    std::move(callback).Run(net::ERR_FAILED);
    return;  
  }
  bool r = transaction_->Rollback();
  cursor_ = nullptr;
  std::move(callback).Run(r ? net::OK : net::ERR_FAILED);
}

StorageSQLCursor::StorageSQLCursor(csqlite_stmt* stmt, int rc, scoped_refptr<base::SequencedTaskRunner> task_runner): 
  stmt_(stmt), 
  rc_(rc),
  task_runner_(task_runner) {

  csqlitePCacheSetDefault();
}

StorageSQLCursor::~StorageSQLCursor() {
  DCHECK(task_runner_->RunsTasksInCurrentSequence());
  csqlite_finalize(stmt_);
}

void StorageSQLCursor::IsValid(IsValidCallback callback) {
  DCHECK(task_runner_->RunsTasksInCurrentSequence());
  std::move(callback).Run(rc_ == SQLITE_ROW);
}

void StorageSQLCursor::First(FirstCallback callback) {

}

void StorageSQLCursor::Last(LastCallback callback) {

}

void StorageSQLCursor::Previous(PreviousCallback callback) {

}

void StorageSQLCursor::Next(NextCallback callback) {
  DCHECK(task_runner_->RunsTasksInCurrentSequence());
  base::AutoLock lock(lock_);
  rc_ = csqlite_step(stmt_);
  std::move(callback).Run(rc_ == SQLITE_ROW);
}

void StorageSQLCursor::GetBlob(const std::vector<int8_t>& row, GetBlobCallback callback) {
  DCHECK(task_runner_->RunsTasksInCurrentSequence());
  base::AutoLock lock(lock_);
  std::string col_name(row.begin(), row.end());
  int col_index = GetColumnIndex(col_name);
  if (col_index == -1) {
    std::move(callback).Run(net::ERR_FAILED, std::vector<uint8_t>());
    return;
  }
  const void* data = csqlite_column_blob(stmt_, col_index);
  size_t size = csqlite_column_bytes(stmt_, col_index);
  std::vector<uint8_t> vec_data;
  vec_data.insert(vec_data.end(), reinterpret_cast<const uint8_t *>(data), reinterpret_cast<const uint8_t *>(data) + size);
  std::move(callback).Run(net::OK, vec_data);
}

void StorageSQLCursor::GetString(const std::vector<int8_t>& row, GetStringCallback callback) {
  DCHECK(task_runner_->RunsTasksInCurrentSequence());
  base::AutoLock lock(lock_);
  std::string col_name(row.begin(), row.end());
  int col_index = GetColumnIndex(col_name);
  if (col_index == -1) {
    std::move(callback).Run(net::ERR_FAILED, std::string());
    return;
  }
  const uint8_t* data = csqlite_column_text(stmt_, col_index);
  size_t size = csqlite_column_bytes(stmt_, col_index);
  std::move(callback).Run(net::OK, std::string(reinterpret_cast<const char*>(data), size));
}

void StorageSQLCursor::GetInt32(const std::vector<int8_t>& row, GetInt32Callback callback) {
  DCHECK(task_runner_->RunsTasksInCurrentSequence());
  base::AutoLock lock(lock_);
  std::string col_name(row.begin(), row.end());
  int col_index = GetColumnIndex(col_name);
  if (col_index == -1) {
    std::move(callback).Run(net::ERR_FAILED, -1);
    return;
  }
  int data = csqlite_column_int(stmt_, col_index);
  std::move(callback).Run(net::OK, data);
}

void StorageSQLCursor::GetInt64(const std::vector<int8_t>& row, GetInt64Callback callback) {
  DCHECK(task_runner_->RunsTasksInCurrentSequence());
  base::AutoLock lock(lock_);
  std::string col_name(row.begin(), row.end());
  int col_index = GetColumnIndex(col_name);
  if (col_index == -1) {
    std::move(callback).Run(net::ERR_FAILED, -1);
    return;
  }
  int64_t data = csqlite_column_int64(stmt_, col_index);
  std::move(callback).Run(net::OK, data);
}

void StorageSQLCursor::GetDouble(const std::vector<int8_t>& row, GetDoubleCallback callback) {
  DCHECK(task_runner_->RunsTasksInCurrentSequence());
  base::AutoLock lock(lock_);
  std::string col_name(row.begin(), row.end());
  int col_index = GetColumnIndex(col_name);
  if (col_index == -1) {
    std::move(callback).Run(net::ERR_FAILED, 0.0);
    return;
  }
  double data = csqlite_column_double(stmt_, col_index);
  std::move(callback).Run(net::OK, data);
}

int StorageSQLCursor::GetColumnIndex(const std::string& name) {
  DCHECK(task_runner_->RunsTasksInCurrentSequence());
  //base::AutoLock lock(lock_);
  int index = -1;
  auto it = colname_map_.find(name);
  // not cached
  if (it == colname_map_.end()) {
    for (int i = 0; i < csqlite_column_count(stmt_); i++) {
      const char* cname = csqlite_column_name(stmt_, i);
      if (strcmp(cname, name.c_str()) == 0) {
        colname_map_.emplace(std::make_pair(name, i));
        index = i;
        break;
      }
    }
  } else {
    index = it->second;
  }
  return index;
}

StorageContext::StorageContext(int id, scoped_refptr<Workspace> workspace, Domain* domain):
  id_(id),
  workspace_(workspace),
  domain_(domain),
  task_runner_(
    //base::CreateSingleThreadTaskRunnerWithTraits(
    base::CreateSequencedTaskRunnerWithTraits(
       { base::MayBlock(), base::WithBaseSyncPrimitives() })) {//,
         //base::WithBaseSyncPrimitives() },
       //base::SingleThreadTaskRunnerThreadMode::SHARED)) {
  domain_->AddStorageContext(this); 
}

StorageContext::~StorageContext() {
  // TODO: see if this is ok, given maybe context outlives domain
  domain_->RemoveStorageContext(this); 
}

const std::string& StorageContext::domain_name() {
  base::AutoLock m(domain_lock_);
  return domain_->name();
}

const base::UUID& StorageContext::domain_uuid() {
  base::AutoLock m(domain_lock_);
  return domain_->id(); 
}

storage::StorageManager& StorageContext::storage_manager() {
  return workspace_->storage_manager();
}

common::mojom::DataCursorPtr StorageContext::CreateBinding(StorageDataCursor* cursor) {
  common::mojom::DataCursorPtr cursor_ptr;
  cursor_bindings_.AddBinding(cursor, mojo::MakeRequest(&cursor_ptr));
  return cursor_ptr;
}

common::mojom::SQLCursorPtr StorageContext::CreateSQLBinding(StorageSQLCursor* cursor) {
  common::mojom::SQLCursorPtr cursor_ptr;
  sql_cursor_bindings_.AddBinding(cursor, mojo::MakeRequest(&cursor_ptr));
  return cursor_ptr;
}

int64_t StorageContext::GetAllocatedSize(uint32_t context_id, int32_t req) {
  Volume* volume = domain_->main_volume();//workspace_->volume_storage()->storage_manager()->GetStorage(domain_->name());
  // should not fail. severe logic fault of it does
  DCHECK(volume);
  storage::Storage* storage = volume->volume_storage();
  return storage->GetAllocatedSize();
}
  
void StorageContext::ListShares(uint32_t context_id, int32_t req, base::OnceCallback<void(std::vector<common::mojom::ShareInfoPtr>)> cb) {
  Volume* volume = domain_->main_volume();
  storage::Storage* storage = volume->volume_storage();
  storage->ListEntries(base::Bind(&StorageContext::ListSharesImpl, this, context_id, req, base::Passed(std::move(cb))));
}

void StorageContext::ListShareEntries(uint32_t context_id, int32_t req, const std::string& tid, base::OnceCallback<void(std::vector<common::mojom::ShareStorageEntryPtr>)> cb) {
  Volume* volume = domain_->main_volume();
  storage::Storage* storage = volume->volume_storage();
  storage->ListEntries(base::Bind(&StorageContext::ListShareEntriesImpl, this, context_id, req, tid, base::Passed(std::move(cb))));
}

void StorageContext::ShareExists(uint32_t context_id, int32_t req, const std::string& tid, base::OnceCallback<void(bool)> cb) {
  task_runner_->PostTask(
    FROM_HERE,
    base::Bind(&StorageContext::ShareExistsImpl, this, context_id, req, tid, base::Passed(std::move(cb))));
}

void StorageContext::ShareCreateWithPath(uint32_t context_id, int32_t req, common::mojom::StorageType type, const std::string& name, const std::vector<std::string>& keyspaces, const std::string& source_path, bool in_memory) {
  task_runner_->PostTask(
    FROM_HERE,
    base::Bind(&StorageContext::ShareCreateWithPathImpl, this, context_id, req, type, name, keyspaces, source_path, in_memory));
}

void StorageContext::ShareCreateWithInfohash(uint32_t context_id, int32_t req, common::mojom::StorageType type, const std::string& name, const std::vector<std::string>& keyspaces, const std::string& infohash) {
  task_runner_->PostTask(
    FROM_HERE,
    base::Bind(&StorageContext::ShareCreateWithInfohashImpl, this, context_id, req, type, name, keyspaces, infohash));
}

void StorageContext::ShareAdd(uint32_t context_id, int32_t req, const std::string& tid, const std::string& url) {
  task_runner_->PostTask(
    FROM_HERE,
    base::Bind(&StorageContext::ShareAddImpl, this, tid, url));
}

void StorageContext::ShareOpen(uint32_t context_id, int32_t req, common::mojom::StorageType type, const std::string& tid, bool create_if_not_exists) {
  task_runner_->PostTask(
    FROM_HERE,
    base::Bind(&StorageContext::ShareOpenImpl, this, context_id, req, type, tid, create_if_not_exists));
}

void StorageContext::ShareRead(uint32_t context_id, int32_t req, const std::string& tid, int64_t offset, int64_t size, mojo::ScopedSharedBufferHandle data) {
  task_runner_->PostTask(
    FROM_HERE,
    base::Bind(&StorageContext::ShareReadImpl, this, context_id, req, tid, offset, size, base::Passed(std::move(data))));
}

void StorageContext::ShareWrite(uint32_t context_id, int32_t req, const std::string& tid, int64_t offset, int64_t size, mojo::ScopedSharedBufferHandle data) {
  task_runner_->PostTask(
    FROM_HERE,
    base::Bind(&StorageContext::ShareWriteImpl, this, context_id, req, tid, offset, size, base::Passed(std::move(data))));
}

void StorageContext::ShareClose(uint32_t context_id, int32_t req, const std::string& tid) {
  task_runner_->PostTask(
    FROM_HERE,
    base::Bind(&StorageContext::ShareCloseImpl, this, context_id, req, tid));
}

void StorageContext::ShareDelete(uint32_t context_id, int32_t req, const std::string& tid) {
  task_runner_->PostTask(
    FROM_HERE,
    base::Bind(&StorageContext::ShareDeleteImpl, this, context_id, req, tid));
}

void StorageContext::ShareShare(uint32_t context_id, int32_t req, const std::string& tid) {
  task_runner_->PostTask(
    FROM_HERE,
    base::Bind(&StorageContext::ShareShareImpl, this, tid));
}

void StorageContext::ShareUnshare(uint32_t context_id, int32_t req, const std::string& tid) {
  task_runner_->PostTask(
    FROM_HERE,
    base::Bind(&StorageContext::ShareUnshareImpl, this, tid)); 
}

void StorageContext::ShareSubscribe(uint32_t context_id, int32_t req, const std::string& tid) {
  task_runner_->PostTask(
    FROM_HERE,
    base::Bind(&StorageContext::ShareSubscribeImpl, this, tid));
}

void StorageContext::ShareUnsubscribe(uint32_t context_id, int32_t req, const std::string& tid) {
  task_runner_->PostTask(
    FROM_HERE,
    base::Bind(&StorageContext::ShareUnsubscribeImpl, this, tid));
}

void StorageContext::FileCreate(uint32_t context_id, int32_t req, const std::string& tid, const std::string& file) {
  task_runner_->PostTask(
    FROM_HERE,
    base::Bind(&StorageContext::FileCreateImpl, this, tid, file));
}

void StorageContext::FileAdd(uint32_t context_id, int32_t req, const std::string& tid, const std::string& file, const std::string& path) {
  task_runner_->PostTask(
    FROM_HERE,
    base::Bind(&StorageContext::FileAddImpl, this, tid, file, path));
}

void StorageContext::FileOpen(uint32_t context_id, int32_t req, const std::string& tid, const std::string& file) {
  task_runner_->PostTask(
    FROM_HERE,
    base::Bind(&StorageContext::FileOpenImpl, this, tid, file)); 
}

void StorageContext::FileDelete(uint32_t context_id, int32_t req, const std::string& tid, const std::string& file) {
  task_runner_->PostTask(
    FROM_HERE,
    base::Bind(&StorageContext::FileDeleteImpl, this, tid, file));
}

void StorageContext::FileRename(uint32_t context_id, int32_t req, const std::string& tid, const std::string& input, const std::string& output) {
  task_runner_->PostTask(
    FROM_HERE,
    base::Bind(&StorageContext::FileRenameImpl, this, tid, input, output));
}

void StorageContext::FileRead(uint32_t context_id, int32_t req, const std::string& tid, const std::string& file, int64_t offset, int64_t size, mojo::ScopedSharedBufferHandle data) {
  task_runner_->PostTask(
    FROM_HERE,
    base::Bind(&StorageContext::FileReadImpl, this, context_id, req, tid, file, offset, size, base::Passed(std::move(data))));
}

void StorageContext::FileReadOnce(uint32_t context_id, int32_t req, const std::string& tid, const std::string& file, int64_t offset, int64_t size) {
  task_runner_->PostTask(
    FROM_HERE,
    base::Bind(&StorageContext::FileReadOnceImpl, this, context_id, req, tid, file, offset, size));
}

void StorageContext::FileWrite(uint32_t context_id, int32_t req, const std::string& tid, const std::string& file, int64_t offset, int64_t size, mojo::ScopedSharedBufferHandle data) {
  task_runner_->PostTask(
    FROM_HERE,
    base::Bind(&StorageContext::FileWriteImpl, this, context_id, req, tid, file, offset, size, base::Passed(std::move(data))));
}

void StorageContext::FileWriteOnce(uint32_t context_id, int32_t req, const std::string& tid, const std::string& file, int64_t offset, int64_t size, const std::vector<uint8_t>& data) {
  task_runner_->PostTask(
    FROM_HERE,
    base::Bind(&StorageContext::FileWriteOnceImpl, this, context_id, req, tid, file, offset, size, data));
}

void StorageContext::FileClose(uint32_t context_id, int32_t req, const std::string& tid, const std::string& file) {
  task_runner_->PostTask(
    FROM_HERE,
    base::Bind(&StorageContext::FileCloseImpl, this, tid, file));
}

void StorageContext::DataClose(uint32_t context_id, int32_t req, const std::string& tid) {
  task_runner_->PostTask(
    FROM_HERE,
    base::Bind(&StorageContext::DataCloseImpl, this, context_id, req, tid));
}

void StorageContext::DataDrop(uint32_t context_id, int32_t req, const std::string& tid) {
  task_runner_->PostTask(
    FROM_HERE,
    base::Bind(&StorageContext::DataDropImpl, this, context_id, req, tid));
}

void StorageContext::DataCreateKeyspace(uint32_t context_id, int32_t req, const std::string& tid, const std::string& keyspace) {
  task_runner_->PostTask(
    FROM_HERE,
    base::Bind(&StorageContext::DataCreateKeyspaceImpl, this, context_id, req, tid, keyspace));
}

void StorageContext::DataDeleteKeyspace(uint32_t context_id, int32_t req, const std::string& tid, const std::string& keyspace) {
  task_runner_->PostTask(
    FROM_HERE,
    base::Bind(&StorageContext::DataDeleteKeyspaceImpl, this, context_id, req, tid, keyspace));
}

void StorageContext::DataListKeyspaces(uint32_t context_id, int32_t req, const std::string& tid) {
  task_runner_->PostTask(
    FROM_HERE,
    base::Bind(&StorageContext::DataListKeyspacesImpl, this, context_id, req, tid)); 
}

void StorageContext::DataPut(uint32_t context_id, int32_t req, const std::string& tid, const std::string& keyspace, const std::string& key, int64_t size, mojo::ScopedSharedBufferHandle data) {
  task_runner_->PostTask(
    FROM_HERE,
    base::Bind(&StorageContext::DataPutImpl, this, context_id, req, tid, keyspace, key, size, base::Passed(std::move(data))));
}

void StorageContext::DataGet(uint32_t context_id, int32_t req, const std::string& tid, const std::string& keyspace, const std::string& key, int64_t size, mojo::ScopedSharedBufferHandle data) {
  task_runner_->PostTask(
    FROM_HERE,
    base::Bind(&StorageContext::DataGetImpl, this, context_id, req, tid, keyspace, key, size, base::Passed(std::move(data))));
}

void StorageContext::DataGetOnce(uint32_t context_id, int32_t req, const std::string& tid, const std::string& keyspace, const std::string& key) {
  task_runner_->PostTask(
    FROM_HERE,
    base::Bind(&StorageContext::DataGetOnceImpl, this, context_id, req, tid, keyspace, key));
}

void StorageContext::DataDelete(uint32_t context_id, int32_t req, const std::string& tid, const std::string& keyspace, const std::string& key) {
  task_runner_->PostTask(
    FROM_HERE,
    base::Bind(&StorageContext::DataDeleteImpl, this, context_id, req, tid, keyspace, key));
}

void StorageContext::DataDeleteAll(uint32_t context_id, int32_t req, const std::string& tid, const std::string& keyspace) {
  task_runner_->PostTask(
    FROM_HERE,
    base::Bind(&StorageContext::DataDeleteAllImpl, this, context_id, req, tid, keyspace));
}

void StorageContext::DataCreateCursor(uint32_t context_id, int32_t req, const std::string& tid, const std::string& keyspace, common::mojom::Order order, bool write, common::mojom::StorageDispatcherHost::DataCreateCursorCallback callback) {
  task_runner_->PostTask(
    FROM_HERE,
    base::BindOnce(&StorageContext::DataCreateCursorImpl, this, context_id, req, tid, keyspace, order, write, base::Passed(std::move(callback))));
}

void StorageContext::DataExecuteQuery(uint32_t context_id, int32_t req, const std::string& tid, const std::string& query, common::mojom::StorageDispatcherHost::DataExecuteQueryCallback callback) {
  task_runner_->PostTask(
    FROM_HERE,
    base::BindOnce(&StorageContext::DataExecuteQueryImpl, this, context_id, req, tid, query, base::Passed(std::move(callback))));
}

void StorageContext::IndexResolveId(uint32_t context_id, int32_t req, const std::string& address) {
  task_runner_->PostTask(
    FROM_HERE,
    base::Bind(&StorageContext::IndexResolveIdImpl, this, context_id, req, address)); 
}

/* 
 * Implementations
 */

void StorageContext::ListSharesImpl(uint32_t context_id, int32_t req, base::OnceCallback<void(std::vector<common::mojom::ShareInfoPtr>)> cb, std::vector<std::unique_ptr<storage_proto::Info>> entries, int64_t result_code) {
  std::vector<common::mojom::ShareInfoPtr> result;  
  
  for (auto it = entries.begin(); it != entries.end(); ++it) {
    common::mojom::ShareInfoPtr info = common::mojom::ShareInfo::New();
    storage_proto::Info* current = it->get();
    // fill info
    info->uuid = base::UUID(reinterpret_cast<const uint8_t *>(current->id().data())).to_string();
    info->path = current->path();
    info->kind = static_cast<common::mojom::InfoKind>(current->kind());
    info->state = static_cast<common::mojom::InfoState>(current->state());
    info->root_hash = base::HexEncode(current->root_hash().data(), current->root_hash().size());
    info->size = current->length();
    info->block_size = current->piece_length();
    info->blocks = current->piece_count();
    info->created_time = current->creation_date();
    info->entry_count = current->inode_count();
    // fill entries
    for (int i = 0; i < current->inode_count(); i++) {
      common::mojom::ShareStorageEntryPtr entry = common::mojom::ShareStorageEntry::New();
      const storage_proto::InfoInode& current_entry = current->inodes(i);
      entry->name = current_entry.name();
      entry->path = current_entry.path();
      entry->size = current_entry.length();
      entry->start_block = current_entry.piece_start();
      entry->end_block = current_entry.piece_end();
      entry->blocks = current_entry.piece_count();
      entry->content_type = current_entry.content_type();
      entry->created_time = current_entry.creation_date();
      info->entries.push_back(std::move(entry));
    }
    result.push_back(std::move(info));
  }
  std::move(cb).Run(std::move(result));
}

void StorageContext::ListShareEntriesImpl(uint32_t context_id, int32_t req, const std::string& tid, base::OnceCallback<void(std::vector<common::mojom::ShareStorageEntryPtr>)> cb, std::vector<std::unique_ptr<storage_proto::Info>> entries, int64_t result_code) {
  std::vector<common::mojom::ShareStorageEntryPtr> result;  

  bool ok = false;
  base::UUID uuid = base::UUID::from_string(tid, &ok);
  
  Share* parent = workspace_->share_manager()->GetShare(uuid);//domain_->name(), uuid);
  // theres a share with this name? and it is the database kind? 
  //if (t && t->info().kind() == storage_proto::INFO_KVDB) {
  if (!parent) {
    //DLOG(INFO) << "StorageContext::ShareExist: share not found for '" << tid << "'";
    std::move(cb).Run(std::move(result));
    return;
  }

  std::string parent_uuid_bytes = parent->id().string();
  for (auto it = entries.begin(); it != entries.end(); ++it) {
    storage_proto::Info* current = it->get();
    for (int i = 0; i < current->inode_count(); i++) {
      const storage_proto::InfoInode& current_entry = current->inodes(i);
      if (current_entry.parent() == parent_uuid_bytes) {
        common::mojom::ShareStorageEntryPtr entry = common::mojom::ShareStorageEntry::New();
        entry->name = current_entry.name();
        entry->path = current_entry.path();
        entry->size = current_entry.length();
        entry->start_block = current_entry.piece_start();
        entry->end_block = current_entry.piece_end();
        entry->blocks = current_entry.piece_count();
        entry->content_type = current_entry.content_type();
        entry->created_time = current_entry.creation_date();
        result.push_back(std::move(entry));
      }
    }
  }
  std::move(cb).Run(std::move(result));
}

void StorageContext::ShareExistsImpl(uint32_t context_id, int32_t req, const std::string& tid, base::OnceCallback<void(bool)> cb) {
  base::UUID uuid;
  bool exists = false;
  // storage::StorageManager* manager = workspace_->volume_storage()->storage_manager();
  // storage::Storage* storage = manager->GetStorage(domain_->name());
  // if (storage && storage->GetUUID(tid, &uuid)) {
  //   exists = true;
  // }
  ShareManager* share_manager = workspace_->share_manager();

  if (share_manager->GetUUID(domain_->name(), tid, &uuid)) {
    exists = true;
  }

  HostThread::PostTask(
    HostThread::IO,
    FROM_HERE,
    base::BindOnce(
      &StorageContext::ReplyShareExistsOnIOThread,
      this,
      context_id, 
      req, 
      base::Passed(std::move(uuid)), 
      base::Passed(std::move(cb)),
      exists));
}

void StorageContext::ShareCreateWithPathImpl(uint32_t context_id, int32_t req, common::mojom::StorageType type, const std::string& name, const std::vector<std::string>& keyspaces, const std::string& source_path, bool in_memory) {
  //base::UUID uuid = base::UUID::generate();
  //storage::StorageManager* manager = workspace_->volume_storage()->storage_manager();
  ShareManager* share_manager = workspace_->share_manager();
  storage_proto::InfoKind share_kind = ToInfoKind(type);
  // if source_path is not empty, we create the share with AddEntry
  // instead, so it will be populated with the files pointed by source path
  if (share_kind == storage_proto::INFO_FILE && !source_path.empty()) {
#if defined(OS_WIN)
    base::FilePath path(base::ASCIIToUTF16(source_path));
#else
    base::FilePath path(source_path);
#endif
    // if (!path.is_valid()) {
    //   ReplyShareCreate(context_id, req, std::string(reinterpret_cast<const char *>(uuid.data), 16), net::ERR_FAILED);
    //   return;
    // }
    base::UUID uuid = base::UUID::generate();
    share_manager->AddEntry(
      domain_->name(),
      path,
      uuid,
      base::Bind(&StorageContext::ReplyShareCreate, 
        this, 
        context_id, 
        req, 
        base::Passed(std::move(uuid))),
      name);
  } else {
    base::UUID uuid = base::UUID::generate();
    share_manager->CreateShare(
      domain_->name(), 
      share_kind,
      uuid, 
      name, 
      keyspaces,
      in_memory,
      base::Bind(&StorageContext::ReplyShareCreate, 
        this, 
        context_id, 
        req, 
        base::Passed(std::move(uuid))));
  }
}

void StorageContext::ShareCreateWithInfohashImpl(uint32_t context_id, int32_t req, common::mojom::StorageType type, const std::string& name, const std::vector<std::string>& keyspaces, const std::string& infohash) {
  //storage::StorageManager* manager = workspace_->volume_storage()->storage_manager();
  ShareManager* share_manager = workspace_->share_manager();
  storage_proto::InfoKind share_kind = ToInfoKind(type);
  base::UUID uuid = base::UUID::generate();
  share_manager->CreateShareWithInfohash(
    domain_->name(), 
    share_kind,
    uuid, 
    name, 
    infohash,
    base::Bind(&StorageContext::ReplyShareCreate, 
      this, 
      context_id, 
      req, 
      base::Passed(std::move(uuid))));
}

void StorageContext::ShareAddImpl(const std::string& tid, const std::string& url) {
  
}

void StorageContext::ShareOpenImpl(uint32_t context_id, int32_t req, common::mojom::StorageType type, const std::string& tid, bool create_if_not_exists) {
  base::UUID uuid;
  //storage::StorageManager* manager = workspace_->volume_storage()->storage_manager();
  DLOG(INFO) << "StorageContext::ShareOpen: opening share for '" << tid << "'";
  ShareManager* share_manager = workspace_->share_manager();
  bool found = share_manager->GetUUID(domain_->name(), tid, &uuid);
  // it might be the system databases, so try it
  if (!found) {
    found = workspace_->storage_manager().GetUUID(
      workspace_->workspace_storage()->workspace_disk_name(), 
      tid, 
      &uuid);
  }
  if (found) {
    DLOG(INFO) << "StorageContext::ShareOpen: opening share for '" << tid << "' => found => " << uuid.to_string();
    share_manager->OpenShare(
      domain_->name(),
      uuid,
      base::Bind(&StorageContext::ReplyShareOpen, 
        this, 
        context_id,
        req, 
        base::Passed(std::move(uuid))));
  } else if (create_if_not_exists) {
    std::vector<std::string> keyspaces;
    uuid = base::UUID::generate();
    share_manager->CreateShare(
      domain_->name(), 
      ToInfoKind(type),
      uuid, 
      tid, 
      keyspaces,
      false,
      base::Bind(&StorageContext::ReplyShareCreate, 
        this, 
        context_id, 
        req, 
        base::Passed(std::move(uuid))));
  } else { // share does not exists, and create_if_not_exists = false. just fail
    DLOG(INFO) << "StorageContext::ShareOpen: opening share for '" << tid << "' => NOT found";
    ReplyShareOpen(context_id, req, std::move(uuid), net::ERR_FAILED);
  }
}

void StorageContext::ShareReadImpl(uint32_t context_id, int32_t req, const std::string& tid, int64_t offset, int64_t size, mojo::ScopedSharedBufferHandle data) {
  // get the opened share from the cache
  int64_t r = net::OK;
  int64_t bytes = 0;

  //storage::StorageManager* manager = workspace_->volume_storage()->storage_manager();
  ShareManager* share_manager = workspace_->share_manager();
  base::UUID uuid;//(reinterpret_cast<const uint8_t *>(tid.data()));
  if (!share_manager->GetUUID(domain_->name(), tid, &uuid)) {
    //DLOG(INFO) << "reading share '" << tid << "' failed";
    r = net::ERR_FAILED;
  }
  Share* share = share_manager->GetShare(uuid);
  if (!share) {
    // open or create should have been called first
    // if is not cached in the share manager it means
    // none were called
    r = net::ERR_FAILED;
  } else {
    // TODO: do we want to map the whole thing on the shared buffer?
    //       what about big files?
    mojo::ScopedSharedBufferMapping mapping = data->MapAtOffset(size, offset);
    r = share->Read(mapping.get(), offset, size);
    if (r == net::OK) {
      bytes = size;
    }
  }
  HostThread::PostTask(
    HostThread::IO,
    FROM_HERE,
    base::Bind(&StorageContext::ReplyShareRead, this, context_id, req, base::Passed(std::move(uuid)), r, bytes));
}

void StorageContext::ShareWriteImpl(uint32_t context_id, int32_t req, const std::string& tid, int64_t offset, int64_t size, mojo::ScopedSharedBufferHandle data) {
  int64_t r = net::OK;
  int64_t bytes = 0;

  base::UUID uuid(reinterpret_cast<const uint8_t *>(tid.data()));
  Share* share = workspace_->share_manager()->GetShare(uuid);
  if (!share) {
    // open or create should have been called first
    // if is not cached in the share manager it means
    // none were called
    r = net::ERR_FAILED;
  } else {
    // TODO: do we want to map the whole thing on the shared buffer?
    //       what about big files?
    mojo::ScopedSharedBufferMapping mapping = data->MapAtOffset(size, offset);
    r = share->Write(mapping.get(), offset, size);
    if (r == net::OK) {
      bytes = size;
    }
  }
  HostThread::PostTask(
    HostThread::IO,
    FROM_HERE,
    base::Bind(&StorageContext::ReplyShareWrite, this, context_id, req, base::Passed(std::move(uuid)), r, bytes)); 
}

void StorageContext::ShareCloseImpl(uint32_t context_id, int32_t req, const std::string& tid) {
  int64_t r = net::OK;
  //base::UUID uuid(reinterpret_cast<const uint8_t *>(tid.data()));
  //scoped_refptr<storage::Share> share = workspace_->volume_storage()->storage_manager()->share_manager()->GetShare(uuid);
  //storage::StorageManager* manager = workspace_->volume_storage()->storage_manager();
  base::UUID uuid;
  ShareManager* share_manager = workspace_->share_manager();
  //DLOG(INFO) << "trying to close share named '" << tid << "'";
  if (!share_manager->GetUUID(domain_->name(), tid, &uuid)) {
    //DLOG(INFO) << "closing share '" << tid << "' failed";
    r = net::ERR_FAILED;
  }
  Share* share = share_manager->GetShare(uuid);
  if (!share) {
    r = net::ERR_FAILED;
  } else {
    r = share->Close();
  }
  HostThread::PostTask(
    HostThread::IO,
    FROM_HERE,
    base::BindOnce(
      &StorageContext::ReplyShareClose,
      this,
      context_id, 
      req, 
      base::Passed(std::move(uuid)),
      r));
}

void StorageContext::ShareDeleteImpl(uint32_t context_id, int32_t req, const std::string& tid) {
  base::UUID uuid(reinterpret_cast<const uint8_t *>(tid.data()));
  int64_t r = workspace_->share_manager()->DropShare(uuid) ? net::OK : net::ERR_FAILED;
  HostThread::PostTask(
    HostThread::IO,
    FROM_HERE,
    base::BindOnce(
      &StorageContext::ReplyShareDelete,
      this,
      context_id, 
      req, 
      base::Passed(std::move(uuid)),
      r));
}

void StorageContext::ShareShareImpl(const std::string& tid) {
  
}

void StorageContext::ShareUnshareImpl(const std::string& tid) {
  
}

void StorageContext::ShareSubscribeImpl(const std::string& tid) {
  
}

void StorageContext::ShareUnsubscribeImpl(const std::string& tid) {
  
}

void StorageContext::FileCreateImpl(const std::string& tid, const std::string& file) {
  
}

void StorageContext::FileAddImpl(const std::string& tid, const std::string& file, const std::string& path) {
  
}

void StorageContext::FileOpenImpl(const std::string& tid, const std::string& file) {
  
}

void StorageContext::FileDeleteImpl(const std::string& tid, const std::string& file) {
  
}

void StorageContext::FileRenameImpl(const std::string& tid, const std::string& input, const std::string& output) {
  
}

void StorageContext::FileReadOnceImpl(uint32_t context_id, int32_t req, const std::string& tid, const std::string& file, int64_t offset, int64_t size) {
//  int64_t r = net::OK;
  mojo::ScopedSharedBufferHandle data; //= mojo::SharedBufferHandle::Create(data_view.size());
  //mojo::ScopedSharedBufferMapping mapping = data->Map(data_view.size());
  // copy to the shared mem
  //memcpy(mapping.get(), data_view.data(), data_view.size());
  //bytes = data_view.size();
  //storage::StorageManager* manager = workspace_->volume_storage()->storage_manager();
  ShareManager* share_manager = workspace_->share_manager();
  // storage::Storage* storage = share_manager->GetStorage(domain_->name());
  // if (!storage) {
  //   OnFileReadOnce(context_id, req, base::UUID(), file, 0, mojo::ScopedSharedBufferHandle(), net::ERR_FAILED);
  //   return;
  // }
  base::UUID uuid;
  //DLOG(INFO) << "trying to read share named '" << tid << "'";
  if (!share_manager->GetUUID(domain_->name(), tid, &uuid)) {
    OnFileReadOnce(context_id, req, base::UUID(), file, 0, mojo::ScopedSharedBufferHandle(), net::ERR_FAILED);
    return;
  }
  Share* share = share_manager->GetShare(uuid);
  if (!share) {
    OnFileReadOnce(context_id, req, std::move(uuid), file, 0, mojo::ScopedSharedBufferHandle(), net::ERR_FAILED);
    return;
  }
  share->ReadEntryFileAsSharedBuffer(
#if defined(OS_WIN)
    base::FilePath(base::ASCIIToUTF16(file)),
#else
    base::FilePath(file),
#endif
    base::Bind(&StorageContext::OnFileReadOnce, this, context_id, req, base::Passed(std::move(uuid)), file));
}

void StorageContext::OnFileReadOnce(uint32_t context_id, int32_t req, base::UUID uuid, const std::string& file, int64_t file_size, mojo::ScopedSharedBufferHandle file_data, int64_t result) {
  HostThread::PostTask(
    HostThread::IO,
    FROM_HERE,
    base::Bind(&StorageContext::ReplyFileReadOnce, this, context_id, req, base::Passed(std::move(uuid)), file, result, file_size, base::Passed(std::move(file_data))));
}

void StorageContext::FileWriteImpl(uint32_t context_id, int32_t req, const std::string& tid, const std::string& file, int64_t offset, int64_t size, mojo::ScopedSharedBufferHandle data) {
  HostThread::PostTask(
    HostThread::IO,
    FROM_HERE,
    base::Bind(&StorageContext::ReplyFileWrite, this, context_id, req, base::Passed(base::UUID(reinterpret_cast<const uint8_t *>(tid.data()))), file, net::OK, 0));  
}

void StorageContext::FileWriteOnceImpl(uint32_t context_id, int32_t req, const std::string& tid, const std::string& file, int64_t offset, int64_t size, const std::vector<uint8_t>& data) {
  //int64_t r = net::OK;
  ShareManager* share_manager = workspace_->share_manager();
  bool ok = false;
  base::UUID uuid = base::UUID::from_string(tid, &ok);
  if (!ok) {
    OnFileWriteOnce(context_id, req, tid, file, net::ERR_FAILED, 0);
    return;
  }
  Share* share = share_manager->GetShare(uuid);
  if (!share) {
    OnFileWriteOnce(context_id, req, tid, file, net::ERR_FAILED, 0);
    return;
  }
  share->WriteEntryFile(
#if defined(OS_WIN)
    base::FilePath(base::ASCIIToUTF16(file)),
#else
    base::FilePath(file),
#endif
     offset,
     size,
     data,
     base::Bind(&StorageContext::OnFileWriteOnce, this, context_id, req, tid, file, net::OK));
}

void StorageContext::OnFileWriteOnce(uint32_t context_id, int32_t req, const std::string& tid, const std::string& file, int64_t result, int64_t bytes_written) {
  HostThread::PostTask(
    HostThread::IO,
    FROM_HERE,
    base::Bind(&StorageContext::ReplyFileWriteOnce, this, context_id, req, base::Passed(base::UUID(reinterpret_cast<const uint8_t *>(tid.data()))), file, (bytes_written == net::ERR_FAILED ? bytes_written : result), bytes_written));
}

void StorageContext::FileReadImpl(uint32_t context_id, int32_t req, const std::string& tid, const std::string& file, int64_t offset, int64_t size, mojo::ScopedSharedBufferHandle data) {
  HostThread::PostTask(
    HostThread::IO,
    FROM_HERE,
    base::Bind(&StorageContext::ReplyFileRead, this, context_id, req, base::Passed(base::UUID(reinterpret_cast<const uint8_t *>(tid.data()))), file, net::OK, 0));  
}

void StorageContext::FileCloseImpl(const std::string& tid, const std::string& file) {
  
}

// void StorageContext::DataOpenImpl(uint32_t context_id, int32_t req, const std::string& tid) {
//   storage::StorageManager* storage = workspace_->volume_storage()->storage_manager();
//   scoped_refptr<storage::Share> t = storage->OpenShare(
//     domain_->name(), 
//     tid,
//     base::Bind(&StorageContext::ReplyDataOpen, this, context_id, req, tid));
// }

void StorageContext::DataCloseImpl(uint32_t context_id, int32_t req, const std::string& tid) {
  base::UUID uuid(reinterpret_cast<const uint8_t *>(tid.data()));
  ShareManager* share_manager = workspace_->share_manager();
  share_manager->CloseDatabase(
    domain_->name(),
    uuid,
    base::Bind(&StorageContext::ReplyDataClose, 
      this, 
      context_id, 
      req, 
      base::Passed(std::move(uuid))));
}

// int64_t StorageContext::DataCreateImpl(const std::string& tid) {
//   return net::OK;
// }

void StorageContext::DataDropImpl(uint32_t context_id, int32_t req, const std::string& tid) {
  /*
   * A drop table is actually a delete share where the kind must be equals data
   */
  int64_t r = net::OK;
  base::UUID uuid(reinterpret_cast<const uint8_t *>(tid.data()));
  ShareManager* share_manager = workspace_->share_manager();
  Share* share = share_manager->GetShare(uuid);
  if (!share || share->info().kind() != storage_proto::INFO_KVDB) {
    r = net::ERR_FAILED;
  } else {
    r = share_manager->DropShare(share) ? net::OK : net::ERR_FAILED;
  }
  HostThread::PostTask(
    HostThread::IO,
    FROM_HERE,
    base::BindOnce(
      &StorageContext::ReplyDataDrop,
      this,
      context_id, 
      req, 
      base::Passed(std::move(uuid)),
      r));  
}

void StorageContext::DataCreateKeyspaceImpl(uint32_t context_id, int32_t req, const std::string& tid, const std::string& keyspace) {
  int64_t r = net::OK;
  base::UUID uuid(reinterpret_cast<const uint8_t *>(tid.data()));
  ShareManager* share_manager = workspace_->share_manager();
  Share* share = share_manager->GetShare(uuid);
  if (!share) {
    r = net::ERR_FAILED;
  } else if (!share->is_open() || !share->db_is_open()) {
    r = net::ERR_FAILED;
  } else {
    bool created = share->db()->CreateKeyspace(keyspace);
    r = created ? net::OK : net::ERR_FAILED;
  }
  HostThread::PostTask(
    HostThread::IO,
    FROM_HERE,
    base::Bind(&StorageContext::ReplyDataCreateKeyspace, 
      this, 
      context_id, 
      req, 
      base::Passed(std::move(uuid)), 
      keyspace,
      r));
}

void StorageContext::DataDeleteKeyspaceImpl(uint32_t context_id, int32_t req, const std::string& tid, const std::string& keyspace) {
  int64_t r = net::OK;
  base::UUID uuid(reinterpret_cast<const uint8_t *>(tid.data()));
  ShareManager* share_manager = workspace_->share_manager();
  Share* share = share_manager->GetShare(uuid);
  if (!share) {
    r = net::ERR_FAILED;
  } else if (!share->is_open() || !share->db_is_open()) {
    r = net::ERR_FAILED;
  } else {
    bool created = share->db()->DropKeyspace(keyspace);
    r = created ? net::OK : net::ERR_FAILED;
  }
  HostThread::PostTask(
    HostThread::IO,
    FROM_HERE,
    base::Bind(&StorageContext::ReplyDataDeleteKeyspace, 
      this, 
      context_id, 
      req, 
      base::Passed(std::move(uuid)), 
      keyspace,
      r)); 
}

void StorageContext::DataListKeyspacesImpl(uint32_t context_id, int32_t req, const std::string& tid) {
  int64_t r = net::OK;
  base::UUID uuid(reinterpret_cast<const uint8_t *>(tid.data()));
  std::vector<std::string> keyspaces;
  ShareManager* share_manager = workspace_->share_manager();
  Share* share = share_manager->GetShare(uuid);
  if (!share) {
    r = net::ERR_FAILED;
  } else if (!share->is_open() || !share->db_is_open()) {
    r = net::ERR_FAILED;
  } else {
    share->db()->GetKeyspaceList(&keyspaces);
  }
  
  HostThread::PostTask(
    HostThread::IO,
    FROM_HERE,
    base::Bind(&StorageContext::ReplyDataListKeyspaces, 
      this, 
      context_id, 
      req, 
      base::Passed(std::move(uuid)),
      r,
      base::Passed(std::move(keyspaces))));
}

void StorageContext::DataDeleteImpl(uint32_t context_id, int32_t req, const std::string& tid, const std::string& keyspace, const std::string& key) {
  int64_t r = net::OK;
  base::UUID uuid(reinterpret_cast<const uint8_t *>(tid.data()));
  ShareManager* share_manager = workspace_->share_manager();
  Share* share = share_manager->GetShare(uuid);
  if (!share) {
    r = net::ERR_FAILED;
  } else if (!share->is_open() || !share->db_is_open()) {
    r = net::ERR_FAILED;
  } else {
    storage::Transaction* tr = share->db()->Begin(true);
    storage::Cursor* cursor = tr->CreateCursor(keyspace);
    if (cursor) {
      bool match = false;
      cursor->SeekTo(key, storage::Seek::EQ, &match);
      if (match) {
        cursor->Delete();
      }    
    } else {
      r = net::ERR_FAILED;
    }
    r == net::OK ? tr->Commit() : tr->Rollback();
  }
  HostThread::PostTask(
    HostThread::IO,
    FROM_HERE,
    base::Bind(&StorageContext::ReplyDataDelete,
      this,
      context_id,
      req, 
      base::Passed(std::move(uuid)),
      keyspace,
      r));
}

void StorageContext::DataDeleteAllImpl(uint32_t context_id, int32_t req, const std::string& tid, const std::string& keyspace) {
  int64_t r = net::OK;
  base::UUID uuid(reinterpret_cast<const uint8_t *>(tid.data()));
  ShareManager* share_manager = workspace_->share_manager();
  Share* share = share_manager->GetShare(uuid);
  if (!share) {
    r = net::ERR_FAILED;
  } else if (!share->is_open() || !share->db_is_open()) {
    r = net::ERR_FAILED;
  } else {
    storage::Transaction* tr = share->db()->Begin(true);
    storage::Cursor* cursor = tr->CreateCursor(keyspace);
    if (cursor) {
      cursor->First();
      while (cursor->IsValid()) {
        cursor->Delete();
        cursor->Next();
      }
      tr->Commit();
    } else {
      r = net::ERR_FAILED;
      tr->Rollback();
    }
  }
  HostThread::PostTask(
    HostThread::IO,
    FROM_HERE,
    base::Bind(&StorageContext::ReplyDataDeleteAll, 
      this, 
      context_id, 
      req, 
      base::Passed(std::move(uuid)), 
      keyspace,
      r));  
}

void StorageContext::DataPutImpl(uint32_t context_id, int32_t req, const std::string& tid, const std::string& keyspace, const std::string& key, int64_t size, mojo::ScopedSharedBufferHandle data) {
  int64_t r = net::OK;
  int64_t bytes = size;
  base::UUID uuid;
  ShareManager* share_manager = workspace_->share_manager();
  if (!share_manager->GetUUID(domain_->name(), tid, &uuid)) {
    r = net::ERR_FAILED;
    bytes = 0;
  } else {
    //storage::Storage* storage = share_manager->GetStorage(domain_->name());
    //DCHECK(storage);
    //scoped_refptr<storage::Share> share = manager->share_manager()->GetOrCreateShare(storage, uuid);
    //Share* share = share_manager->torrent_manager()->GetOrCreateShare(storage, uuid);
    Share* share = share_manager->GetShare(uuid);
    if (!share) {
      r = net::ERR_FAILED;
      bytes = 0;
    } else if (!share->is_open() || !share->db_is_open()) {
      r = net::ERR_FAILED;
      bytes = 0;
    } else {
      scoped_refptr<ShareDatabase> db = share->db();
      mojo::ScopedSharedBufferMapping mapping = data->Map(size);
      storage::Transaction* tr = db->Begin(true);
      auto kv = std::make_pair(key, base::StringPiece(static_cast<const char *>(mapping.get()), size));
      storage::Cursor* cursor = tr->CreateCursor(keyspace);
      if (!cursor) {
        //DLOG(INFO) << "Database::Put: cursor for keyspace " << keyspace << " failed";
        r = net::ERR_FAILED;
      } else {
        r = cursor->Insert(kv) 
          ? net::OK 
          : net::ERR_FAILED;
      }
      r == net::OK ? tr->Commit() : tr->Rollback();
    }
  }
  HostThread::PostTask(
    HostThread::IO,
    FROM_HERE,
    base::Bind(&StorageContext::ReplyDataPut, 
      this, 
      context_id, 
      req, 
      base::Passed(std::move(uuid)), 
      keyspace, 
      r, 
      0));  
}

void StorageContext::DataGetOnceImpl(uint32_t context_id, int32_t req, const std::string& tid, const std::string& keyspace, const std::string& key) {
  int64_t r = net::OK;
  int64_t bytes = 0;
  mojo::ScopedSharedBufferHandle data;
  base::UUID uuid;
  ShareManager* share_manager = workspace_->share_manager();
  if (!share_manager->GetUUID(domain_->name(), tid, &uuid)) {
    r = net::ERR_FAILED;
    bytes = 0;
  } else {
    //storage::Storage* storage = manager->GetStorage(domain_->name());
    //DCHECK(storage);
    Share* share = share_manager->GetShare(uuid);
    if (!share) {
      r = net::ERR_FAILED;
    } else if (!share->is_open() || !share->db_is_open()) {
      r = net::ERR_FAILED;
    } else {
      base::StringPiece data_view;
      storage::Transaction* tr = share->db()->Begin(false);
      storage::Cursor* cursor = tr->CreateCursor(keyspace);
      if (!cursor) {
        tr->Rollback();
        r = net::ERR_FAILED;
      } else {
        if (cursor->GetValue(key, &data_view)) {
          // allocate the shared memory here (we only know the size now)
          DCHECK(data_view.size() > 0);
          data = mojo::SharedBufferHandle::Create(data_view.size());
          mojo::ScopedSharedBufferMapping mapping = data->Map(data_view.size());
          // copy to the shared mem
          memcpy(mapping.get(), data_view.data(), data_view.size());
          bytes = data_view.size();
        } else {
          r = net::ERR_FAILED;
        }
        r == net::OK ? tr->Commit() : tr->Rollback();
      }
    }
  }
  HostThread::PostTask(
    HostThread::IO,
    FROM_HERE,
    base::Bind(&StorageContext::ReplyDataGetOnce, this, context_id, req, base::Passed(std::move(uuid)), keyspace, r, bytes, base::Passed(std::move(data))));
}

void StorageContext::DataGetImpl(uint32_t context_id, int32_t req, const std::string& tid, const std::string& keyspace, const std::string& key, int64_t size, mojo::ScopedSharedBufferHandle data) {
  HostThread::PostTask(
    HostThread::IO,
    FROM_HERE,
    base::Bind(&StorageContext::ReplyDataGet, 
      this, 
      context_id, 
      req, 
      base::Passed(base::UUID(reinterpret_cast<const uint8_t *>(tid.data()))), 
      keyspace, 
      0, 
      0));
}

void StorageContext::DataCreateCursorImpl(uint32_t context_id, int32_t req, const std::string& tid, const std::string& keyspace, common::mojom::Order order, bool write, common::mojom::StorageDispatcherHost::DataCreateCursorCallback callback) {
  //storage::StorageManager* manager = workspace_->volume_storage()->storage_manager();
  ShareManager* share_manager = workspace_->share_manager();
  common::mojom::DataCursorPtr cursor_proxy;
  bool ok = false;
  base::UUID id = base::UUID::from_string(tid, &ok);
  Share* share = share_manager->GetShare(id);
  if (!share) {
    //DLOG(INFO) << "StorageContext::DataCreateCursorImpl: error => no share found with name " << tid;
    HostThread::PostTask(
      HostThread::IO,
      FROM_HERE,
      base::BindOnce(
        &StorageContext::ReplyCreateCursor, 
        this, 
        base::Passed(std::move(callback)),
        false, 
        base::Passed(std::move(cursor_proxy))));
    return;
  }

  if (!share->is_open() || !share->db_is_open()) {
    //DLOG(INFO) << "StorageContext::DataCreateCursorImpl: error => no share db for " << tid << " is not open" ;
    HostThread::PostTask(
      HostThread::IO,
      FROM_HERE,
      base::BindOnce(
        &StorageContext::ReplyCreateCursor, 
        this, 
        base::Passed(std::move(callback)),
        false, 
        base::Passed(std::move(cursor_proxy))));
    return; 
  }
  storage::Transaction* trans = share->db()->Begin(write);
  if (!trans) {
    //DLOG(INFO) << "StorageContext::DataCreateCursorImpl: error => transaction failed for " << tid;
    HostThread::PostTask(
      HostThread::IO,
      FROM_HERE,
      base::BindOnce(
        &StorageContext::ReplyCreateCursor, 
        this, 
        base::Passed(std::move(callback)),
        false,
        base::Passed(std::move(cursor_proxy))));
    return; 
  }

  auto cursor = std::make_unique<StorageDataCursor>(trans, write);
  if (!cursor->Init(keyspace, static_cast<storage::Order>(order))) {
    //DLOG(INFO) << "StorageContext::DataCreateCursorImpl: error => cursor init failed for " << tid;
    HostThread::PostTask(
      HostThread::IO,
      FROM_HERE,
      base::BindOnce(
        &StorageContext::ReplyCreateCursor, 
        this, 
        base::Passed(std::move(callback)),
        false,
        base::Passed(std::move(cursor_proxy))));
    return; 
  }
  cursor_proxy = CreateBinding(cursor.get());
  cursors_.push_back(std::move(cursor));
  HostThread::PostTask(
      HostThread::IO,
      FROM_HERE,
      base::BindOnce(
        &StorageContext::ReplyCreateCursor, 
        this, 
        base::Passed(std::move(callback)),
        true,
        base::Passed(std::move(cursor_proxy))));
}

void StorageContext::DataExecuteQueryImpl(uint32_t context_id, int32_t req, const std::string& tid, const std::string& query, common::mojom::StorageDispatcherHost::DataExecuteQueryCallback callback) {
  DLOG(INFO) << "StorageContext::DataExecuteQueryImpl";
  ShareManager* share_manager = workspace_->share_manager();
  std::string ns = domain_->name();
  common::mojom::SQLCursorPtr cursor_proxy;
  base::UUID uuid;
  bool found = share_manager->GetUUID(ns, tid, &uuid);
  if (!found) {
    DLOG(INFO) << "StorageContext::DataExecuteQueryImpl: uuid for '" << tid << "' not found.. trying system databases now";
    ns = workspace_->workspace_storage()->workspace_disk_name();
    found = workspace_->storage_manager().GetUUID(
      ns, 
      tid, 
      &uuid);
  }
  if (!found) {
    DLOG(INFO) << "StorageContext::ExecuteQueryImpl: error => uuid for '" << tid << "' not found";
    HostThread::PostTask(
      HostThread::IO,
      FROM_HERE,
      base::BindOnce(
        &StorageContext::ReplyExecuteQuery, 
        this, 
        base::Passed(std::move(callback)),
        false, 
        base::Passed(std::move(cursor_proxy))));
    return;
  }
  Share* share = share_manager->GetShare(ns, uuid);
  if (!share) {
    DLOG(INFO) << "StorageContext::ExecuteQueryImpl: error => share for " << uuid.to_string() << " => '" << tid << "' not found";
    HostThread::PostTask(
      HostThread::IO,
      FROM_HERE,
      base::BindOnce(
        &StorageContext::ReplyExecuteQuery, 
        this, 
        base::Passed(std::move(callback)),
        false, 
        base::Passed(std::move(cursor_proxy))));
    return;
  }
  if (!share->is_open() || !share->db_is_open()) {
    DLOG(INFO) << "StorageContext::ExecuteQueryImpl: error => " << tid << " is not open" ;
    HostThread::PostTask(
      HostThread::IO,
      FROM_HERE,
      base::BindOnce(
        &StorageContext::ReplyExecuteQuery, 
        this, 
        base::Passed(std::move(callback)),
        false, 
        base::Passed(std::move(cursor_proxy))));
    return; 
  }
  int rc = 0;
  auto* stmt = share->db()->ExecuteQuery(query, &rc);
  if (stmt == nullptr) {
    DLOG(INFO) << "StorageContext::DataExecuteQueryImpl: failed to execute statement '" << query << "' on db " << share->db()->db();
    HostThread::PostTask(
      HostThread::IO,
      FROM_HERE,
      base::BindOnce(
        &StorageContext::ReplyExecuteQuery, 
        this, 
        base::Passed(std::move(callback)),
        false,
        base::Passed(std::move(cursor_proxy))));
    return; 
  }
  auto cursor = std::make_unique<StorageSQLCursor>(stmt, rc, task_runner_);
  cursor_proxy = CreateSQLBinding(cursor.get());
  sql_cursors_.push_back(std::move(cursor));
  HostThread::PostTask(
      HostThread::IO,
      FROM_HERE,
      base::BindOnce(
        &StorageContext::ReplyExecuteQuery, 
        this, 
        base::Passed(std::move(callback)),
        true,
        base::Passed(std::move(cursor_proxy))));
}

void StorageContext::IndexResolveIdImpl(uint32_t context_id, int32_t req, const std::string& address) {
  DCHECK(domain_);
  DCHECK(workspace_);
  int64_t r = net::OK;
  base::UUID uuid;
  Volume* volume = workspace_->volume_manager()->volumes()->GetVolumeByName(domain_->name());
  if (volume) {
    r = volume->GetUUID(address, &uuid) ? net::OK : net::ERR_FAILED;
  } else {
    //DLOG(ERROR) << "Theres no volume named '" << domain_->name() << "'";
    r = net::ERR_FAILED;
  }
  HostThread::PostTask(
    HostThread::IO,
    FROM_HERE,
    base::Bind(&StorageContext::ReplyIndexResolveId, this, context_id, req, address, base::Passed(std::move(uuid)), r));
}

/* 
 * Responses
 */
void StorageContext::ReplyContextDestroy(uint32_t context_id, int64_t status) {
  base::AutoLock mutex(domain_lock_);
  //DLOG(INFO) << "StorageContext::ReplyContextDestroy";
  common::mojom::StorageDispatcher* client = domain_->process_for_io()->GetStorageDispatcherInterface();
  client->OnContextDestroy(context_id, ToStorageStatus(status));
}

void StorageContext::ReplyShareExistsOnIOThread(uint32_t context_id, int32_t req, base::UUID uuid, base::OnceCallback<void(bool)> cb, bool exists) {
  std::move(cb).Run(exists);
}

void StorageContext::ReplyShareCreate(uint32_t context_id, int32_t req, base::UUID uuid, int64_t result) {
  if (result == net::OK) {
    //bool ok = false;
    //storage::StorageManager* manager = workspace_->volume_storage()->storage_manager();
    ShareManager* share_manager = workspace_->share_manager();
    auto share = share_manager->GetShare(uuid);
    DCHECK(share);
    //DLOG(INFO) << "StorageContext::ReplyShareCreate: adding this context as observer to share " << share->id().to_string();
    share->AddObserver(this);
  }
  HostThread::PostTask(
    HostThread::IO,
    FROM_HERE,
    base::BindOnce(
      &StorageContext::ReplyShareCreateOnIOThread,
      this,
      context_id, 
      req, 
      base::Passed(std::move(uuid)), 
      result));
}

void StorageContext::ReplyShareCreateOnIOThread(uint32_t context_id, int32_t req, base::UUID uuid, int64_t result) {
  base::AutoLock mutex(domain_lock_);
  //DLOG(INFO) << "StorageContext::ReplyShareCreateOnIOThread";  
  common::mojom::StorageDispatcher* client = domain_->process_for_io()->GetStorageDispatcherInterface();
  client->OnShareCreate(context_id, req, std::string(reinterpret_cast<const char *>(uuid.data), 16), ToStorageStatus(result));
}

void StorageContext::ReplyShareAdd(uint32_t context_id, int32_t req, base::UUID uuid, int64_t status) {
  base::AutoLock mutex(domain_lock_);
  //DLOG(INFO) << "StorageContext::ReplyShareAdd";
  common::mojom::StorageDispatcher* client = domain_->process_for_io()->GetStorageDispatcherInterface();
  client->OnShareAdd(context_id, req, std::string(reinterpret_cast<const char *>(uuid.data), 16), ToStorageStatus(status));
}

void StorageContext::ReplyShareOpen(uint32_t context_id, int32_t req, base::UUID uuid, int64_t status) {
  if (status == net::OK) {
    //bool ok = false;
    //storage::StorageManager* manager = workspace_->volume_storage()->storage_manager();
    ShareManager* share_manager = workspace_->share_manager();
    auto share = share_manager->GetShare(uuid);
    DCHECK(share);
    share->AddObserver(this);
  }
  HostThread::PostTask(
    HostThread::IO,
    FROM_HERE,
    base::BindOnce(
      &StorageContext::ReplyShareOpenOnIOThread,
      this,
      context_id, 
      req, 
      base::Passed(std::move(uuid)), 
      status));
}

void StorageContext::ReplyShareOpenOnIOThread(uint32_t context_id, int32_t req, base::UUID uuid, int64_t status) {
  base::AutoLock mutex(domain_lock_);
  common::mojom::StorageDispatcher* client = domain_->process_for_io()->GetStorageDispatcherInterface();
  client->OnShareOpen(context_id, req, std::string(reinterpret_cast<const char *>(uuid.data), 16), ToStorageStatus(status));
}

void StorageContext::ReplyFileCreate(uint32_t context_id, int32_t req, base::UUID uuid, const std::string& file, int64_t status) {
  base::AutoLock mutex(domain_lock_);
  common::mojom::StorageDispatcher* client = domain_->process_for_io()->GetStorageDispatcherInterface();
  client->OnFileCreate(context_id, req, std::string(reinterpret_cast<const char *>(uuid.data), 16), file, ToStorageStatus(status));
}

void StorageContext::ReplyFileAdd(uint32_t context_id, int32_t req, base::UUID uuid, const std::string& file, int64_t status) {
  base::AutoLock mutex(domain_lock_);
  common::mojom::StorageDispatcher* client = domain_->process_for_io()->GetStorageDispatcherInterface();
  client->OnFileAdd(context_id, req, std::string(reinterpret_cast<const char *>(uuid.data), 16), file, ToStorageStatus(status));
}

void StorageContext::ReplyFileOpen(uint32_t context_id, int32_t req, base::UUID uuid, const std::string& file, int64_t status) {
  base::AutoLock mutex(domain_lock_);
  common::mojom::StorageDispatcher* client = domain_->process_for_io()->GetStorageDispatcherInterface();
  client->OnFileOpen(context_id, req, std::string(reinterpret_cast<const char *>(uuid.data), 16), file, ToStorageStatus(status));
}

void StorageContext::ReplyFileDelete(uint32_t context_id, int32_t req, base::UUID uuid, const std::string& file, int64_t status) {
  base::AutoLock mutex(domain_lock_);
  common::mojom::StorageDispatcher* client = domain_->process_for_io()->GetStorageDispatcherInterface();
  client->OnFileDelete(context_id, req, std::string(reinterpret_cast<const char *>(uuid.data), 16), file, ToStorageStatus(status));
}

void StorageContext::ReplyFileReadOnce(uint32_t context_id, int32_t req, base::UUID uuid, const std::string& file, int64_t status, int64_t bytes_readed, mojo::ScopedSharedBufferHandle data) {
  base::AutoLock mutex(domain_lock_);
  common::mojom::StorageDispatcher* client = domain_->process_for_io()->GetStorageDispatcherInterface();
  client->OnFileReadOnce(context_id, req, std::string(reinterpret_cast<const char *>(uuid.data), 16), file, ToStorageStatus(status), bytes_readed, std::move(data));
}

void StorageContext::ReplyFileRead(uint32_t context_id, int32_t req, base::UUID uuid, const std::string& file, int64_t status, int64_t bytes_written) {
  base::AutoLock mutex(domain_lock_);
  common::mojom::StorageDispatcher* client = domain_->process_for_io()->GetStorageDispatcherInterface();
  client->OnFileRead(context_id, req, std::string(reinterpret_cast<const char *>(uuid.data), 16), file, ToStorageStatus(status), bytes_written);
}

void StorageContext::ReplyFileWrite(uint32_t context_id, int32_t req, base::UUID uuid, const std::string& file, int64_t status, int64_t bytes_written) {
  base::AutoLock mutex(domain_lock_);
  common::mojom::StorageDispatcher* client = domain_->process_for_io()->GetStorageDispatcherInterface();
  client->OnFileWrite(context_id, req, std::string(reinterpret_cast<const char *>(uuid.data), 16), file, ToStorageStatus(status), bytes_written);
}

void StorageContext::ReplyFileWriteOnce(uint32_t context_id, int32_t req, base::UUID uuid, const std::string& file, int64_t status, int64_t bytes_written) {
  base::AutoLock mutex(domain_lock_);
  common::mojom::StorageDispatcher* client = domain_->process_for_io()->GetStorageDispatcherInterface();
  client->OnFileWriteOnce(context_id, req, std::string(reinterpret_cast<const char *>(uuid.data), 16), file, ToStorageStatus(status), bytes_written);
}

void StorageContext::ReplyFileClose(uint32_t context_id, int32_t req, base::UUID uuid, const std::string& file, int64_t status) {
  base::AutoLock mutex(domain_lock_);
  common::mojom::StorageDispatcher* client = domain_->process_for_io()->GetStorageDispatcherInterface();
  client->OnFileClose(context_id, req, std::string(reinterpret_cast<const char *>(uuid.data), 16), file, ToStorageStatus(status));
}

void StorageContext::ReplyFileRename(uint32_t context_id, int32_t req, base::UUID uuid, const std::string& file, int64_t status) {
  base::AutoLock mutex(domain_lock_);
  common::mojom::StorageDispatcher* client = domain_->process_for_io()->GetStorageDispatcherInterface();
  client->OnFileRename(context_id, req, std::string(reinterpret_cast<const char *>(uuid.data), 16), file, ToStorageStatus(status));
}


// void StorageContext::ReplyDataOpen(uint32_t context_id, int32_t req, base::UUID uuid, int64_t status) {
//   HostThread::PostTask(HostThread::IO, 
//     FROM_HERE, 
//     base::BindOnce(&StorageContext::ReplyDataOpenOnIOThread, this, context_id, req, tid, status));
// }

// void StorageContext::ReplyDataOpenOnIOThread(uint32_t context_id, int32_t req, base::UUID uuid, int64_t status) {
//   base::AutoLock mutex(domain_lock_);
//   common::mojom::StorageDispatcher* client = domain_->process_for_io()->GetStorageDispatcherInterface();
//   client->OnDataOpen(context_id, req, tid, ToStorageStatus(status));
// }

void StorageContext::ReplyDataClose(uint32_t context_id, int32_t req, base::UUID uuid, int64_t status) {
  HostThread::PostTask(
    HostThread::IO,
    FROM_HERE,
    base::BindOnce(
      &StorageContext::ReplyDataCloseOnIOThread,
      this,
      context_id, 
      req, 
      base::Passed(std::move(uuid)), 
      status));
}

void StorageContext::ReplyDataCloseOnIOThread(uint32_t context_id, int32_t req, base::UUID uuid, int64_t status) {
  base::AutoLock mutex(domain_lock_);
  common::mojom::StorageDispatcher* client = domain_->process_for_io()->GetStorageDispatcherInterface();
  client->OnDataClose(context_id, req, std::string(reinterpret_cast<const char *>(uuid.data), 16), ToStorageStatus(status));
}

// void StorageContext::ReplyDataCreate(uint32_t context_id, int32_t req, base::UUID uuid, int64_t status) {
//   base::AutoLock mutex(domain_lock_);
//   common::mojom::StorageDispatcher* client = domain_->process_for_io()->GetStorageDispatcherInterface();
//   client->OnDataCreate(context_id, req, tid, ToStorageStatus(status));
// }

void StorageContext::ReplyDataDrop(uint32_t context_id, int32_t req, base::UUID uuid, int64_t status) {
  base::AutoLock mutex(domain_lock_);
  common::mojom::StorageDispatcher* client = domain_->process_for_io()->GetStorageDispatcherInterface();
  client->OnDataDrop(context_id, req, std::string(reinterpret_cast<const char *>(uuid.data), 16), ToStorageStatus(status));
}

void StorageContext::ReplyDataCreateKeyspace(uint32_t context_id, int32_t req, base::UUID uuid, const std::string& keyspace, int64_t status) {
  base::AutoLock mutex(domain_lock_);
  common::mojom::StorageDispatcher* client = domain_->process_for_io()->GetStorageDispatcherInterface();
  client->OnDataCreateKeyspace(context_id, req, std::string(reinterpret_cast<const char *>(uuid.data), 16), keyspace, ToStorageStatus(status));
}

void StorageContext::ReplyDataDeleteKeyspace(uint32_t context_id, int32_t req, base::UUID uuid, const std::string& keyspace, int64_t status) {
  base::AutoLock mutex(domain_lock_);
  common::mojom::StorageDispatcher* client = domain_->process_for_io()->GetStorageDispatcherInterface();
  client->OnDataDeleteKeyspace(context_id, req, std::string(reinterpret_cast<const char *>(uuid.data), 16), keyspace, ToStorageStatus(status));
}

void StorageContext::ReplyDataListKeyspaces(uint32_t context_id, int32_t req, base::UUID uuid, int64_t status, std::vector<std::string> keyspaces) {
  base::AutoLock mutex(domain_lock_);
  common::mojom::StorageDispatcher* client = domain_->process_for_io()->GetStorageDispatcherInterface();
  client->OnDataListKeyspaces(context_id, req, std::string(reinterpret_cast<const char *>(uuid.data), 16), ToStorageStatus(status), std::move(keyspaces));
}

void StorageContext::ReplyDataPut(uint32_t context_id, int32_t req, base::UUID uuid, const std::string& keyspace, int64_t status, int64_t wrote) {
  base::AutoLock mutex(domain_lock_);
  common::mojom::StorageDispatcher* client = domain_->process_for_io()->GetStorageDispatcherInterface();
  client->OnDataPut(context_id, req, std::string(reinterpret_cast<const char *>(uuid.data), 16), keyspace, ToStorageStatus(status), wrote);
}

void StorageContext::ReplyDataGet(uint32_t context_id, int32_t req, base::UUID uuid, const std::string& keyspace, int64_t status, int64_t wrote) {
  base::AutoLock mutex(domain_lock_);
  common::mojom::StorageDispatcher* client = domain_->process_for_io()->GetStorageDispatcherInterface();
  if (status == net::OK) {
    client->OnDataGet(context_id, req, std::string(reinterpret_cast<const char *>(uuid.data), 16), keyspace, ToStorageStatus(status), wrote);
  } else {
    client->OnDataGetFailed(context_id, req, std::string(reinterpret_cast<const char *>(uuid.data), 16), keyspace, ToStorageStatus(status));
  }
}

void StorageContext::ReplyDataGetOnce(uint32_t context_id, int32_t req, base::UUID uuid, const std::string& keyspace, int64_t status, int64_t readed, mojo::ScopedSharedBufferHandle data) {
  base::AutoLock mutex(domain_lock_);
  common::mojom::StorageDispatcher* client = domain_->process_for_io()->GetStorageDispatcherInterface();
  if (status == net::OK) {
    client->OnDataGetOnce(context_id, req, std::string(reinterpret_cast<const char *>(uuid.data), 16), keyspace, ToStorageStatus(status), readed, std::move(data));
  } else {
    client->OnDataGetFailed(context_id, req, std::string(reinterpret_cast<const char *>(uuid.data), 16), keyspace, ToStorageStatus(status));
  }
}

void StorageContext::ReplyDataDelete(uint32_t context_id, int32_t req, base::UUID uuid, const std::string& keyspace, int64_t status) {
  base::AutoLock mutex(domain_lock_);
  common::mojom::StorageDispatcher* client = domain_->process_for_io()->GetStorageDispatcherInterface();
  client->OnDataDelete(context_id, req, std::string(reinterpret_cast<const char *>(uuid.data), 16), keyspace, ToStorageStatus(status)); 
}

void StorageContext::ReplyDataDeleteAll(uint32_t context_id, int32_t req, base::UUID uuid, const std::string& keyspace, int64_t status) {
  base::AutoLock mutex(domain_lock_);
  common::mojom::StorageDispatcher* client = domain_->process_for_io()->GetStorageDispatcherInterface();
  client->OnDataDeleteAll(context_id, req, std::string(reinterpret_cast<const char *>(uuid.data), 16), keyspace, ToStorageStatus(status));
}

void StorageContext::ReplyIndexResolveId(uint32_t context_id, int32_t req, const std::string& address, base::UUID resolved, int64_t status) {
  base::AutoLock mutex(domain_lock_);
  common::mojom::StorageDispatcher* client = domain_->process_for_io()->GetStorageDispatcherInterface();
  client->OnIndexResolveId(context_id, req, address, std::string(reinterpret_cast<const char *>(resolved.data), 16), ToStorageStatus(status)); 
}

void StorageContext::ReplyCreateCursor(common::mojom::StorageDispatcherHost::DataCreateCursorCallback callback, bool ok, common::mojom::DataCursorPtr cursor) {
  std::move(callback).Run(std::move(cursor));     
}

void StorageContext::ReplyExecuteQuery(common::mojom::StorageDispatcherHost::DataExecuteQueryCallback callback, bool ok, common::mojom::SQLCursorPtr cursor) {
  std::move(callback).Run(std::move(cursor));
}

// ShareObserver
void StorageContext::OnDHTAnnounceReply(Share* share, int peers) {
  //DLOG(INFO) << "StorageContext::OnDHTAnnounceReply: " << share->id().to_string();
  HostThread::PostTask(
    HostThread::IO,
    FROM_HERE,
    base::BindOnce(
      &StorageContext::ReplyShareDHTAnnounceReply,
      this,
      id_,
      -1,
      share->id(),
      peers));
}

void StorageContext::ReplyShareDHTAnnounceReply(uint32_t context_id, int32_t req, base::UUID uuid, int peers) {
  base::AutoLock mutex(domain_lock_);
  //DLOG(INFO) << "StorageContext::ReplyShareDHTAnnounceReply";
  common::mojom::StorageDispatcher* client = domain_->process_for_io()->GetStorageDispatcherInterface();
  client->OnShareDHTAnnounceReply(context_id, req, std::string(reinterpret_cast<const char *>(uuid.data), 16), peers);
}

void StorageContext::OnShareMetadataReceived(Share* share) {
  //DLOG(INFO) << "StorageContext::OnShareMetadataReceived: " << share->id().to_string();
  HostThread::PostTask(
    HostThread::IO,
    FROM_HERE,
    base::BindOnce(
      &StorageContext::ReplyShareMetadataReceived,
      this,
      id_,
      -1,
      share->id()));
}

void StorageContext::ReplyShareMetadataReceived(uint32_t context_id, int32_t req, base::UUID uuid) {
  base::AutoLock mutex(domain_lock_);
  //DLOG(INFO) << "StorageContext::ReplyShareMetadataReceived";
  common::mojom::StorageDispatcher* client = domain_->process_for_io()->GetStorageDispatcherInterface();
  client->OnShareMetadataReceived(context_id, req, std::string(reinterpret_cast<const char *>(uuid.data), 16));
}

void StorageContext::OnShareMetadataError(Share* share, int error) {
  //DLOG(INFO) << "StorageContext::OnShareMetadataError: " << share->id().to_string();
  HostThread::PostTask(
    HostThread::IO,
    FROM_HERE,
    base::BindOnce(
      &StorageContext::ReplyShareMetadataError,
      this,
      id_,
      -1,
      share->id(),
      error));
}

void StorageContext::ReplyShareMetadataError(uint32_t context_id, int32_t req, base::UUID uuid, int error) {
  base::AutoLock mutex(domain_lock_);
  //DLOG(INFO) << "StorageContext::ReplyShareMetadataError";
  common::mojom::StorageDispatcher* client = domain_->process_for_io()->GetStorageDispatcherInterface();
  client->OnShareMetadataError(context_id, req, std::string(reinterpret_cast<const char *>(uuid.data), 16), error);
}

void StorageContext::OnSharePieceReadError(Share* share, int piece_offset, int error) {
  //DLOG(INFO) << "StorageContext::OnSharePieceReadError: " << share->id().to_string() << " piece: " << piece_offset;
  HostThread::PostTask(
    HostThread::IO,
    FROM_HERE,
    base::BindOnce(
      &StorageContext::ReplySharePieceReadError,
      this,
      id_,
      -1,
      share->id(),
      piece_offset,
      error));
}

void StorageContext::ReplySharePieceReadError(uint32_t context_id, int32_t req, base::UUID uuid, int piece, int error) {
  base::AutoLock mutex(domain_lock_);
  //DLOG(INFO) << "StorageContext::ReplySharePieceReadError";
  common::mojom::StorageDispatcher* client = domain_->process_for_io()->GetStorageDispatcherInterface();
  client->OnSharePieceReadError(context_id, req, std::string(reinterpret_cast<const char *>(uuid.data), 16), piece, error);
}

void StorageContext::OnSharePiecePass(Share* share, int piece_offset) {
  //DLOG(INFO) << "StorageContext::OnSharePiecePass: " << share->id().to_string() << " piece: " << piece_offset;
  HostThread::PostTask(
    HostThread::IO,
    FROM_HERE,
    base::BindOnce(
      &StorageContext::ReplySharePiecePass,
      this,
      id_,
      -1,
      share->id(),
      piece_offset));
}

void StorageContext::ReplySharePiecePass(uint32_t context_id, int32_t req, base::UUID uuid, int piece) {
  base::AutoLock mutex(domain_lock_);
  //DLOG(INFO) << "StorageContext::ReplySharePiecePass";
  common::mojom::StorageDispatcher* client = domain_->process_for_io()->GetStorageDispatcherInterface();
  client->OnSharePiecePass(context_id, req, std::string(reinterpret_cast<const char *>(uuid.data), 16), piece);
}

void StorageContext::OnSharePieceFailed(Share* share, int piece_offset) {
  //DLOG(INFO) << "StorageContext::OnSharePieceFailed: " << share->id().to_string() << " piece_offset: " << piece_offset;
  HostThread::PostTask(
    HostThread::IO,
    FROM_HERE,
    base::BindOnce(
      &StorageContext::ReplySharePieceFailed,
      this,
      id_,
      -1,
      share->id(),
      piece_offset));
}

void StorageContext::ReplySharePieceFailed(uint32_t context_id, int32_t req, base::UUID uuid, int piece) {
  base::AutoLock mutex(domain_lock_);
  //DLOG(INFO) << "StorageContext::ReplySharePieceFailed";
  common::mojom::StorageDispatcher* client = domain_->process_for_io()->GetStorageDispatcherInterface();
  client->OnSharePieceFailed(context_id, req, std::string(reinterpret_cast<const char *>(uuid.data), 16), piece);
}

void StorageContext::OnSharePieceRead(Share* share, int piece, int64_t offset, int64_t size, int64_t block_size, int result) {
  //DLOG(INFO) << "StorageContext::OnSharePieceRead: " << share->id().to_string() << " piece: " << piece;
  HostThread::PostTask(
    HostThread::IO,
    FROM_HERE,
    base::BindOnce(
      &StorageContext::ReplySharePieceRead,
      this,
      id_,
      -1,
      share->id(),
      piece,
      offset, 
      size, 
      block_size, 
      result));
}

void StorageContext::ReplySharePieceRead(uint32_t context_id, int32_t req, base::UUID uuid, int piece, int64_t offset, int64_t size, int64_t block_size, int result) {
  base::AutoLock mutex(domain_lock_);
  //DLOG(INFO) << "StorageContext::ReplySharePieceRead";
  common::mojom::StorageDispatcher* client = domain_->process_for_io()->GetStorageDispatcherInterface();
  client->OnSharePieceRead(context_id, req, std::string(reinterpret_cast<const char *>(uuid.data), 16), piece, offset, size, block_size, result);
}

void StorageContext::ReplyShareRead(uint32_t context_id, int32_t req, base::UUID uuid, int64_t status, int64_t bytes_readed) {
  base::AutoLock mutex(domain_lock_);
  //DLOG(INFO) << "StorageContext::ReplyShareRead";
  common::mojom::StorageDispatcher* client = domain_->process_for_io()->GetStorageDispatcherInterface();
  client->OnShareRead(context_id, req, std::string(reinterpret_cast<const char *>(uuid.data), 16), ToStorageStatus(status), bytes_readed);
}

void StorageContext::OnSharePieceWrite(Share* share, int piece, int64_t offset, int64_t size, int64_t block_size, int result) {
  //DLOG(INFO) << "StorageContext::OnSharePieceWrite: " << share->id().to_string() << " piece: " << piece;
  HostThread::PostTask(
    HostThread::IO,
    FROM_HERE,
    base::BindOnce(
      &StorageContext::ReplySharePieceWrite,
      this,
      id_,
      -1,
      share->id(),
      piece,
      offset, 
      size, 
      block_size, 
      result));
}

void StorageContext::ReplySharePieceWrite(uint32_t context_id, int32_t req, base::UUID uuid, int piece, int64_t offset, int64_t size, int64_t block_size, int result) {
  base::AutoLock mutex(domain_lock_);
  //DLOG(INFO) << "StorageContext::ReplySharePieceWrite";
  common::mojom::StorageDispatcher* client = domain_->process_for_io()->GetStorageDispatcherInterface();
  client->OnSharePieceWrite(context_id, req, std::string(reinterpret_cast<const char *>(uuid.data), 16), piece, offset, size, block_size, result);
}

void StorageContext::ReplyShareWrite(uint32_t context_id, int32_t req, base::UUID uuid, int64_t status, int64_t bytes_written) {
  base::AutoLock mutex(domain_lock_);
  //DLOG(INFO) << "StorageContext::ReplyShareWrite";
  common::mojom::StorageDispatcher* client = domain_->process_for_io()->GetStorageDispatcherInterface();
  client->OnShareWrite(context_id, req, std::string(reinterpret_cast<const char *>(uuid.data), 16), ToStorageStatus(status), bytes_written);
}

void StorageContext::OnSharePieceFinished(Share* share, int piece_offset) {
  //DLOG(INFO) << "StorageContext::OnSharePieceFinished: " << share->id().to_string();
  HostThread::PostTask(
    HostThread::IO,
    FROM_HERE,
    base::BindOnce(
      &StorageContext::ReplySharePieceComplete,
      this,
      id_,
      -1,
      share->id(),
      piece_offset));
}

void StorageContext::ReplySharePieceComplete(uint32_t context_id, int32_t req, base::UUID uuid, uint32_t piece_offset) {
  base::AutoLock mutex(domain_lock_);
  //DLOG(INFO) << "StorageContext::ReplySharePieceComplete";
  common::mojom::StorageDispatcher* client = domain_->process_for_io()->GetStorageDispatcherInterface();
  client->OnSharePieceComplete(context_id, req, std::string(reinterpret_cast<const char *>(uuid.data), 16), piece_offset);
}


void StorageContext::OnSharePieceHashFailed(Share* share, int piece_offset) {
  //DLOG(INFO) << "StorageContext::OnSharePieceHashFailed: " << share->id().to_string();
  HostThread::PostTask(
    HostThread::IO,
    FROM_HERE,
    base::BindOnce(
      &StorageContext::ReplySharePieceHashFailed,
      this,
      id_,
      -1,
      share->id(),
      piece_offset));
}

void StorageContext::ReplySharePieceHashFailed(uint32_t context_id, int32_t req, base::UUID uuid, int piece) {
  base::AutoLock mutex(domain_lock_);
  //DLOG(INFO) << "StorageContext::ReplySharePieceHashFailed";
  common::mojom::StorageDispatcher* client = domain_->process_for_io()->GetStorageDispatcherInterface();
  client->OnSharePieceHashFailed(context_id, req, std::string(reinterpret_cast<const char *>(uuid.data), 16), piece);
}

void StorageContext::OnShareFileCompleted(Share* share, int file_offset) {
  //DLOG(INFO) << "StorageContext::OnShareFileCompleted: " << share->id().to_string();
  HostThread::PostTask(
    HostThread::IO,
    FROM_HERE,
    base::BindOnce(
      &StorageContext::ReplyShareFileComplete,
      this,
      id_,
      -1,
      share->id(),
      file_offset));
}

void StorageContext::ReplyShareFileComplete(uint32_t context_id, int32_t req, base::UUID uuid, int file_offset) {
  base::AutoLock mutex(domain_lock_);
  common::mojom::StorageDispatcher* client = domain_->process_for_io()->GetStorageDispatcherInterface();
  client->OnShareFileComplete(context_id, req, std::string(reinterpret_cast<const char *>(uuid.data), 16), file_offset);
}

void StorageContext::OnShareFinished(Share* share) {
  //DLOG(INFO) << "StorageContext::OnShareFinished: " << share->id().to_string();
  HostThread::PostTask(
    HostThread::IO,
    FROM_HERE,
    base::BindOnce(
      &StorageContext::ReplyShareComplete,
      this,
      id_,
      -1,
      share->id()));
}

void StorageContext::ReplyShareComplete(uint32_t context_id, int32_t req, base::UUID uuid) {
  base::AutoLock mutex(domain_lock_);
  common::mojom::StorageDispatcher* client = domain_->process_for_io()->GetStorageDispatcherInterface();
  client->OnShareComplete(context_id, req, std::string(reinterpret_cast<const char *>(uuid.data), 16)); 
}

void StorageContext::OnShareDownloading(Share* share) {
  //DLOG(INFO) << "StorageContext::OnShareDownloading: " << share->id().to_string();
  HostThread::PostTask(
    HostThread::IO,
    FROM_HERE,
    base::BindOnce(
      &StorageContext::ReplyShareDownloading,
      this,
      id_,
      -1,
      share->id()));
}

void StorageContext::ReplyShareDownloading(uint32_t context_id, int32_t req, base::UUID uuid) {
  base::AutoLock mutex(domain_lock_);
  common::mojom::StorageDispatcher* client = domain_->process_for_io()->GetStorageDispatcherInterface();
  client->OnShareDownloading(context_id, req, std::string(reinterpret_cast<const char *>(uuid.data), 16));
}

void StorageContext::OnShareCheckingFiles(Share* share) {
  //DLOG(INFO) << "StorageContext::OnShareCheckingFiles: " << share->id().to_string();
  HostThread::PostTask(
    HostThread::IO,
    FROM_HERE,
    base::BindOnce(
      &StorageContext::ReplyShareCheckingFiles,
      this,
      id_,
      -1,
      share->id()));
}

void StorageContext::ReplyShareCheckingFiles(uint32_t context_id, int32_t req, base::UUID uuid) {
  base::AutoLock mutex(domain_lock_);
  common::mojom::StorageDispatcher* client = domain_->process_for_io()->GetStorageDispatcherInterface();
  client->OnShareCheckingFiles(context_id, req, std::string(reinterpret_cast<const char *>(uuid.data), 16));
}

void StorageContext::OnShareDownloadingMetadata(Share* share) {
  //DLOG(INFO) << "StorageContext::OnShareDownloadingMetadata: " << share->id().to_string();
  HostThread::PostTask(
    HostThread::IO,
    FROM_HERE,
    base::BindOnce(
      &StorageContext::ReplyShareDownloadingMetadata,
      this,
      id_,
      -1,
      share->id()));
}

void StorageContext::ReplyShareDownloadingMetadata(uint32_t context_id, int32_t req, base::UUID uuid) {
  base::AutoLock mutex(domain_lock_);
  common::mojom::StorageDispatcher* client = domain_->process_for_io()->GetStorageDispatcherInterface();
  client->OnShareDownloadingMetadata(context_id, req, std::string(reinterpret_cast<const char *>(uuid.data), 16));
}

void StorageContext::OnShareSeeding(Share* share) {
  //DLOG(INFO) << "StorageContext::OnShareSeeding: " << share->id().to_string();
  HostThread::PostTask(
    HostThread::IO,
    FROM_HERE,
    base::BindOnce(
      &StorageContext::ReplyShareSeeding,
      this,
      id_,
      -1,
      share->id()));
}

void StorageContext::ReplyShareSeeding(uint32_t context_id, int32_t req, base::UUID uuid) {
  base::AutoLock mutex(domain_lock_);
  common::mojom::StorageDispatcher* client = domain_->process_for_io()->GetStorageDispatcherInterface();
  client->OnShareSeeding(context_id, req, std::string(reinterpret_cast<const char *>(uuid.data), 16));
}

void StorageContext::OnSharePaused(Share* share) {
  //DLOG(INFO) << "StorageContext::OnSharePaused: " << share->id().to_string();
  HostThread::PostTask(
    HostThread::IO,
    FROM_HERE,
    base::BindOnce(
      &StorageContext::ReplySharePaused,
      this,
      id_,
      -1,
      share->id()));
}

void StorageContext::ReplySharePaused(uint32_t context_id, int32_t req, base::UUID uuid) {
  base::AutoLock mutex(domain_lock_);
  //DLOG(INFO) << "StorageContext::ReplySharePaused";
  common::mojom::StorageDispatcher* client = domain_->process_for_io()->GetStorageDispatcherInterface();
  client->OnSharePaused(context_id, req, std::string(reinterpret_cast<const char *>(uuid.data), 16));
}

void StorageContext::OnShareResumed(Share* share) {
  //DLOG(INFO) << "StorageContext::OnShareResumed: " << share->id().to_string();
  HostThread::PostTask(
    HostThread::IO,
    FROM_HERE,
    base::BindOnce(
      &StorageContext::ReplyShareResumed,
      this,
      id_,
      -1,
      share->id()));
}

void StorageContext::ReplyShareResumed(uint32_t context_id, int32_t req, base::UUID uuid) {
  base::AutoLock mutex(domain_lock_);
  //DLOG(INFO) << "StorageContext::ReplyShareResume";
  common::mojom::StorageDispatcher* client = domain_->process_for_io()->GetStorageDispatcherInterface();
  client->OnShareResumed(context_id, req, std::string(reinterpret_cast<const char *>(uuid.data), 16));
}

void StorageContext::OnShareChecked(Share* share) {
  //DLOG(INFO) << "StorageContext::OnShareChecked: " << share->id().to_string();
  HostThread::PostTask(
    HostThread::IO,
    FROM_HERE,
    base::BindOnce(
      &StorageContext::ReplyShareChecked,
      this,
      id_,
      -1,
      share->id(),
      net::OK));
}

void StorageContext::ReplyShareChecked(uint32_t context_id, int32_t req, base::UUID uuid, int64_t status) {
  base::AutoLock mutex(domain_lock_);
  //DLOG(INFO) << "StorageContext::ReplyShareChecked";
  common::mojom::StorageDispatcher* client = domain_->process_for_io()->GetStorageDispatcherInterface();
  client->OnShareChecked(context_id, req, std::string(reinterpret_cast<const char *>(uuid.data), 16), ToStorageStatus(status));
}

void StorageContext::OnShareDeleted(Share* share) {
  //DLOG(INFO) << "StorageContext::OnShareDeleted: " << share->id().to_string();
  HostThread::PostTask(
    HostThread::IO,
    FROM_HERE,
    base::BindOnce(
      &StorageContext::ReplyShareDelete,
      this,
      id_,
      -1,
      share->id(),
      net::OK));
}

void StorageContext::OnShareDeletedError(Share* share, int error) {
  //DLOG(INFO) << "StorageContext::OnShareDeletedError: " << share->id().to_string();
  HostThread::PostTask(
    HostThread::IO,
    FROM_HERE,
    base::BindOnce(
      &StorageContext::ReplyShareDelete,
      this,
      id_,
      -1,
      share->id(),
      error));
}

void StorageContext::ReplyShareDelete(uint32_t context_id, int32_t req, base::UUID uuid, int64_t status) {
  base::AutoLock mutex(domain_lock_);
  //DLOG(INFO) << "StorageContext::ReplyShareDelete";
  common::mojom::StorageDispatcher* client = domain_->process_for_io()->GetStorageDispatcherInterface();
  client->OnShareDelete(context_id, req, std::string(reinterpret_cast<const char *>(uuid.data), 16), ToStorageStatus(status));
}

void StorageContext::OnShareFileRenamed(Share* share, int file_offset, const std::string& name) {
  //DLOG(INFO) << "StorageContext::OnShareFileRenamed: " << share->id().to_string();
  HostThread::PostTask(
    HostThread::IO,
    FROM_HERE,
    base::BindOnce(
      &StorageContext::ReplyShareFileRenamed,
      this,
      id_,
      -1,
      share->id(),
      file_offset,
      name));
}

void StorageContext::ReplyShareFileRenamed(uint32_t context_id, int32_t req, base::UUID uuid, int file_offset, const std::string& name) {
  base::AutoLock mutex(domain_lock_);
  //DLOG(INFO) << "StorageContext::ReplyShareFileRenamed";
  common::mojom::StorageDispatcher* client = domain_->process_for_io()->GetStorageDispatcherInterface();
  client->OnShareFileRenamed(context_id, req, std::string(reinterpret_cast<const char *>(uuid.data), 16), file_offset, name, net::OK);
}

void StorageContext::OnShareFileRenamedError(Share* share, int index, int error) {
  //DLOG(INFO) << "StorageContext::OnShareFileRenamedError: " << share->id().to_string();
  HostThread::PostTask(
    HostThread::IO,
    FROM_HERE,
    base::BindOnce(
      &StorageContext::ReplyShareFileRenamedError,
      this,
      id_,
      -1,
      share->id(),
      index,
      error));
}

void StorageContext::ReplyShareFileRenamedError(uint32_t context_id, int32_t req, base::UUID uuid, int file_offset, int error) {
  base::AutoLock mutex(domain_lock_);
  //DLOG(INFO) << "StorageContext::ReplyShareFileRenamed";
  common::mojom::StorageDispatcher* client = domain_->process_for_io()->GetStorageDispatcherInterface();
  client->OnShareFileRenamed(context_id, req, std::string(reinterpret_cast<const char *>(uuid.data), 16), file_offset, std::string(), error);
}

void StorageContext::ReplyShareClose(uint32_t context_id, int32_t req, base::UUID uuid, int64_t status) {
  base::AutoLock mutex(domain_lock_);
  //DLOG(INFO) << "StorageContext::ReplyShareClose";
  common::mojom::StorageDispatcher* client = domain_->process_for_io()->GetStorageDispatcherInterface();
  client->OnShareClose(context_id, req, std::string(reinterpret_cast<const char *>(uuid.data), 16), ToStorageStatus(status));
}

void StorageContext::ReplyShareShare(uint32_t context_id, int32_t req, base::UUID uuid, int64_t status) {
  base::AutoLock mutex(domain_lock_);
  common::mojom::StorageDispatcher* client = domain_->process_for_io()->GetStorageDispatcherInterface();
  client->OnShareShare(context_id, req, std::string(reinterpret_cast<const char *>(uuid.data), 16), ToStorageStatus(status));
}

void StorageContext::ReplyShareUnshare(uint32_t context_id, int32_t req, base::UUID uuid, int64_t status) {
  base::AutoLock mutex(domain_lock_);
  common::mojom::StorageDispatcher* client = domain_->process_for_io()->GetStorageDispatcherInterface();
  client->OnShareUnshare(context_id, req, std::string(reinterpret_cast<const char *>(uuid.data), 16), ToStorageStatus(status));
}

void StorageContext::ReplyShareSubscribe(uint32_t context_id, int32_t req, base::UUID uuid, int64_t status) {
  base::AutoLock mutex(domain_lock_);
  common::mojom::StorageDispatcher* client = domain_->process_for_io()->GetStorageDispatcherInterface();
  client->OnShareSubscribe(context_id, req, std::string(reinterpret_cast<const char *>(uuid.data), 16), ToStorageStatus(status));
}

void StorageContext::ReplyShareUnsubscribe(uint32_t context_id, int32_t req, base::UUID uuid, int64_t status) {
  base::AutoLock mutex(domain_lock_);
  common::mojom::StorageDispatcher* client = domain_->process_for_io()->GetStorageDispatcherInterface();
  client->OnShareUnsubscribe(context_id, req, std::string(reinterpret_cast<const char *>(uuid.data), 16), ToStorageStatus(status));
}

void StorageContext::ReplyShareEvent(uint32_t context_id, int32_t req, base::UUID uuid, common::mojom::ShareEventPtr event) {
  base::AutoLock mutex(domain_lock_);
  common::mojom::StorageDispatcher* client = domain_->process_for_io()->GetStorageDispatcherInterface();
  client->OnShareEvent(context_id, req, std::string(reinterpret_cast<const char *>(uuid.data), 16), std::move(event));
}


}
