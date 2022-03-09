// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "StorageHelper.h"

#include "base/task_scheduler/post_task.h"
#include "base/threading/thread_restrictions.h"
#include "base/message_loop/message_loop.h"
#include "base/single_thread_task_runner.h"
#include "base/task_scheduler/task_traits.h"
#include "core/shared/domain/storage/share_storage.h"
#include "core/shared/domain/module/module_state.h"
#include "core/shared/domain/application/application.h"
#include "core/shared/domain/storage/data_storage.h"
#include "core/shared/domain/storage/file_storage.h"

namespace {

void RunCursorAvailableCallback(void* state, void* cursor, void (*callback)(void*, void*)) {
  callback(state, cursor);
}

void RunSQLCursorAvailableCallback(void* state, void* cursor, void (*callback)(void*, void*)) {
  callback(state, cursor);
}

void RunCursorIsValidCallback(void* state, int valid, void(*callback)(void*, int)) {
  callback(state, valid);
}

void RunCursorSeekToCallback(void* state, int32_t result, int match, void(*callback)(void*, int, int)) {
  callback(state, result, match);
}

void RunCursorCountCallback(void* state, int32_t result, int items, void(*callback)(void*, int, int)) {
  callback(state, result, items);
}

void RunCursorDataSizeCallback(void* state, int32_t result, int size, void(*callback)(void*, int, int)) {
  callback(state, result, size);
}

void RunCursorGetDataCallback(void* state, int32_t result, const std::vector<uint8_t>& data, void(*callback)(void*, int, const uint8_t*, int)) {
  callback(state, result, data.data(), static_cast<int>(data.size()));
}

void RunCursorGetKeyValueCallback(void* state, int32_t result, common::mojom::KeyValuePtr kv, void(*callback)(void*, int, const uint8_t*, int, const uint8_t*, int)) {
  callback(state, result, kv->key.data(), static_cast<int>(kv->key.size()), kv->value.data(), static_cast<int>(kv->value.size()));
}

void RunCursorGetCallback(void* state, int32_t result, common::mojom::KeyValuePtr kv, void(*callback)(void*, int, const uint8_t*, int)) {
  callback(state, result, kv->value.data(), static_cast<int>(kv->value.size()));
}

void RunCursorGetBlobCallback(void* state, int32_t result, const std::vector<uint8_t>& data, void(*callback)(void*, int, const uint8_t*, int)) {
  callback(state, result, data.data(), static_cast<int>(data.size()));
}

void RunCursorGetStringCallback(void* state, int32_t result, const std::string& data, void(*callback)(void*, int, const int8_t*, int)) {
  callback(state, result, reinterpret_cast<const int8_t*>(data.data()), static_cast<int>(data.size()));
}

void RunCursorGetIntCallback(void* state, int32_t result, int data, void(*callback)(void*, int, int)) {
  callback(state, result, data);
}

void RunCursorGetDoubleCallback(void* state, int32_t result, double data, void(*callback)(void*, int, double)) {
  callback(state, result, data);
}

void RunStatusCallback(void* state, int status, void(*callback)(void*, int)) {
  callback(state, status);
}

void RunDatabaseCallback(void* state, int status, DatabaseRef db, void(*callback)(void*, int, DatabaseRef)) {
  callback(state, status, db);
}

void RunFilebaseCallback(void* state, int status, FilebaseRef db, void(*callback)(void*, int, FilebaseRef)) {
  callback(state, status, db);
}

//void RunCursorCallback(void* state, void(*callback)(void*)) {
//  callback(state);
//}

void RunSharedBufferCallback(void* state, int status, mojo::ScopedSharedBufferHandle value, int len, void(*callback)(void*, int, SharedMemoryRef)) {
  if (status == 0) {
    // Its expected that the (heap) lifetime of this object is managed by the
    // handler
    mojo::SharedBufferHandle mem_handle = value.release();
    SharedMemoryRef handle = new SharedMemoryState(std::move(mem_handle), len);
    callback(state, status, handle);
  } else {
    callback(state, status, nullptr);
  }
}

// **
void RunListSharesCallback(
  void* state, 
  std::vector<common::mojom::ShareInfoPtr> shares,
  void(*callback)
  (void*,
   int /* info count*/,
   const char**,
   const char**,
   int32_t*,
   int32_t*,
   const char**,
   int64_t*,
   int32_t*,
   int32_t*,
   int64_t*,
   int32_t*)) {

  std::vector<const char*> uuids;
  std::vector<const char*> paths;
  std::vector<int32_t> kinds;
  std::vector<int32_t> states;
  std::vector<const char*> hashes;
  std::vector<int64_t> sizes;
  std::vector<int32_t> blocks;
  std::vector<int32_t> blocksizes; 
  std::vector<int64_t> createtimes;
  std::vector<int32_t> entrycounts;

  for (size_t i = 0; i < shares.size(); i++) {
    uuids.push_back(shares[i]->uuid.c_str());
    paths.push_back(shares[i]->path.c_str());
    kinds.push_back(static_cast<int>(shares[i]->kind));
    states.push_back(static_cast<int>(shares[i]->state));
    hashes.push_back(shares[i]->root_hash.c_str());
    sizes.push_back(shares[i]->size);
    blocks.push_back(shares[i]->blocks);
    blocksizes.push_back(shares[i]->block_size);
    createtimes.push_back(shares[i]->created_time);
    entrycounts.push_back(shares[i]->entry_count);
  }

  callback(
    state, 
    shares.size(), 
    &uuids[0],
    &paths[0],
    &kinds[0],
    &states[0],
    &hashes[0],
    &sizes[0],
    &blocks[0],
    &blocksizes[0],
    &createtimes[0],
    &entrycounts[0]);
}

void RunKeyspaceListCallback(void* state, int result, int count, const std::vector<std::string>& keyspaces, void(*callback)(void*, int, int, const char**)) {
  std::vector<const char*> list;
  for (size_t i = 0; i < keyspaces.size(); i++) {
    list.push_back(keyspaces[i].c_str());
  }
  callback(state, result, count, &list[0]);
}

void RunListFilesCallback(
  void* state, 
  std::vector<common::mojom::ShareStorageEntryPtr> entries,
  void(*callback)
  (void*, 
   int,
   const char**,
   const char**,
   const char**,
   int32_t*,
   int64_t*,
   int32_t*,
   int32_t*,
   int32_t*,
   int64_t*)) {

  std::vector<const char*> names;
  std::vector<const char*> paths;
  std::vector<const char*> types;
  std::vector<int32_t> offsets;
  std::vector<int64_t> sizes;
  std::vector<int32_t> blocks;
  std::vector<int32_t> blockstarts;
  std::vector<int32_t> blockends; 
  std::vector<int64_t> createtimes;

  for (size_t i = 0; i < entries.size(); i++) {
    names.push_back(entries[i]->name.c_str());
    paths.push_back(entries[i]->path.c_str());
    types.push_back(entries[i]->content_type.c_str());
    offsets.push_back(entries[i]->offset); 
    sizes.push_back(entries[i]->size);
    blocks.push_back(entries[i]->blocks);
    blockstarts.push_back(entries[i]->start_block);
    blockends.push_back(entries[i]->end_block);
    createtimes.push_back(entries[i]->created_time);
  }

  callback(
    state, 
    entries.size(), 
    &names[0],
    &paths[0],
    &types[0],
    &offsets[0],
    &sizes[0],
    &blocks[0],
    &blockstarts[0],
    &blockends[0],
    &createtimes[0]);
}

void DeleteSQLCursorOnMainThread(common::mojom::SQLCursorPtr cursor) {
  // just let it vanish here
  common::mojom::SQLCursorPtr local = std::move(cursor);
}

} // namespace

DatabaseCursorState::DatabaseCursorState(
  const scoped_refptr<domain::StorageContext>& context, 
  scoped_refptr<base::SingleThreadTaskRunner> module_task_runner,
  void* state, void (*callback)(void*, void*)):
 context_(context),
 module_task_runner_(module_task_runner),
 state_(state),
 callback_(callback) {

 //DCHECK(task_runner_ != context_->GetTaskRunner());

}

DatabaseCursorState::~DatabaseCursorState() {
  module_task_runner_ = nullptr;
}

void DatabaseCursorState::IsValid(void* state, void(*callback)(void*, int), bool blocking) {
  context_->GetMainTaskRunner()->PostTask(
    FROM_HERE,
    base::BindOnce(&DatabaseCursorState::IsValidImpl,
      base::Unretained(this),
      base::Unretained(state), 
      base::Unretained(callback),
      blocking)); 
}

void DatabaseCursorState::First(void* state, void(*callback)(void*, int), bool blocking) {
  context_->GetMainTaskRunner()->PostTask(
    FROM_HERE,
    base::BindOnce(&DatabaseCursorState::FirstImpl, base::Unretained(this), 
      base::Unretained(state), 
      base::Unretained(callback),
      blocking));
}

void DatabaseCursorState::Last(void* state, void(*callback)(void*, int), bool blocking) {
  context_->GetMainTaskRunner()->PostTask(
    FROM_HERE,
    base::BindOnce(&DatabaseCursorState::Last, base::Unretained(this), 
      base::Unretained(state), 
      base::Unretained(callback),
      blocking));
}

void DatabaseCursorState::Previous(void* state, void(*callback)(void*, int), bool blocking) {
  context_->GetMainTaskRunner()->PostTask(
    FROM_HERE,
    base::BindOnce(&DatabaseCursorState::PreviousImpl,
      base::Unretained(this), 
      base::Unretained(state), 
      base::Unretained(callback),
      blocking));
}

void DatabaseCursorState::Next(void* state, void(*callback)(void*, int), bool blocking) {
  context_->GetMainTaskRunner()->PostTask(
    FROM_HERE,
    base::BindOnce(&DatabaseCursorState::NextImpl,
      base::Unretained(this), 
      base::Unretained(state), 
      base::Unretained(callback),
      blocking));
}

void DatabaseCursorState::SeekTo(std::vector<uint8_t> key, common::mojom::Seek seek, void* state, void(*callback)(void*, int, int), bool blocking) {
  context_->GetMainTaskRunner()->PostTask(
    FROM_HERE,
    base::BindOnce(&DatabaseCursorState::SeekToImpl,
      base::Unretained(this),
      std::move(key), 
      seek, 
      base::Unretained(state), 
      base::Unretained(callback),
      blocking));
}

void DatabaseCursorState::DataSize(void* state, void(*callback)(void*, int, int), bool blocking) {
  context_->GetMainTaskRunner()->PostTask(
    FROM_HERE,
    base::BindOnce(&DatabaseCursorState::DataSizeImpl,
      base::Unretained(this),
      base::Unretained(state), 
      base::Unretained(callback),
      blocking));
}

void DatabaseCursorState::Count(void* state, void(*callback)(void*, int, int), bool blocking) {
  context_->GetMainTaskRunner()->PostTask(
    FROM_HERE,
    base::BindOnce(&DatabaseCursorState::CountImpl,
      base::Unretained(this),
      base::Unretained(state), 
      base::Unretained(callback),
      blocking));
}

void DatabaseCursorState::GetData(void* state, void(*callback)(void*, int, const uint8_t*, int), bool blocking) {
  context_->GetMainTaskRunner()->PostTask(
    FROM_HERE,
    base::BindOnce(&DatabaseCursorState::GetDataImpl,
      base::Unretained(this), 
      base::Unretained(state), 
      base::Unretained(callback),
      blocking));
}

void DatabaseCursorState::GetKeyValue(void* state, void(*callback)(void*, int, const uint8_t*, int, const uint8_t*, int), bool blocking) {
  context_->GetMainTaskRunner()->PostTask(
    FROM_HERE,
    base::BindOnce(&DatabaseCursorState::GetKeyValueImpl,
      base::Unretained(this), 
      base::Unretained(state), 
      base::Unretained(callback),
      blocking));
}

void DatabaseCursorState::Get(const std::vector<uint8_t>& key, void* state, void(*callback)(void*, int, const uint8_t*, int), bool blocking) {
   context_->GetMainTaskRunner()->PostTask(
    FROM_HERE,
    base::BindOnce(&DatabaseCursorState::GetImpl,
      base::Unretained(this),
      key,
      base::Unretained(state), 
      base::Unretained(callback),
      blocking));
}

void DatabaseCursorState::Insert(common::mojom::KeyValuePtr kv, void* state, void(*callback)(void*, int), bool blocking) {
  context_->GetMainTaskRunner()->PostTask(
    FROM_HERE,
    base::BindOnce(&DatabaseCursorState::InsertImpl,
      base::Unretained(this),
      base::Passed(std::move(kv)), 
      base::Unretained(state), 
      base::Unretained(callback),     
      blocking));
}

void DatabaseCursorState::Delete(void* state, void(*callback)(void*, int), bool blocking) {
  context_->GetMainTaskRunner()->PostTask(
    FROM_HERE,
    base::BindOnce(&DatabaseCursorState::DeleteImpl,
    base::Unretained(this), 
    base::Unretained(state), 
      base::Unretained(callback),
    blocking));
}

void DatabaseCursorState::Commit(void* state, void(*callback)(void*, int), bool blocking) {
  context_->GetMainTaskRunner()->PostTask(
    FROM_HERE,
    base::BindOnce(&DatabaseCursorState::CommitImpl,
    base::Unretained(this), 
    base::Unretained(state), 
    base::Unretained(callback),
    blocking));
}

void DatabaseCursorState::Rollback(void* state, void(*callback)(void*, int), bool blocking) {
  context_->GetMainTaskRunner()->PostTask(
    FROM_HERE,
    base::BindOnce(&DatabaseCursorState::RollbackImpl,
    base::Unretained(this), 
    base::Unretained(state), 
    base::Unretained(callback),
    blocking));
}

void DatabaseCursorState::IsValidImpl(void* state, void(*callback)(void*, int), bool blocking) {
  cursor_->IsValid(
    base::Bind(&DatabaseCursorState::OnIsValid, 
        base::Unretained(this),
        blocking,
        base::Unretained(state),
        base::Unretained(callback)));
}

void DatabaseCursorState::FirstImpl(void* state, void(*callback)(void*, int), bool blocking) {
  cursor_->First(
    base::Bind(&DatabaseCursorState::OnFirst, 
        base::Unretained(this),
        blocking, 
        base::Unretained(state), 
        base::Unretained(callback)));
}

void DatabaseCursorState::LastImpl(void* state, void(*callback)(void*, int), bool blocking) {
  cursor_->Last(
    base::Bind(&DatabaseCursorState::OnLast, 
        base::Unretained(this),
        blocking, 
        base::Unretained(state), 
        base::Unretained(callback)));
}

void DatabaseCursorState::PreviousImpl(void* state, void(*callback)(void*, int), bool blocking) {
  cursor_->Previous(
    base::Bind(&DatabaseCursorState::OnPrevious, 
        base::Unretained(this),
        blocking, 
        base::Unretained(state), 
        base::Unretained(callback)));
}

void DatabaseCursorState::NextImpl(void* state, void(*callback)(void*, int), bool blocking) {
  cursor_->Next(
    base::Bind(&DatabaseCursorState::OnNext, 
        base::Unretained(this),
        blocking, 
        base::Unretained(state), 
        base::Unretained(callback)));
}

void DatabaseCursorState::SeekToImpl(std::vector<uint8_t> key, common::mojom::Seek seek, void* state, void(*callback)(void*, int, int), bool blocking) {
  cursor_->SeekTo(
      std::move(key),
      seek, 
      base::Bind(&DatabaseCursorState::OnSeekTo, 
        base::Unretained(this),
        blocking, 
        base::Unretained(state), 
        base::Unretained(callback)));
}

void DatabaseCursorState::DataSizeImpl(void* state, void(*callback)(void*, int, int), bool blocking) {
  cursor_->DataSize(
    base::Bind(&DatabaseCursorState::OnDataSize, 
        base::Unretained(this),
        blocking,
        base::Unretained(state), 
        base::Unretained(callback)));
}

void DatabaseCursorState::CountImpl(void* state, void(*callback)(void*, int, int), bool blocking) {
  cursor_->Count(
    base::Bind(&DatabaseCursorState::OnCount, 
        base::Unretained(this),
        blocking,
        base::Unretained(state), 
        base::Unretained(callback)));
}

void DatabaseCursorState::GetDataImpl(void* state, void(*callback)(void*, int, const uint8_t*, int), bool blocking) {
  cursor_->GetData(
    base::Bind(&DatabaseCursorState::OnGetData, 
        base::Unretained(this),
        blocking, 
        base::Unretained(state), 
        base::Unretained(callback)));
}

void DatabaseCursorState::GetKeyValueImpl(void* state, void(*callback)(void*, int, const uint8_t*, int, const uint8_t*, int), bool blocking) {
  cursor_->GetKeyValue(
    base::Bind(&DatabaseCursorState::OnGetKeyValue, 
        base::Unretained(this),
        blocking,
        base::Unretained(state), 
        base::Unretained(callback)));
}

void DatabaseCursorState::GetImpl(const std::vector<uint8_t>& key, void* state, void(*callback)(void*, int, const uint8_t*, int), bool blocking) {
  cursor_->Get(
    key,
    base::Bind(&DatabaseCursorState::OnGet, 
      base::Unretained(this),
        blocking,
        base::Unretained(state), 
        base::Unretained(callback)));
}

void DatabaseCursorState::InsertImpl(common::mojom::KeyValuePtr kv, void* state, void(*callback)(void*, int), bool blocking) {
  cursor_->Insert(std::move(kv),
      base::Bind(&DatabaseCursorState::OnInsert, 
        base::Unretained(this),
        blocking, 
        base::Unretained(state), 
        base::Unretained(callback)));
}

void DatabaseCursorState::DeleteImpl(void* state, void(*callback)(void*, int), bool blocking) {
  cursor_->Delete(
    base::Bind(&DatabaseCursorState::OnDelete, 
        base::Unretained(this),
        blocking, 
        base::Unretained(state), 
        base::Unretained(callback)));
}

void DatabaseCursorState::CommitImpl(void* state, void(*callback)(void*, int), bool blocking) {
  cursor_->Commit(
    base::Bind(&DatabaseCursorState::OnCommit, 
        base::Unretained(this),
        blocking, 
        base::Unretained(state), 
        base::Unretained(callback)));
}

void DatabaseCursorState::RollbackImpl(void* state, void(*callback)(void*, int), bool blocking) {
  cursor_->Rollback(
    base::Bind(&DatabaseCursorState::OnRollback, 
        base::Unretained(this),
        blocking, 
        base::Unretained(state), 
        base::Unretained(callback)));
}

void DatabaseCursorState::OnCursorAvailable(common::mojom::DataCursorPtr cursor) {
  //DLOG(INFO) << "DatabaseCursorState::OnCursorAvailable";
  cursor_ = std::move(cursor);
  module_task_runner_->PostTask(
    FROM_HERE, 
    base::BindOnce(&RunCursorAvailableCallback, 
      base::Unretained(state_), 
      base::Unretained(this), 
      base::Unretained(callback_)));
}

void DatabaseCursorState::OnIsValid(bool blocking, void* state, void(*callback)(void*, int), bool valid) {
  //DLOG(INFO) << "DatabaseCursorState::OnIsValid";
  if (blocking) {
    base::PostTaskWithTraits(
      FROM_HERE,
      { base::MayBlock(), 
        base::WithBaseSyncPrimitives() },
      base::BindOnce(&RunCursorIsValidCallback, 
        base::Unretained(state), 
        valid ?  1 : 0, 
        base::Unretained(callback)));
    //RunCursorIsValidCallback(state, valid ?  1 : 0, callback);
  } else {
    module_task_runner_->PostTask(
      FROM_HERE, 
      base::BindOnce(&RunCursorIsValidCallback, 
        base::Unretained(state), 
        valid ?  1 : 0, 
        base::Unretained(callback)));
  }
}

void DatabaseCursorState::OnFirst(bool blocking, void* state, void(*callback)(void*, int), int32_t status) {
  if (blocking) {
    base::PostTaskWithTraits(
      FROM_HERE,
      { base::MayBlock(), 
        base::WithBaseSyncPrimitives() },
      base::BindOnce(&RunStatusCallback, 
        base::Unretained(state),
        status,
        base::Unretained(callback)));
    //RunStatusCallback(state, status, callback);
  } else {
    module_task_runner_->PostTask(
      FROM_HERE, 
      base::BindOnce(&RunStatusCallback, 
        base::Unretained(state),
        status,
        base::Unretained(callback)));
  }
}

void DatabaseCursorState::OnLast(bool blocking, void* state, void(*callback)(void*, int), int32_t status) {
  if (blocking) {
    base::PostTaskWithTraits(
      FROM_HERE,
      { base::MayBlock(), 
        base::WithBaseSyncPrimitives() },
       base::BindOnce(&RunStatusCallback, 
        base::Unretained(state),
        status,
        base::Unretained(callback)));
    //RunStatusCallback(state, status, callback);
  } else {
    module_task_runner_->PostTask(
      FROM_HERE, 
      base::BindOnce(&RunStatusCallback, 
        base::Unretained(state),
        status,
        base::Unretained(callback)));
  }
}

void DatabaseCursorState::OnPrevious(bool blocking, void* state, void(*callback)(void*, int), int32_t status) {
  if (blocking) {
    base::PostTaskWithTraits(
      FROM_HERE,
      { base::MayBlock(), 
        base::WithBaseSyncPrimitives() },
      base::BindOnce(&RunStatusCallback, 
        base::Unretained(state),
        status,
        base::Unretained(callback)));  
    //RunStatusCallback(state, status, callback);
  } else {
    module_task_runner_->PostTask(
      FROM_HERE, 
      base::BindOnce(&RunStatusCallback, 
        base::Unretained(state),
        status,
        base::Unretained(callback)));
  }
}

void DatabaseCursorState::OnNext(bool blocking, void* state, void(*callback)(void*, int), int32_t status) {
  if (blocking) {
    RunStatusCallback(state, status, callback);
  } else {
    module_task_runner_->PostTask(
      FROM_HERE, 
      base::BindOnce(&RunStatusCallback, 
        base::Unretained(state),
        status,
        base::Unretained(callback)));
  }
}

void DatabaseCursorState::OnSeekTo(bool blocking, void* state, void(*callback)(void*, int, int), int32_t result, bool match) {
  //DLOG(INFO) << "DatabaseCursorState::OnSeekTo";
  if (blocking) {
    RunCursorSeekToCallback(state, result, match ? 1 : 0, callback);
  } else {
    module_task_runner_->PostTask(
      FROM_HERE, 
      base::BindOnce(&RunCursorSeekToCallback, 
        base::Unretained(state), 
        result, 
        match ?  1 : 0,
        base::Unretained(callback)));
  }
}

void DatabaseCursorState::OnDataSize(bool blocking, void* state, void(*callback)(void*, int, int), int32_t status, int64_t size) {
  //DLOG(INFO) << "DatabaseCursorState::OnDataSize";
  if (blocking) {
    RunCursorDataSizeCallback(state, status, size, callback);
  } else {
    module_task_runner_->PostTask(
      FROM_HERE, 
      base::BindOnce(&RunCursorDataSizeCallback, 
        base::Unretained(state),
        status,
        static_cast<int>(size),
        base::Unretained(callback)));
  }
}

void DatabaseCursorState::OnCount(bool blocking, void* state, void(*callback)(void*, int, int), int32_t status, int64_t items) {
  //DLOG(INFO) << "DatabaseCursorState::OnCount";
  if (blocking) {
    RunCursorCountCallback(state, status, static_cast<int>(items), callback);
  } else {
    module_task_runner_->PostTask(
      FROM_HERE, 
      base::BindOnce(&RunCursorCountCallback, 
        base::Unretained(state),
        status, 
        static_cast<int>(items),
        base::Unretained(callback)));
  }
}

void DatabaseCursorState::OnGetData(bool blocking, void* state, void(*callback)(void*, int, const uint8_t*, int), int32_t status, const std::vector<uint8_t>& data) {
  //DLOG(INFO) << "DatabaseCursorState::OnGetData";
  if (blocking) {
    RunCursorGetDataCallback(state, status, data, callback);
  } else {
    module_task_runner_->PostTask(
      FROM_HERE, 
      base::BindOnce(&RunCursorGetDataCallback, 
        base::Unretained(state), 
        status, 
        data,
        base::Unretained(callback)));
  }
}

void DatabaseCursorState::OnGetKeyValue(bool blocking, void* state, void(*callback)(void*, int, const uint8_t*, int, const uint8_t*, int), int32_t status, common::mojom::KeyValuePtr kv) {
  //DLOG(INFO) << "DatabaseCursorState::OnGetKeyValue: k: " << std::string(reinterpret_cast<const char*>(&kv->key[0]), kv->key.size()) << " v:" << std::string(reinterpret_cast<const char*>(&kv->value[0]), kv->value.size());
  if (blocking) {
    RunCursorGetKeyValueCallback(state, status, std::move(kv), callback);
  } else {
    module_task_runner_->PostTask(
      FROM_HERE, 
      base::BindOnce(&RunCursorGetKeyValueCallback, 
        base::Unretained(state),
        status, 
        base::Passed(std::move(kv)),
        base::Unretained(callback)));
  }
}

void DatabaseCursorState::OnGet(bool blocking, void* state, void(*callback)(void*, int, const uint8_t*, int), int32_t status, common::mojom::KeyValuePtr kv) {
  //DLOG(INFO) << "DatabaseCursorState::OnGet";
  if (blocking) {
    RunCursorGetCallback(state, status, std::move(kv), callback);
  } else {
    module_task_runner_->PostTask(
      FROM_HERE, 
      base::BindOnce(&RunCursorGetCallback, 
        base::Unretained(state), 
        status, 
        base::Passed(std::move(kv)),
        base::Unretained(callback)));
  }
}

void DatabaseCursorState::OnInsert(bool blocking, void* state, void(*callback)(void*, int), int32_t status) {
  if (blocking) {
    RunStatusCallback(state, status, callback);
  } else {
    module_task_runner_->PostTask(
      FROM_HERE, 
      base::BindOnce(&RunStatusCallback, 
        base::Unretained(state),
        status,
        base::Unretained(callback)));
  }
}

void DatabaseCursorState::OnDelete(bool blocking, void* state, void(*callback)(void*, int), int32_t status) {
  if (blocking) {
    RunStatusCallback(state, status, callback);
  } else {
    module_task_runner_->PostTask(
      FROM_HERE, 
      base::BindOnce(&RunStatusCallback, 
        base::Unretained(state),
        status,
        base::Unretained(callback)));
  }
}

void DatabaseCursorState::OnCommit(bool blocking, void* state, void(*callback)(void*, int), int32_t status) {
  if (blocking) {
    RunStatusCallback(state, status, callback);
  } else {
    module_task_runner_->PostTask(
      FROM_HERE, 
      base::BindOnce(&RunStatusCallback, 
        base::Unretained(state),
        status,
        base::Unretained(callback)));
  }
}

void DatabaseCursorState::OnRollback(bool blocking, void* state, void(*callback)(void*, int), int32_t status) {
  if (blocking) {
    RunStatusCallback(state, status, callback);
  } else {
    module_task_runner_->PostTask(
      FROM_HERE, 
      base::BindOnce(&RunStatusCallback, 
        base::Unretained(state),
        status,
        base::Unretained(callback)));
  }
}


//
//
//
//
//
//

SQLCursorState::SQLCursorState(
  const scoped_refptr<domain::StorageContext>& context, 
  scoped_refptr<base::SingleThreadTaskRunner> module_task_runner,
  void* state, void (*callback)(void*, void*)):
 context_(context),
 module_task_runner_(module_task_runner),
 state_(state),
 callback_(callback) {

}

SQLCursorState::~SQLCursorState() {
  module_task_runner_ = nullptr;
  if (main_task_runner_) {
    main_task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&DeleteSQLCursorOnMainThread, base::Passed(std::move(sql_cursor_))));
  }
}

void SQLCursorState::IsValid(void* state, void(*callback)(void*, int), bool blocking) {
  context_->GetMainTaskRunner()->PostTask(
    FROM_HERE,
    base::BindOnce(&SQLCursorState::IsValidImpl,
      base::Unretained(this),
      base::Unretained(state), 
      base::Unretained(callback),
      blocking)); 
}

void SQLCursorState::First(void* state, void(*callback)(void*, int), bool blocking) {
  context_->GetMainTaskRunner()->PostTask(
    FROM_HERE,
    base::BindOnce(&SQLCursorState::FirstImpl, base::Unretained(this), 
      base::Unretained(state), 
      base::Unretained(callback),
      blocking));
}

void SQLCursorState::Last(void* state, void(*callback)(void*, int), bool blocking) {
  context_->GetMainTaskRunner()->PostTask(
    FROM_HERE,
    base::BindOnce(&SQLCursorState::Last, base::Unretained(this), 
      base::Unretained(state), 
      base::Unretained(callback),
      blocking));
}

void SQLCursorState::Previous(void* state, void(*callback)(void*, int), bool blocking) {
  context_->GetMainTaskRunner()->PostTask(
    FROM_HERE,
    base::BindOnce(&SQLCursorState::PreviousImpl,
      base::Unretained(this), 
      base::Unretained(state), 
      base::Unretained(callback),
      blocking));
}

void SQLCursorState::Next(void* state, void(*callback)(void*, int), bool blocking) {
  context_->GetMainTaskRunner()->PostTask(
    FROM_HERE,
    base::BindOnce(&SQLCursorState::NextImpl,
      base::Unretained(this), 
      base::Unretained(state), 
      base::Unretained(callback),
      blocking));
}

void SQLCursorState::GetBlob(const std::vector<int8_t>& key, void* state, void(*callback)(void*, int, const uint8_t*, int), bool blocking) {
  context_->GetMainTaskRunner()->PostTask(
    FROM_HERE,
    base::BindOnce(&SQLCursorState::GetBlobImpl,
      base::Unretained(this),
      key,
      base::Unretained(state), 
      base::Unretained(callback),
      blocking));
}

void SQLCursorState::GetString(const std::vector<int8_t>& key, void* state, void(*callback)(void*, int, const int8_t*, int), bool blocking) {
  context_->GetMainTaskRunner()->PostTask(
    FROM_HERE,
    base::BindOnce(&SQLCursorState::GetStringImpl,
      base::Unretained(this),
      key,
      base::Unretained(state), 
      base::Unretained(callback),
      blocking));
}

void SQLCursorState::GetInt(const std::vector<int8_t>& key, void* state, void(*callback)(void*, int, int), bool blocking) {
  context_->GetMainTaskRunner()->PostTask(
    FROM_HERE,
    base::BindOnce(&SQLCursorState::GetIntImpl,
      base::Unretained(this),
      key,
      base::Unretained(state), 
      base::Unretained(callback),
      blocking));
}

void SQLCursorState::GetDouble(const std::vector<int8_t>& key, void* state, void(*callback)(void*, int, double), bool blocking) {
  context_->GetMainTaskRunner()->PostTask(
    FROM_HERE,
    base::BindOnce(&SQLCursorState::GetDoubleImpl,
      base::Unretained(this),
      key,
      base::Unretained(state), 
      base::Unretained(callback),
      blocking));
}  

void SQLCursorState::Commit(void* state, void(*callback)(void*, int), bool blocking) {
  context_->GetMainTaskRunner()->PostTask(
    FROM_HERE,
    base::BindOnce(&SQLCursorState::CommitImpl,
    base::Unretained(this), 
    base::Unretained(state), 
    base::Unretained(callback),
    blocking));
}

void SQLCursorState::Rollback(void* state, void(*callback)(void*, int), bool blocking) {
  context_->GetMainTaskRunner()->PostTask(
    FROM_HERE,
    base::BindOnce(&SQLCursorState::RollbackImpl,
    base::Unretained(this), 
    base::Unretained(state), 
    base::Unretained(callback),
    blocking));
}

void SQLCursorState::IsValidImpl(void* state, void(*callback)(void*, int), bool blocking) {
  sql_cursor_->IsValid(
    base::Bind(&SQLCursorState::OnIsValid, 
        base::Unretained(this),
        blocking,
        base::Unretained(state),
        base::Unretained(callback)));
}

void SQLCursorState::FirstImpl(void* state, void(*callback)(void*, int), bool blocking) {
  sql_cursor_->First(
    base::Bind(&SQLCursorState::OnFirst, 
        base::Unretained(this),
        blocking, 
        base::Unretained(state), 
        base::Unretained(callback)));
}

void SQLCursorState::LastImpl(void* state, void(*callback)(void*, int), bool blocking) {
  sql_cursor_->Last(
    base::Bind(&SQLCursorState::OnLast, 
        base::Unretained(this),
        blocking, 
        base::Unretained(state), 
        base::Unretained(callback)));
}

void SQLCursorState::PreviousImpl(void* state, void(*callback)(void*, int), bool blocking) {
  sql_cursor_->Previous(
    base::Bind(&SQLCursorState::OnPrevious, 
        base::Unretained(this),
        blocking, 
        base::Unretained(state), 
        base::Unretained(callback)));
}

void SQLCursorState::NextImpl(void* state, void(*callback)(void*, int), bool blocking) {
  sql_cursor_->Next(
    base::Bind(&SQLCursorState::OnNext, 
        base::Unretained(this),
        blocking, 
        base::Unretained(state), 
        base::Unretained(callback)));
}

void SQLCursorState::GetBlobImpl(const std::vector<int8_t>& key, void* state, void(*callback)(void*, int, const uint8_t*, int), bool blocking) {
  sql_cursor_->GetBlob(
    key,
    base::Bind(&SQLCursorState::OnGetBlob, 
      base::Unretained(this),
        blocking,
        base::Unretained(state), 
        base::Unretained(callback)));
}

void SQLCursorState::GetStringImpl(const std::vector<int8_t>& key, void* state, void(*callback)(void*, int, const int8_t*, int), bool blocking) {
  sql_cursor_->GetString(
    key,
    base::Bind(&SQLCursorState::OnGetString, 
      base::Unretained(this),
        blocking,
        base::Unretained(state), 
        base::Unretained(callback)));
}

void SQLCursorState::GetIntImpl(const std::vector<int8_t>& key, void* state, void(*callback)(void*, int, int), bool blocking) {
  sql_cursor_->GetInt32(
    key,
    base::Bind(&SQLCursorState::OnGetInt, 
      base::Unretained(this),
        blocking,
        base::Unretained(state), 
        base::Unretained(callback)));
}

void SQLCursorState::GetDoubleImpl(const std::vector<int8_t>& key, void* state, void(*callback)(void*, int, double), bool blocking) {
  sql_cursor_->GetDouble(
    key,
    base::Bind(&SQLCursorState::OnGetDouble, 
      base::Unretained(this),
        blocking,
        base::Unretained(state), 
        base::Unretained(callback)));
} 

void SQLCursorState::CommitImpl(void* state, void(*callback)(void*, int), bool blocking) {
  // sql_cursor_->Commit(
  //   base::Bind(&SQLCursorState::OnCommit, 
  //       base::Unretained(this),
  //       blocking, 
  //       base::Unretained(state), 
  //       base::Unretained(callback)));
}

void SQLCursorState::RollbackImpl(void* state, void(*callback)(void*, int), bool blocking) {
  // sql_cursor_->Rollback(
  //   base::Bind(&SQLCursorState::OnRollback, 
  //       base::Unretained(this),
  //       blocking, 
  //       base::Unretained(state), 
  //       base::Unretained(callback)));
}

void SQLCursorState::OnSQLCursorAvailable(common::mojom::SQLCursorPtr cursor) {
  sql_cursor_ = std::move(cursor);
  main_task_runner_ = base::ThreadTaskRunnerHandle::Get();
  module_task_runner_->PostTask(
    FROM_HERE, 
    base::BindOnce(&RunSQLCursorAvailableCallback, 
      base::Unretained(state_), 
      base::Unretained(this), 
      base::Unretained(callback_)));
}

void SQLCursorState::OnIsValid(bool blocking, void* state, void(*callback)(void*, int), bool valid) {
  //DLOG(INFO) << "SQLCursorState::OnIsValid";
  if (blocking) {
    base::PostTaskWithTraits(
      FROM_HERE,
      { base::MayBlock(), 
        base::WithBaseSyncPrimitives() },
      base::BindOnce(&RunCursorIsValidCallback, 
        base::Unretained(state), 
        valid ?  1 : 0, 
        base::Unretained(callback)));
    //RunCursorIsValidCallback(state, valid ?  1 : 0, callback);
  } else {
    module_task_runner_->PostTask(
      FROM_HERE, 
      base::BindOnce(&RunCursorIsValidCallback, 
        base::Unretained(state), 
        valid ?  1 : 0, 
        base::Unretained(callback)));
  }
}

void SQLCursorState::OnFirst(bool blocking, void* state, void(*callback)(void*, int), int32_t status) {
  if (blocking) {
    base::PostTaskWithTraits(
      FROM_HERE,
      { base::MayBlock(), 
        base::WithBaseSyncPrimitives() },
      base::BindOnce(&RunStatusCallback, 
        base::Unretained(state),
        status,
        base::Unretained(callback)));
    //RunStatusCallback(state, status, callback);
  } else {
    module_task_runner_->PostTask(
      FROM_HERE, 
      base::BindOnce(&RunStatusCallback, 
        base::Unretained(state),
        status,
        base::Unretained(callback)));
  }
}

void SQLCursorState::OnLast(bool blocking, void* state, void(*callback)(void*, int), int32_t status) {
  if (blocking) {
    base::PostTaskWithTraits(
      FROM_HERE,
      { base::MayBlock(), 
        base::WithBaseSyncPrimitives() },
       base::BindOnce(&RunStatusCallback, 
        base::Unretained(state),
        status,
        base::Unretained(callback)));
    //RunStatusCallback(state, status, callback);
  } else {
    module_task_runner_->PostTask(
      FROM_HERE, 
      base::BindOnce(&RunStatusCallback, 
        base::Unretained(state),
        status,
        base::Unretained(callback)));
  }
}

void SQLCursorState::OnPrevious(bool blocking, void* state, void(*callback)(void*, int), int32_t status) {
  if (blocking) {
    base::PostTaskWithTraits(
      FROM_HERE,
      { base::MayBlock(), 
        base::WithBaseSyncPrimitives() },
      base::BindOnce(&RunStatusCallback, 
        base::Unretained(state),
        status,
        base::Unretained(callback)));  
    //RunStatusCallback(state, status, callback);
  } else {
    module_task_runner_->PostTask(
      FROM_HERE, 
      base::BindOnce(&RunStatusCallback, 
        base::Unretained(state),
        status,
        base::Unretained(callback)));
  }
}

void SQLCursorState::OnNext(bool blocking, void* state, void(*callback)(void*, int), int32_t status) {
  if (blocking) {
    RunStatusCallback(state, status, callback);
  } else {
    module_task_runner_->PostTask(
      FROM_HERE, 
      base::BindOnce(&RunStatusCallback, 
        base::Unretained(state),
        status,
        base::Unretained(callback)));
  }
}

void SQLCursorState::OnGetBlob(bool blocking, void* state, void(*callback)(void*, int, const uint8_t*, int), int32_t status, const std::vector<uint8_t>& data) {
  if (blocking) {
    RunCursorGetBlobCallback(state, status, data, callback);
  } else {
    module_task_runner_->PostTask(
      FROM_HERE, 
      base::BindOnce(&RunCursorGetBlobCallback, 
        base::Unretained(state), 
        status, 
        data,
        base::Unretained(callback)));
  }
}

void SQLCursorState::OnGetString(bool blocking, void* state, void(*callback)(void*, int, const int8_t*, int), int32_t status, const std::string& data) {
  if (blocking) {
    RunCursorGetStringCallback(state, status, data, callback);
  } else {
    module_task_runner_->PostTask(
      FROM_HERE, 
      base::BindOnce(&RunCursorGetStringCallback, 
        base::Unretained(state), 
        status, 
        data,
        base::Unretained(callback)));
  }
}

void SQLCursorState::OnGetInt(bool blocking, void* state, void(*callback)(void*, int,  int), int32_t status, int32_t value) {
  if (blocking) {
    RunCursorGetIntCallback(state, status, value, callback);
  } else {
    module_task_runner_->PostTask(
      FROM_HERE, 
      base::BindOnce(&RunCursorGetIntCallback, 
        base::Unretained(state), 
        status, 
        value,
        base::Unretained(callback)));
  }
}

void SQLCursorState::OnGetDouble(bool blocking, void* state, void(*callback)(void*, int, double), int32_t status, double v) {
  if (blocking) {
    RunCursorGetDoubleCallback(state, status, v, callback);
  } else {
    module_task_runner_->PostTask(
      FROM_HERE, 
      base::BindOnce(&RunCursorGetDoubleCallback, 
        base::Unretained(state), 
        status, 
        v,
        base::Unretained(callback)));
  }
}

void SQLCursorState::OnCommit(bool blocking, void* state, void(*callback)(void*, int), int32_t status) {
  if (blocking) {
    RunStatusCallback(state, status, callback);
  } else {
    module_task_runner_->PostTask(
      FROM_HERE, 
      base::BindOnce(&RunStatusCallback, 
        base::Unretained(state),
        status,
        base::Unretained(callback)));
  }
}

void SQLCursorState::OnRollback(bool blocking, void* state, void(*callback)(void*, int), int32_t status) {
  if (blocking) {
    RunStatusCallback(state, status, callback);
  } else {
    module_task_runner_->PostTask(
      FROM_HERE, 
      base::BindOnce(&RunStatusCallback, 
        base::Unretained(state),
        status,
        base::Unretained(callback)));
  }
}


StorageState::StorageState(
  scoped_refptr<domain::StorageContext> context,
  domain::ModuleState* module,
  void* state,
  StorageShareCallbacks callbacks): 
    context_(std::move(context)),
    module_(module),
    state_(state),
    callbacks_(std::move(callbacks)),
    weak_factory_(this) {

  context_->AddShareObserver(weak_factory_.GetWeakPtr());
}

StorageState::~StorageState() {
  context_->RemoveShareObserver(this);
}

void StorageState::GetAllocatedSize(void* ptr, void(*cb)(void*, int64_t)) {
  context_->GetMainTaskRunner()->PostTask(
    FROM_HERE,
    base::BindOnce(&StorageState::GetAllocatedSizeImpl,
      base::Unretained(this),
      base::Unretained(ptr),
      base::Unretained(cb)));
}

void StorageState::ListShares(void* ptr, void(*cb)(void*,
   int /* info count*/,
   const char**,
   const char**,
   int32_t*,
   int32_t*,
   const char**,
   int64_t*,
   int32_t*,
   int32_t*,
   int64_t*,
   int32_t*)) {
  context_->GetMainTaskRunner()->PostTask(
    FROM_HERE,
    base::BindOnce(&StorageState::ListSharesImpl,
      base::Unretained(this),
      base::Unretained(ptr),
      base::Unretained(cb)));
}

void StorageState::DatabaseCreate(void* ptr, const std::string& name, const std::vector<std::string>& keyspaces, bool in_memory, void(*cb)(void*, int, DatabaseRef)) {
  context_->GetMainTaskRunner()->PostTask(
    FROM_HERE,
    base::BindOnce(&StorageState::DatabaseCreateImpl,
      base::Unretained(this),
      base::Unretained(ptr),
      name,
      keyspaces,
      in_memory,
      base::Unretained(cb))); 
}

void StorageState::DatabaseExists(void* ptr, const std::string& name, void(*cb)(void*, int)) {
  //context_->GetMainTaskRunner()->PostTask(
  //module_->GetModuleTaskRunner()->PostTask(
  context_->GetIOTaskRunner()->PostTask(
    FROM_HERE,
    base::BindOnce(&StorageState::DatabaseExistsImpl,
      base::Unretained(this),
      base::Unretained(ptr),
      name,
      base::Unretained(cb)));
}

void StorageState::DatabaseOpen(void* ptr, const std::string& name, bool create_if_not_exists, void(*cb)(void*, int, DatabaseRef)) {
  context_->GetMainTaskRunner()->PostTask(
    FROM_HERE,
    base::BindOnce(&StorageState::DatabaseOpenImpl,
      base::Unretained(this),
      base::Unretained(ptr),
      name,
      create_if_not_exists,
      base::Unretained(cb))); 
}

void StorageState::DatabaseDrop(void* ptr, const std::string& name, void(*cb)(void*, int)) {
  context_->GetMainTaskRunner()->PostTask(
    FROM_HERE,
    base::BindOnce(&StorageState::DatabaseDropImpl,
      base::Unretained(this),
      base::Unretained(ptr),
      name,
      base::Unretained(cb)));
}

void StorageState::FilebaseCreateWithPath(void* ptr, const std::string& name, const std::string& source_path, void(*cb)(void*, int, FilebaseRef)) {
  context_->GetMainTaskRunner()->PostTask(
    FROM_HERE,
    base::BindOnce(&StorageState::FilebaseCreateWithPathImpl,
      base::Unretained(this),
      base::Unretained(ptr),
      name,
      source_path,
      base::Unretained(cb))); 
}

void StorageState::FilebaseCreateWithInfohash(void* ptr, const std::string& name, const std::string& infohash, void(*cb)(void*, int, FilebaseRef)) {
  context_->GetMainTaskRunner()->PostTask(
    FROM_HERE,
    base::BindOnce(&StorageState::FilebaseCreateWithInfohashImpl,
      base::Unretained(this),
      base::Unretained(ptr),
      name,
      infohash,
      base::Unretained(cb))); 
}

void StorageState::FilebaseOpen(void* ptr, const std::string& name, void(*cb)(void*, int, FilebaseRef)) {
  context_->GetMainTaskRunner()->PostTask(
    FROM_HERE,
    base::BindOnce(&StorageState::FilebaseOpenImpl,
      base::Unretained(this),
      base::Unretained(ptr),
      name,
      base::Unretained(cb)));
}

void StorageState::FilebaseListFiles(void* ptr, const std::string& name, void(*cb)(
    void*, 
    int,
    const char**,
    const char**,
    const char**,
    int32_t*,
    int64_t*,
    int32_t*,
    int32_t*,
    int32_t*,
    int64_t*)) {
  context_->GetMainTaskRunner()->PostTask(
    FROM_HERE,
    base::BindOnce(&StorageState::FilebaseListFilesImpl,
      base::Unretained(this),
      base::Unretained(ptr),
      name,
      base::Unretained(cb)));
}

void StorageState::FilebaseExists(void* ptr, const std::string& name, void(*cb)(void*, int)) {
  context_->GetIOTaskRunner()->PostTask(
    FROM_HERE,
    base::BindOnce(&StorageState::FilebaseExistsImpl,
      base::Unretained(this),
      base::Unretained(ptr),
      name,
      base::Unretained(cb)));
}


void StorageState::GetAllocatedSizeImpl(void* ptr, void(*cb)(void*, int64_t)) {
  context_->GetAllocatedSize(
    base::Bind(&StorageState::OnAllocatedSizeReply, 
      base::Unretained(this),
      base::Unretained(ptr),
      base::Unretained(cb)));
}

void StorageState::DatabaseCreateImpl(void* ptr, const std::string& name, const std::vector<std::string>& keyspaces, bool in_memory, void(*cb)(void*, int, DatabaseRef)) {
  // its basically a create share, with type of DATA
  context_->share().CreateShareWithPath(
    common::mojom::StorageType::kData,
    name,
    keyspaces,
    std::string(),
    in_memory,
    base::Bind(&StorageState::OnDatabaseCreate, 
      base::Unretained(this),
      name,
      base::Unretained(ptr),
      base::Unretained(cb)));
}

void StorageState::DatabaseOpenImpl(void* ptr, const std::string& name, bool create_if_not_exists, void(*cb)(void*, int, DatabaseRef)) {
  context_->share().OpenShare(
    common::mojom::StorageType::kData,
    name,
    create_if_not_exists,
    base::Bind(&StorageState::OnDatabaseOpen, 
      base::Unretained(this),
      name,
      base::Unretained(ptr),
      base::Unretained(cb)));
}

void StorageState::DatabaseExistsImpl(void* ptr, const std::string& name, void(*cb)(void*, int)) {
  context_->share().ShareExists(
    name,
    base::Bind(&StorageState::OnDatabaseExists, 
      base::Unretained(this),
      base::Unretained(ptr),
      base::Unretained(cb)));
}

void StorageState::DatabaseDropImpl(void* ptr, const std::string& name, void(*cb)(void*, int)) {
  context_->data().Drop(
    name,
    base::Bind(&StorageState::OnDatabaseDrop, 
      base::Unretained(this),
      base::Unretained(ptr),
      base::Unretained(cb))); 
}

void StorageState::ListSharesImpl(void* ptr, void(*cb)(void*,
   int /* info count*/,
   const char**,
   const char**,
   int32_t*,
   int32_t*,
   const char**,
   int64_t*,
   int32_t*,
   int32_t*,
   int64_t*,
   int32_t*)) {
  context_->ListShares(
    base::Bind(&StorageState::OnListShares, 
      base::Unretained(this),
      base::Unretained(ptr),
      base::Unretained(cb)));
}

void StorageState::FilebaseExistsImpl(void* ptr, const std::string& name, void(*cb)(void*, int)) {
  context_->share().ShareExists(
    name,
    base::Bind(&StorageState::OnFilebaseExists, 
      base::Unretained(this),
      base::Unretained(ptr),
      base::Unretained(cb)));
}

void StorageState::FilebaseCreateWithPathImpl(void* ptr, const std::string& name, const std::string& source_path, void(*cb)(void*, int, FilebaseRef)) {
  context_->share().CreateShareWithPath(
    common::mojom::StorageType::kFile,
    name,
    std::vector<std::string>(),
    source_path,
    false,
    base::Bind(&StorageState::OnFilebaseCreate, 
      base::Unretained(this),
      name,
      base::Unretained(ptr),
      base::Unretained(cb)));
}

void StorageState::FilebaseCreateWithInfohashImpl(void* ptr, const std::string& name, const std::string& infohash, void(*cb)(void*, int, FilebaseRef)) {
  context_->share().CreateShareWithInfohash(
    common::mojom::StorageType::kFile,
    name,
    std::vector<std::string>(),
    infohash,
    base::Bind(&StorageState::OnFilebaseCreate, 
      base::Unretained(this),
      name,
      base::Unretained(ptr),
      base::Unretained(cb)));
}

void StorageState::FilebaseOpenImpl(void* ptr, const std::string& name, void(*cb)(void*, int, FilebaseRef)) {
  context_->share().OpenShare(
    common::mojom::StorageType::kFile,
    name,
    false,
    base::Bind(&StorageState::OnFilebaseOpen, 
      base::Unretained(this),
      name,
      base::Unretained(ptr),
      base::Unretained(cb))); 
}

void StorageState::FilebaseListFilesImpl(void* ptr, const std::string& name, void(*cb)(
    void*, 
    int,
    const char**,
    const char**,
    const char**,
    int32_t*,
    int64_t*,
    int32_t*,
    int32_t*,
    int32_t*,
    int64_t*)) {
  context_->file().ListFiles(
    name,
    base::Bind(&StorageState::OnFilebaseListFiles, 
      base::Unretained(this),
      base::Unretained(ptr),
      base::Unretained(cb))); 
}

void StorageState::OnAllocatedSizeReply(void* ptr, void(*cb)(void*, int64_t), int64_t size) {
  module_->GetModuleTaskRunner()->PostTask(
    FROM_HERE, 
    base::BindOnce(cb, base::Unretained(ptr), size));
  //cb(ptr, size);
}

void StorageState::OnListShares(
  void* ptr, 
  void(*cb)(void*,
   int /* info count*/,
   const char**,
   const char**,
   int32_t*,
   int32_t*,
   const char**,
   int64_t*,
   int32_t*,
   int32_t*,
   int64_t*,
   int32_t*), 
  std::vector<common::mojom::ShareInfoPtr> shares) {
  module_->GetModuleTaskRunner()->PostTask(
    FROM_HERE, 
    base::BindOnce(
      &RunListSharesCallback,
      base::Unretained(ptr), 
      base::Passed(std::move(shares)), 
      base::Unretained(cb)));
}

void StorageState::OnDatabaseCreate(const std::string& name, void* ptr, void(*cb)(void*, int, DatabaseRef), int result) {
  DatabaseState* db = result == 0 ? new DatabaseState(name, context_, module_) : nullptr;
  module_->GetModuleTaskRunner()->PostTask(
    FROM_HERE, 
    base::BindOnce(
      &RunDatabaseCallback,
      base::Unretained(ptr), 
      result,
      base::Unretained(db),
      base::Unretained(cb)));
}

void StorageState::OnDatabaseOpen(const std::string& name, void* ptr, void(*cb)(void*, int, DatabaseRef), int result) {
  DatabaseState* db = result == 0 ? new DatabaseState(name, context_, module_) : nullptr;
  module_->GetModuleTaskRunner()->PostTask(
    FROM_HERE, 
    base::BindOnce(
      &RunDatabaseCallback,
      base::Unretained(ptr), 
      result,
      base::Unretained(db),
      base::Unretained(cb)));
}

void StorageState::OnDatabaseDrop(void* ptr, void(*cb)(void*, int), int result) {
  module_->GetModuleTaskRunner()->PostTask(
    FROM_HERE,
    base::BindOnce(
      &RunStatusCallback,
      base::Unretained(ptr), 
      result,
      base::Unretained(cb)));
}

void StorageState::OnDatabaseExists(void* ptr, void(*cb)(void*, int), int result) {
  module_->GetModuleTaskRunner()->PostTask(
    FROM_HERE, 
    base::BindOnce(
      &RunStatusCallback,
      base::Unretained(ptr), 
      result,
      base::Unretained(cb))); 
}

void StorageState::OnFilebaseExists(void* ptr, void(*cb)(void*, int), int result) {
  module_->GetModuleTaskRunner()->PostTask(
    FROM_HERE, 
    base::BindOnce(
      &RunStatusCallback,
      base::Unretained(ptr), 
      result,
      base::Unretained(cb)));
}

void StorageState::OnFilebaseCreate(const std::string& name, void* ptr, void(*cb)(void*, int, FilebaseRef), int result) {
  FilebaseState* fb = result == 0 ? new FilebaseState(name, context_, module_) : nullptr;
  module_->GetModuleTaskRunner()->PostTask(
    FROM_HERE, 
    base::BindOnce(
      &RunFilebaseCallback,
      base::Unretained(ptr), 
      result,
      base::Unretained(fb),
      base::Unretained(cb)));
}

void StorageState::OnFilebaseOpen(const std::string& name, void* ptr, void(*cb)(void*, int, FilebaseRef), int result) {
  FilebaseState* fb = result == 0 ? new FilebaseState(name, context_, module_) : nullptr;
  module_->GetModuleTaskRunner()->PostTask(
    FROM_HERE, 
    base::BindOnce(
      &RunFilebaseCallback,
      base::Unretained(ptr), 
      result,
      base::Unretained(fb),
      base::Unretained(cb)));
}

void StorageState::OnFilebaseListFiles(void* ptr, void(*cb)(
    void*, 
    int,
    const char**,
    const char**,
    const char**,
    int32_t*,
    int64_t*,
    int32_t*,
    int32_t*,
    int32_t*,
    int64_t*), 
  std::vector<common::mojom::ShareStorageEntryPtr> entries) {
  
  module_->GetModuleTaskRunner()->PostTask(
    FROM_HERE, 
    base::BindOnce(
      &RunListFilesCallback,
      base::Unretained(ptr),
      base::Passed(std::move(entries)),
      base::Unretained(cb)));
}

void StorageState::OnShareDHTAnnounceReply(const base::UUID& tid, int32_t peers) {
  callbacks_.OnShareDHTAnnounceReply(state_, (const uint8_t *)tid.to_string().data(), peers);
}

void StorageState::OnShareMetadataReceived(const base::UUID& tid) {
  callbacks_.OnShareMetadataReceived(state_, (const uint8_t *)tid.to_string().data());
}

void StorageState::OnShareMetadataError(const base::UUID& tid, int32_t error) {
  callbacks_.OnShareMetadataError(state_, (const uint8_t *)tid.to_string().data(), error);
}

void StorageState::OnSharePieceReadError(const base::UUID& tid, int32_t piece, int32_t error) {
  callbacks_.OnSharePieceReadError(state_, (const uint8_t *)tid.to_string().data(), piece, error);
}

void StorageState::OnSharePiecePass(const base::UUID& tid, int32_t piece) {
  callbacks_.OnSharePiecePass(state_, (const uint8_t *)tid.to_string().data(), piece);
}

void StorageState::OnSharePieceFailed(const base::UUID& tid, int32_t piece) {
  callbacks_.OnSharePieceFailed(state_, (const uint8_t *)tid.to_string().data(), piece);
}

void StorageState::OnSharePieceRead(const base::UUID& tid, int32_t piece, int64_t offset, int64_t size, int64_t block_size, int32_t result) {
  callbacks_.OnSharePieceRead(state_, (const uint8_t *)tid.to_string().data(), piece, offset, size, block_size, result);
}

void StorageState::OnSharePieceWrite(const base::UUID& tid, int32_t piece, int64_t offset, int64_t size, int64_t block_size, int32_t result) {
  callbacks_.OnSharePieceRead(state_, (const uint8_t *)tid.to_string().data(), piece, offset, size, block_size, result);
}

void StorageState::OnSharePieceHashFailed(const base::UUID& tid, int32_t piece) {
  callbacks_.OnSharePieceHashFailed(state_, (const uint8_t *)tid.to_string().data(), piece);
}

void StorageState::OnShareCheckingFiles(const base::UUID& tid) {
  callbacks_.OnShareCheckingFiles(state_, (const uint8_t *)tid.to_string().data());
}

void StorageState::OnShareDownloadingMetadata(const base::UUID& tid) {
  callbacks_.OnShareDownloadingMetadata(state_, (const uint8_t *)tid.to_string().data());
}

void StorageState::OnShareFileRenamed(const base::UUID& tid, int32_t file_offset, const std::string& name, int32_t error) {
  callbacks_.OnShareFileRenamed(state_, (const uint8_t *)tid.to_string().data(), file_offset, name.c_str(), error);
}

void StorageState::OnShareResumed(const base::UUID& tid) {
  callbacks_.OnShareResumed(state_, (const uint8_t *)tid.to_string().data());
}

void StorageState::OnShareChecked(const base::UUID& tid, common::mojom::DomainStatus status) {
  callbacks_.OnShareChecked(state_, (const uint8_t *)tid.to_string().data(), static_cast<int>(status));
}

void StorageState::OnSharePieceComplete(const base::UUID& tid, uint32_t piece_offset) {
  callbacks_.OnSharePieceComplete(state_, (const uint8_t *)tid.to_string().data(), piece_offset);
}

void StorageState::OnShareFileComplete(const base::UUID& tid, int file_offset) {
  callbacks_.OnShareFileComplete(state_, (const uint8_t *)tid.to_string().data(), file_offset);
}

void StorageState::OnShareDownloading(const base::UUID& tid) {
  callbacks_.OnShareDownloading(state_, (const uint8_t *)tid.to_string().data());
}

void StorageState::OnShareComplete(const base::UUID& tid) {
  callbacks_.OnShareComplete(state_, (const uint8_t *)tid.to_string().data());
}

void StorageState::OnShareSeeding(const base::UUID& tid) {
  callbacks_.OnShareSeeding(state_, (const uint8_t *)tid.to_string().data());
}

void StorageState::OnSharePaused(const base::UUID& tid) {
  callbacks_.OnSharePaused(state_, (const uint8_t *)tid.to_string().data());
}

///
///
///
///

DatabaseState::DatabaseState(
  const std::string& share,
  const scoped_refptr<domain::StorageContext>& context,
  domain::ModuleState* module): 
    share_(share),
    context_(context),
    module_(module) {}

DatabaseState::~DatabaseState() {}

void DatabaseState::DatabaseClose(void* ptr, void(*cb)(void*, int)) {
  context_->GetMainTaskRunner()->PostTask(
    FROM_HERE,
    base::BindOnce(&DatabaseState::DatabaseCloseImpl,
      base::Unretained(this),
      base::Unretained(ptr),
      base::Unretained(cb))); 
}

void DatabaseState::DatabaseCursorCreate(
  void* state, const std::string& keyspace, common::mojom::Order order, bool write, void (*callback)(void*, void*)) {
  //base::WaitableEvent sync {base::WaitableEvent::ResetPolicy::MANUAL, base::WaitableEvent::InitialState::NOT_SIGNALED};
  //common::mojom::DataCursorPtr cursor_ptr;
  auto cursor = std::make_unique<DatabaseCursorState>(context_, module_->GetModuleTaskRunner(), state, callback);
  DatabaseCursorState* ref = cursor.get();
  //DLOG(INFO) << "DatabaseCursorCreate: DatabaseCursorState* = " << ref << " keyspace: " << keyspace;
  context_->GetMainTaskRunner()->PostTask(
    FROM_HERE,
    base::BindOnce(&DatabaseState::DatabaseCursorCreateImpl,
      base::Unretained(this),
      keyspace,
      order,
      write,
      base::Unretained(ref)));
  // TODO: we are on the domain's main thread here..
  // see if theres a better way to pass out the handle
  // One way would be to pass the reference and with a callback
  // on 'DatabaseCursorState' we add the 'DataCursorPtr' handled to us
  // of course until then, the StorageCursor will be useless
  // but at least we handle it and dont need to block
  // (we will probably need to block on StorageCursor's methods
  //  until the DataCursorPtr is available though)

  //sync.Wait();
  cursors_.push_back(std::move(cursor));
}

void DatabaseState::DatabaseExecuteQuery(void* state, const std::string& query, void(*callback)(void*, void*)) {
  auto cursor = std::make_unique<SQLCursorState>(context_, module_->GetModuleTaskRunner(), state, callback);
  SQLCursorState* ref = cursor.get();
  context_->GetMainTaskRunner()->PostTask(
    FROM_HERE,
    base::BindOnce(&DatabaseState::DatabaseExecuteQueryImpl,
      base::Unretained(this),
      query,
      base::Unretained(ref)));
  sql_cursors_.push_back(std::move(cursor));
}

void DatabaseState::DatabaseGet(void* ptr, const std::string& keyspace, const std::string& key, void(*cb)(void*, int, SharedMemoryRef)) {
  context_->GetMainTaskRunner()->PostTask(
    FROM_HERE,
    base::BindOnce(&DatabaseState::DatabaseGetImpl,
      base::Unretained(this),
      base::Unretained(ptr),
      keyspace,
      key,
      base::Unretained(cb))); 
}

void DatabaseState::DatabasePut(void* ptr, const std::string& keyspace, const std::string& key, mojo::ScopedSharedBufferHandle value, void(*cb)(void*, int)) {
  context_->GetMainTaskRunner()->PostTask(
    FROM_HERE,
    base::BindOnce(&DatabaseState::DatabasePutImpl,
      base::Unretained(this),
      base::Unretained(ptr),
      keyspace,
      key,
      std::move(value),
      base::Unretained(cb)));
}

void DatabaseState::DatabaseDelete(void* ptr, const std::string& keyspace, const std::string& key, void(*cb)(void*, int)) {
  context_->GetMainTaskRunner()->PostTask(
    FROM_HERE,
    base::BindOnce(&DatabaseState::DatabaseDeleteImpl,
      base::Unretained(this),
      base::Unretained(ptr),
      keyspace,
      key,
      base::Unretained(cb))); 
}

void DatabaseState::DatabaseDeleteAll(void* ptr, const std::string& keyspace, void(*cb)(void*, int)) {
  context_->GetMainTaskRunner()->PostTask(
    FROM_HERE,
    base::BindOnce(&DatabaseState::DatabaseDeleteAllImpl,
      base::Unretained(this),
      base::Unretained(ptr),
      keyspace,
      base::Unretained(cb)));
}

void DatabaseState::DatabaseKeyspaceCreate(void* ptr, const std::string& keyspace, void(*cb)(void*, int)) {
  context_->GetMainTaskRunner()->PostTask(
    FROM_HERE,
    base::BindOnce(&DatabaseState::DatabaseKeyspaceCreateImpl,
      base::Unretained(this),
      base::Unretained(ptr),
      keyspace,
      base::Unretained(cb)));
}

void DatabaseState::DatabaseKeyspaceDrop(void* ptr, const std::string& keyspace, void(*cb)(void*, int)) {
  context_->GetMainTaskRunner()->PostTask(
    FROM_HERE,
    base::BindOnce(&DatabaseState::DatabaseKeyspaceDropImpl,
      base::Unretained(this),
      base::Unretained(ptr),
      keyspace,
      base::Unretained(cb)));
}

void DatabaseState::DatabaseKeyspaceList(void* ptr, void(*cb)(void*, int, int, const char**)) {
  context_->GetMainTaskRunner()->PostTask(
    FROM_HERE,
    base::BindOnce(&DatabaseState::DatabaseKeyspaceListImpl,
      base::Unretained(this),
      base::Unretained(ptr),
      base::Unretained(cb))); 
}

void DatabaseState::DatabaseCloseImpl(void* ptr, void(*cb)(void*, int)) {
  context_->data().Close(
    share_,
    base::Bind(&DatabaseState::OnDatabaseClose, 
      base::Unretained(this),
      base::Unretained(ptr),
      base::Unretained(cb)));
}

void DatabaseState::DatabasePutImpl(void* ptr, const std::string& keyspace, const std::string& key, mojo::ScopedSharedBufferHandle value, void(*cb)(void*, int)) {
  context_->data().Put(
    share_,
    keyspace,
    key,
    value->GetSize(),
    std::move(value),
    base::Bind(&DatabaseState::OnDatabasePut, 
      base::Unretained(this),
      base::Unretained(ptr),
      base::Unretained(cb)));
}

void DatabaseState::DatabaseGetImpl(void* ptr, const std::string& keyspace, const std::string& key, void(*cb)(void*, int, SharedMemoryRef)) {
  context_->data().GetOnce(
    share_,
    keyspace,
    key,
    base::Bind(&DatabaseState::OnDatabaseGet, 
      base::Unretained(this),
      base::Unretained(ptr),
      base::Unretained(cb)));
}

void DatabaseState::DatabaseDeleteImpl(void* ptr, const std::string& keyspace, const std::string& key, void(*cb)(void*, int)) {
  context_->data().Delete(
    share_,
    keyspace,
    key,
    base::Bind(&DatabaseState::OnDatabaseDelete, 
      base::Unretained(this),
      base::Unretained(ptr),
      base::Unretained(cb)));
}

void DatabaseState::DatabaseDeleteAllImpl(void* ptr, const std::string& keyspace, void(*cb)(void*, int)) {
  context_->data().DeleteAll(
    share_,
    keyspace,
    base::Bind(&DatabaseState::OnDatabaseDeleteAll, 
      base::Unretained(this),
      base::Unretained(ptr),
      base::Unretained(cb)));
}

void DatabaseState::DatabaseKeyspaceCreateImpl(void* ptr, const std::string& keyspace, void(*cb)(void*, int)) {
  context_->data().CreateKeyspace(
    share_,
    keyspace,
    base::Bind(&DatabaseState::OnDatabaseKeyspaceCreate, 
      base::Unretained(this),
      base::Unretained(ptr),
      base::Unretained(cb))); 
}

void DatabaseState::DatabaseKeyspaceDropImpl(void* ptr, const std::string& keyspace, void(*cb)(void*, int)) {
  context_->data().DeleteKeyspace(
    share_,
    keyspace,
    base::Bind(&DatabaseState::OnDatabaseKeyspaceDrop, 
      base::Unretained(this),
      base::Unretained(ptr),
      base::Unretained(cb))); 
}

void DatabaseState::DatabaseKeyspaceListImpl(void* ptr, void(*cb)(void*, int, int, const char**)) {
  context_->data().ListKeyspaces(
    share_,
    base::Bind(&DatabaseState::OnDatabaseKeyspaceList, 
      base::Unretained(this),
      base::Unretained(ptr),
      base::Unretained(cb))); 
}

void DatabaseState::DatabaseCursorCreateImpl(const std::string& keyspace, common::mojom::Order order, bool write, DatabaseCursorState* cursor) {
  context_->CreateDatabaseCursor(
    share_, 
    keyspace,
    order, 
    write, 
    cursor);
}

void DatabaseState::DatabaseExecuteQueryImpl(const std::string& query, SQLCursorState* cursor) {
  context_->ExecuteQuery(
    share_,
    query,
    cursor);
}

void DatabaseState::OnDatabaseClose(void* ptr, void(*cb)(void*, int), int result) {
  module_->GetModuleTaskRunner()->PostTask(
    FROM_HERE, 
    base::BindOnce(
      &RunStatusCallback,
      base::Unretained(ptr), 
      result,
      base::Unretained(cb)));
}

void DatabaseState::OnDatabasePut(void* ptr, void(*cb)(void*, int), int result) {
  module_->GetModuleTaskRunner()->PostTask(
    FROM_HERE, 
    base::BindOnce(
      &RunStatusCallback,
      base::Unretained(ptr), 
      result,
      base::Unretained(cb)));
}

void DatabaseState::OnDatabaseGet(void* ptr, void(*cb)(void*, int, SharedMemoryRef), int result, mojo::ScopedSharedBufferHandle value, int len) {
  if (result == 0) {
    module_->GetModuleTaskRunner()->PostTask(
    FROM_HERE, 
    base::BindOnce(
      &RunSharedBufferCallback,
      base::Unretained(ptr), 
      result,
      base::Passed(std::move(value)), 
      len,
      base::Unretained(cb)));
  } else {
    module_->GetModuleTaskRunner()->PostTask(
    FROM_HERE, 
    base::BindOnce(
      &RunSharedBufferCallback, 
      base::Unretained(ptr), 
      result, 
      base::Passed(mojo::ScopedSharedBufferHandle()), 
      -1,
      base::Unretained(cb)));
  }
}

void DatabaseState::OnDatabaseDelete(void* ptr, void(*cb)(void*, int), int result) {
  module_->GetModuleTaskRunner()->PostTask(
    FROM_HERE, 
    base::BindOnce(
      &RunStatusCallback,
      base::Unretained(ptr), 
      result,
      base::Unretained(cb)));
}

void DatabaseState::OnDatabaseDeleteAll(void* ptr, void(*cb)(void*, int), int result) {
  module_->GetModuleTaskRunner()->PostTask(
    FROM_HERE, 
    base::BindOnce(
      &RunStatusCallback,
      base::Unretained(ptr), 
      result,
      base::Unretained(cb)));
}

void DatabaseState::OnDatabaseKeyspaceCreate(void* ptr, void(*cb)(void*, int), int result) {
  module_->GetModuleTaskRunner()->PostTask(
    FROM_HERE, 
    base::BindOnce(
      &RunStatusCallback,
      base::Unretained(ptr), 
      result,
      base::Unretained(cb)));
}

void DatabaseState::OnDatabaseKeyspaceDrop(void* ptr, void(*cb)(void*, int), int result) {
  module_->GetModuleTaskRunner()->PostTask(
    FROM_HERE, 
    base::BindOnce(
      &RunStatusCallback,
      base::Unretained(ptr), 
      result,
      base::Unretained(cb)));
}

void DatabaseState::OnDatabaseKeyspaceList(void* ptr, void(*cb)(void*, int, int, const char**), int result, int count, const std::vector<std::string>& keyspaces) {
  module_->GetModuleTaskRunner()->PostTask(
    FROM_HERE, 
    base::BindOnce(
      &RunKeyspaceListCallback,
      base::Unretained(ptr),
      result,
      count,
      keyspaces,
      base::Unretained(cb)));
}

FilebaseState::FilebaseState(
  const std::string& share,
  const scoped_refptr<domain::StorageContext>& context,
  domain::ModuleState* module):
    share_(share), 
    context_(context),
    module_(module) {
}

FilebaseState::~FilebaseState() {

}

void FilebaseState::FilebaseCursorCreate(
  void* state, bool write, void (*callback)(void*, void*)) {
  auto cursor = std::make_unique<FilebaseCursorState>(context_, module_->GetModuleTaskRunner(), state, callback);
  FilebaseCursorState* ref = cursor.get();
  context_->GetMainTaskRunner()->PostTask(
    FROM_HERE,
    base::BindOnce(&FilebaseState::FilebaseCursorCreateImpl,
      base::Unretained(this),
      write,
      base::Unretained(ref)));
  cursors_.push_back(std::move(cursor));
}

void FilebaseState::FilebaseAdd(void* ptr, const std::string& file_path, void(*cb)(void*, int)) {
  context_->GetMainTaskRunner()->PostTask(
    FROM_HERE,
    base::BindOnce(&FilebaseState::FilebaseAddImpl,
      base::Unretained(this),
      base::Unretained(ptr),
      file_path,
      base::Unretained(cb)));
}

void FilebaseState::FilebaseDelete(void* ptr, const std::string& file_name, void(*cb)(void*, int)) {
  context_->GetMainTaskRunner()->PostTask(
    FROM_HERE,
    base::BindOnce(&FilebaseState::FilebaseDeleteImpl,
      base::Unretained(this),
      base::Unretained(ptr),
      file_name,
      base::Unretained(cb)));
}

void FilebaseState::FilebaseReadOnce(void* ptr, const std::string& file_name, int offset, int size, void(*cb)(void*, int, SharedMemoryRef)) {
  context_->GetMainTaskRunner()->PostTask(
    FROM_HERE,
    base::BindOnce(&FilebaseState::FilebaseReadOnceImpl,
      base::Unretained(this),
      base::Unretained(ptr),
      file_name,
      offset,
      size,
      base::Unretained(cb)));
}

void FilebaseState::FilebaseRead(void* ptr, const std::string& file_name, void(*cb)(void*, int)) {
  context_->GetMainTaskRunner()->PostTask(
    FROM_HERE,
    base::BindOnce(&FilebaseState::FilebaseReadImpl,
      base::Unretained(this),
      base::Unretained(ptr),
      file_name,
      base::Unretained(cb)));
}

void FilebaseState::FilebaseWrite(void* ptr, const std::string& file_name, void(*cb)(void*, int)) {
  context_->GetMainTaskRunner()->PostTask(
    FROM_HERE,
    base::BindOnce(&FilebaseState::FilebaseWriteImpl,
      base::Unretained(this),
      base::Unretained(ptr),
      file_name,
      base::Unretained(cb)));
}

void FilebaseState::FilebaseWriteOnce(void* ptr, const std::string& file_name, int data_offset, int data_size, std::vector<uint8_t> data, void(*cb)(void*, int, int)) {
  context_->GetMainTaskRunner()->PostTask(
    FROM_HERE,
    base::BindOnce(&FilebaseState::FilebaseWriteOnceImpl,
      base::Unretained(this),
      base::Unretained(ptr),
      file_name,
      data_offset,
      data_size,
      base::Passed(std::move(data)),
      base::Unretained(cb))); 
}

void FilebaseState::FilebaseList(void* ptr, void(*cb)(void*, int)) {
  context_->GetMainTaskRunner()->PostTask(
    FROM_HERE,
    base::BindOnce(&FilebaseState::FilebaseListImpl,
      base::Unretained(this),
      base::Unretained(ptr),
      base::Unretained(cb)));
}

void FilebaseState::FilebaseClose(void* ptr, void(*cb)(void*, int)) {
  context_->GetMainTaskRunner()->PostTask(
    FROM_HERE,
    base::BindOnce(&FilebaseState::FilebaseCloseImpl,
      base::Unretained(this),
      base::Unretained(ptr),
      base::Unretained(cb)));
}

void FilebaseState::FilebaseAddImpl(void*, const std::string& file_path, void(*)(void*, int)) {

}

void FilebaseState::FilebaseDeleteImpl(void*, const std::string& file_name, void(*)(void*, int)) {

}

void FilebaseState::FilebaseReadOnceImpl(void* ptr, const std::string& file_name, int offset, int size, void(*cb)(void*, int, SharedMemoryRef)) {
  context_->file().ReadFileOnce(
    share_,
    file_name,
    offset, 
    size,
    base::Bind(&FilebaseState::OnFilebaseReadOnce, 
      base::Unretained(this),
      base::Unretained(ptr),
      base::Unretained(cb)));
}

void FilebaseState::FilebaseReadImpl(void*, const std::string& file_name, void(*)(void*, int)) {

}

void FilebaseState::FilebaseWriteImpl(void*, const std::string& file_name, void(*)(void*, int)) {

}

void FilebaseState::FilebaseWriteOnceImpl(void* ptr, const std::string& file_name, int data_offset, int data_size, std::vector<uint8_t> data, void(*cb)(void*, int, int)) {
  context_->file().WriteFileOnce(
    share_,
    file_name,
    data_offset, 
    data_size,
    std::move(data),
    base::Bind(&FilebaseState::OnFilebaseWriteOnce, 
      base::Unretained(this),
      base::Unretained(ptr),
      base::Unretained(cb))); 
}

void FilebaseState::FilebaseListImpl(void*, void(*)(void*, int)) {

}

void FilebaseState::FilebaseCloseImpl(void* ptr, void(*cb)(void*, int)) {
  context_->share().CloseShare(
    share_,
    base::Bind(&FilebaseState::OnFilebaseClose, 
      base::Unretained(this),
      base::Unretained(ptr),
      base::Unretained(cb)));
}

void FilebaseState::FilebaseCursorCreateImpl(
  bool write, FilebaseCursorState* cursor) {

}

void FilebaseState::OnFilebaseAdd(void* ptr, void(*cb)(void*, int), int result) {

}

void FilebaseState::OnFilebaseDelete(void* ptr, void(*cb)(void*, int), int result) {

}

void FilebaseState::OnFilebaseReadOnce(void* ptr, void(*cb)(void*, int, SharedMemoryRef), int result, mojo::ScopedSharedBufferHandle buffer, int readed) {
  module_->GetModuleTaskRunner()->PostTask(
   FROM_HERE, 
   base::BindOnce(
     &RunSharedBufferCallback, 
     base::Unretained(ptr), 
     result,
     base::Passed(std::move(buffer)), 
     readed,
     base::Unretained(cb)));
}

void FilebaseState::OnFilebaseRead(void* ptr, void(*cb)(void*, int), int result) {

}

void FilebaseState::OnFilebaseWrite(void* ptr, void(*cb)(void*, int), int result) {

}

void FilebaseState::OnFilebaseWriteOnce(void* ptr, void(*cb)(void*, int, int), int result, int bytes_written) {
  module_->GetModuleTaskRunner()->PostTask(
   FROM_HERE, 
   base::BindOnce(
     &RunCursorDataSizeCallback, 
     base::Unretained(ptr), 
     result,
     bytes_written,
     base::Unretained(cb)));
}

void FilebaseState::OnFilebaseList(void* ptr, void(*cb)(void*, int), int result) {

}

void FilebaseState::OnFilebaseClose(void* ptr, void(*cb)(void*, int), int result) {
  module_->GetModuleTaskRunner()->PostTask(
   FROM_HERE, 
   base::BindOnce(
     &RunStatusCallback, 
     base::Unretained(ptr), 
     result,
     base::Unretained(cb)));
}

// FilebaseCursor
FilebaseCursorState::FilebaseCursorState(
    const scoped_refptr<domain::StorageContext>& context, 
    scoped_refptr<base::SingleThreadTaskRunner> module_task_runner,
    void* state, void (*callback)(void*, void*)):
 context_(context),
 module_task_runner_(module_task_runner),
 state_(state),
 callback_(callback) {

}

FilebaseCursorState::~FilebaseCursorState() {
  module_task_runner_ = nullptr;
}

void FilebaseCursorState::IsValid(void* state, void(*callback)(void*, int), bool blocking) {
  context_->GetMainTaskRunner()->PostTask(
    FROM_HERE,
    base::BindOnce(&FilebaseCursorState::IsValidImpl,
      base::Unretained(this),
      base::Unretained(state), 
      base::Unretained(callback),
      blocking));
}

void FilebaseCursorState::First(void* state, void(*callback)(void*, int), bool blocking) {
  context_->GetMainTaskRunner()->PostTask(
    FROM_HERE,
    base::BindOnce(&FilebaseCursorState::FirstImpl,
      base::Unretained(this),
      base::Unretained(state), 
      base::Unretained(callback),
      blocking));
}

void FilebaseCursorState::Last(void* state, void(*callback)(void*, int), bool blocking) {
  context_->GetMainTaskRunner()->PostTask(
    FROM_HERE,
    base::BindOnce(&FilebaseCursorState::LastImpl,
      base::Unretained(this),
      base::Unretained(state), 
      base::Unretained(callback),
      blocking));
}

void FilebaseCursorState::Previous(void* state, void(*callback)(void*, int), bool blocking) {
  context_->GetMainTaskRunner()->PostTask(
    FROM_HERE,
    base::BindOnce(&FilebaseCursorState::PreviousImpl,
      base::Unretained(this),
      base::Unretained(state), 
      base::Unretained(callback),
      blocking));
}

void FilebaseCursorState::Next(void* state, void(*callback)(void*, int), bool blocking) {
  context_->GetMainTaskRunner()->PostTask(
    FROM_HERE,
    base::BindOnce(&FilebaseCursorState::NextImpl,
      base::Unretained(this),
      base::Unretained(state), 
      base::Unretained(callback),
      blocking));
}

void FilebaseCursorState::SeekTo(std::vector<uint8_t> key, common::mojom::Seek seek, void* state, void(*callback)(void*, int, int), bool blocking) {
  context_->GetMainTaskRunner()->PostTask(
    FROM_HERE,
    base::BindOnce(&FilebaseCursorState::SeekToImpl,
      base::Unretained(this),
      base::Passed(std::move(key)),
      seek,
      base::Unretained(state), 
      base::Unretained(callback),
      blocking));
}

void FilebaseCursorState::GetSize(void* state, void(*callback)(void*, int, int), bool blocking) {
  context_->GetMainTaskRunner()->PostTask(
    FROM_HERE,
    base::BindOnce(&FilebaseCursorState::GetSizeImpl,
      base::Unretained(this),
      base::Unretained(state), 
      base::Unretained(callback),
      blocking));
}

void FilebaseCursorState::Count(void* state, void(*callback)(void*, int, int), bool blocking) {
  context_->GetMainTaskRunner()->PostTask(
    FROM_HERE,
    base::BindOnce(&FilebaseCursorState::CountImpl,
      base::Unretained(this),
      base::Unretained(state), 
      base::Unretained(callback),
      blocking));
}

void FilebaseCursorState::Read(int offset, int size, void* state, void(*callback)(void*, int, const uint8_t*, int), bool blocking) {
  context_->GetMainTaskRunner()->PostTask(
    FROM_HERE,
    base::BindOnce(&FilebaseCursorState::ReadImpl,
      base::Unretained(this),
      offset,
      size,
      base::Unretained(state), 
      base::Unretained(callback),
      blocking));
}

void FilebaseCursorState::Write(int offset, int size, std::vector<uint8_t> data, void* state, void(*callback)(void*, int, int), bool blocking) {
  context_->GetMainTaskRunner()->PostTask(
    FROM_HERE,
    base::BindOnce(&FilebaseCursorState::WriteImpl,
      base::Unretained(this),
      offset,
      size,
      base::Passed(std::move(data)),
      base::Unretained(state), 
      base::Unretained(callback),
      blocking));
}

void FilebaseCursorState::Delete(void* state, void(*callback)(void*, int), bool blocking) {
  context_->GetMainTaskRunner()->PostTask(
    FROM_HERE,
    base::BindOnce(&FilebaseCursorState::DeleteImpl,
      base::Unretained(this),
      base::Unretained(state), 
      base::Unretained(callback),
      blocking));
}

void FilebaseCursorState::IsValidImpl(void* state, void(*callback)(void*, int), bool blocking) {
  cursor_->IsValid(
    base::Bind(&FilebaseCursorState::OnIsValid, 
        base::Unretained(this),
        blocking,
        base::Unretained(state),
        base::Unretained(callback)));
}

void FilebaseCursorState::FirstImpl(void* state, void(*callback)(void*, int), bool blocking) {
  cursor_->First(
    base::Bind(&FilebaseCursorState::OnFirst, 
        base::Unretained(this),
        blocking,
        base::Unretained(state),
        base::Unretained(callback)));
}

void FilebaseCursorState::LastImpl(void* state, void(*callback)(void*, int), bool blocking) {
  cursor_->Last(
    base::Bind(&FilebaseCursorState::OnLast, 
        base::Unretained(this),
        blocking,
        base::Unretained(state),
        base::Unretained(callback)));
}

void FilebaseCursorState::PreviousImpl(void* state, void(*callback)(void*, int), bool blocking) {
  cursor_->Previous(
    base::Bind(&FilebaseCursorState::OnPrevious, 
        base::Unretained(this),
        blocking,
        base::Unretained(state),
        base::Unretained(callback)));
}

void FilebaseCursorState::NextImpl(void* state, void(*callback)(void*, int), bool blocking) {
  cursor_->Next(
    base::Bind(&FilebaseCursorState::OnNext, 
        base::Unretained(this),
        blocking,
        base::Unretained(state),
        base::Unretained(callback)));
}

void FilebaseCursorState::SeekToImpl(std::vector<uint8_t> key, common::mojom::Seek seek, void* state, void(*callback)(void*, int, int), bool blocking) {
  cursor_->SeekTo(
    key,
    seek,
    base::Bind(&FilebaseCursorState::OnSeekTo, 
        base::Unretained(this),
        blocking,
        base::Unretained(state),
        base::Unretained(callback)));
}

void FilebaseCursorState::GetSizeImpl(void* state, void(*callback)(void*, int, int), bool blocking) {
  cursor_->GetSize(
    base::Bind(&FilebaseCursorState::OnGetSize, 
        base::Unretained(this),
        blocking,
        base::Unretained(state),
        base::Unretained(callback)));
}

void FilebaseCursorState::CountImpl(void* state, void(*callback)(void*, int, int), bool blocking) {
  cursor_->Count(
    base::Bind(&FilebaseCursorState::OnCount, 
        base::Unretained(this),
        blocking,
        base::Unretained(state),
        base::Unretained(callback)));
}

void FilebaseCursorState::ReadImpl(int offset, int size, void* state, void(*callback)(void*, int, const uint8_t*, int), bool blocking) {
  cursor_->Read(
    offset,
    size,
    base::Bind(&FilebaseCursorState::OnRead, 
        base::Unretained(this),
        blocking,
        base::Unretained(state),
        base::Unretained(callback)));
}

void FilebaseCursorState::WriteImpl(int offset, int size, std::vector<uint8_t> data, void* state, void(*callback)(void*, int, int), bool blocking) {
  cursor_->Write(
    offset,
    size,
    data,
    base::Bind(&FilebaseCursorState::OnWrite, 
        base::Unretained(this),
        blocking,
        base::Unretained(state),
        base::Unretained(callback))); 
}

void FilebaseCursorState::DeleteImpl(void* state, void(*callback)(void*, int), bool blocking) {
  cursor_->Delete(
    base::Bind(&FilebaseCursorState::OnDelete, 
        base::Unretained(this),
        blocking,
        base::Unretained(state),
        base::Unretained(callback))); 
}

void FilebaseCursorState::OnCursorAvailable(common::mojom::FileCursorPtr cursor) {
  cursor_ = std::move(cursor);
  module_task_runner_->PostTask(
    FROM_HERE, 
    base::BindOnce(&RunCursorAvailableCallback, 
      base::Unretained(state_), 
      base::Unretained(this), 
      base::Unretained(callback_)));
}

void FilebaseCursorState::OnIsValid(bool blocking, void* state, void(*callback)(void*, int), bool valid) {
  if (blocking) {
    RunStatusCallback(state, valid ? 0 : 2, callback);
  } else {
    module_task_runner_->PostTask(
      FROM_HERE, 
      base::BindOnce(&RunStatusCallback, 
        base::Unretained(state),
        valid ? 0 : 2,
        base::Unretained(callback)));
  }
}

void FilebaseCursorState::OnFirst(bool blocking, void* state, void(*callback)(void*, int), int32_t status) {
  if (blocking) {
    RunStatusCallback(state, status, callback);
  } else {
    module_task_runner_->PostTask(
      FROM_HERE, 
      base::BindOnce(&RunStatusCallback, 
        base::Unretained(state),
        status,
        base::Unretained(callback)));
  }
}

void FilebaseCursorState::OnLast(bool blocking, void* state, void(*callback)(void*, int), int32_t status) {
  if (blocking) {
    RunStatusCallback(state, status, callback);
  } else {
    module_task_runner_->PostTask(
      FROM_HERE, 
      base::BindOnce(&RunStatusCallback, 
        base::Unretained(state),
        status,
        base::Unretained(callback)));
  }
}

void FilebaseCursorState::OnPrevious(bool blocking, void* state, void(*callback)(void*, int), int32_t status) {
  if (blocking) {
    RunStatusCallback(state, status, callback);
  } else {
    module_task_runner_->PostTask(
      FROM_HERE, 
      base::BindOnce(&RunStatusCallback, 
        base::Unretained(state),
        status,
        base::Unretained(callback)));
  }
}

void FilebaseCursorState::OnNext(bool blocking, void* state, void(*callback)(void*, int), int32_t status) {
  if (blocking) {
    RunStatusCallback(state, status, callback);
  } else {
    module_task_runner_->PostTask(
      FROM_HERE, 
      base::BindOnce(&RunStatusCallback, 
        base::Unretained(state),
        status,
        base::Unretained(callback)));
  }
}

void FilebaseCursorState::OnSeekTo(bool blocking, void* state, void(*callback)(void*, int, int), int32_t result, bool match) {

}

void FilebaseCursorState::OnGetSize(bool blocking, void* state, void(*callback)(void*, int, int), int32_t status, int64_t size) {

}

void FilebaseCursorState::OnCount(bool blocking, void* state, void(*callback)(void*, int, int), int32_t status, int64_t items) {

}

void FilebaseCursorState::OnRead(bool blocking, void* state, void(*callback)(void*, int, const uint8_t*, int), int32_t status, const std::vector<uint8_t>& data) {
  if (blocking) {
    RunCursorGetDataCallback(state, status, data, callback);
  } else {
    module_task_runner_->PostTask(
      FROM_HERE, 
      base::BindOnce(&RunCursorGetDataCallback, 
        base::Unretained(state), 
        status, 
        data,
        base::Unretained(callback)));
  }
}

void FilebaseCursorState::OnWrite(bool blocking, void* state, void(*callback)(void*, int, int), int32_t status, int32_t wrote) {
  if (blocking) {
    RunCursorDataSizeCallback(state, status, wrote, callback);
  } else {
    module_task_runner_->PostTask(
      FROM_HERE, 
      base::BindOnce(&RunCursorDataSizeCallback, 
        base::Unretained(state), 
        status, 
        wrote,
        base::Unretained(callback)));
  } 
}

void FilebaseCursorState::OnDelete(bool blocking, void* state, void(*callback)(void*, int), int32_t status) {
  if (blocking) {
    RunStatusCallback(state, status, callback);
  } else {
    module_task_runner_->PostTask(
      FROM_HERE, 
      base::BindOnce(&RunStatusCallback, 
        base::Unretained(state),
        status,
        base::Unretained(callback)));
  }
}

// SharedMemoryState
SharedMemoryState::SharedMemoryState(mojo::SharedBufferHandle shared_handle, int size):
  handle_(std::move(shared_handle)),
  size_(size) {

}

SharedMemoryState::~SharedMemoryState() {
  if (handle_.is_valid()) {
    handle_.Close();
  }
}

void SharedMemoryState::Map(void* state, void(*cb)(void*, char*, int)) {
  mojo::ScopedSharedBufferMapping mapping = handle_.Map(size_);
  cb(state, static_cast<char*>(mapping.get()), size_);
}

void SharedMemoryState::ConstMap(void* state, void(*cb)(void*, const char*, int)) {
  mojo::ScopedSharedBufferMapping mapping = handle_.Map(size_);
  cb(state, static_cast<const char*>(mapping.get()), size_);
}