// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef STORAGE_STORAGE_BACKEND_BLOCKFILE_EVICTION_H_
#define STORAGE_STORAGE_BACKEND_BLOCKFILE_EVICTION_H_

#include "base/macros.h"
#include "base/memory/weak_ptr.h"
#include "storage/backend/rankings.h"

namespace storage {

class StorageBackend;
class StorageEntry;
struct IndexHeader;

// This class implements the eviction algorithm for the cache and it is tightly
// integrated with StorageBackend.
class Eviction {
 public:
  Eviction();
  ~Eviction();

  void Init(StorageBackend* backend);
  void Stop();

  // Deletes entries from the cache until the current size is below the limit.
  // If empty is true, the whole cache will be trimmed, regardless of being in
  // use.
  void TrimCache(bool empty);

  // Updates the ranking information for an entry.
  void UpdateRank(StorageEntry* entry, bool modified);

  // Notifications of interesting events for a given entry.
  void OnOpenEntry(StorageEntry* entry);
  void OnCreateEntry(StorageEntry* entry);
  void OnDoomEntry(StorageEntry* entry);
  void OnDestroyEntry(StorageEntry* entry);

  // Testing interface.
  void SetTestMode();
  void TrimDeletedList(bool empty);

 private:
  void PostDelayedTrim();
  void DelayedTrim();
  bool ShouldTrim();
  bool ShouldTrimDeleted();
  void ReportTrimTimes(StorageEntry* entry);
  Rankings::List GetListForEntry(StorageEntry* entry);
  bool EvictEntry(CacheRankingsBlock* node, bool empty, Rankings::List list);

  // We'll just keep for a while a separate set of methods that implement the
  // new eviction algorithm. This code will replace the original methods when
  // finished.
  void TrimCacheV2(bool empty);
  void UpdateRankV2(StorageEntry* entry, bool modified);
  void OnOpenEntryV2(StorageEntry* entry);
  void OnCreateEntryV2(StorageEntry* entry);
  void OnDoomEntryV2(StorageEntry* entry);
  void OnDestroyEntryV2(StorageEntry* entry);
  Rankings::List GetListForEntryV2(StorageEntry* entry);
  void TrimDeleted(bool empty);
  bool RemoveDeletedNode(CacheRankingsBlock* node);

  bool NodeIsOldEnough(CacheRankingsBlock* node, int list);
  int SelectListByLength(Rankings::ScopedRankingsBlock* next);
  void ReportListStats();

  StorageBackend* backend_;
  Rankings* rankings_;
  IndexHeader* header_;
  int max_size_;
  int trim_delays_;
  int index_size_;
  bool new_eviction_;
  bool first_trim_;
  bool trimming_;
  bool delay_trim_;
  bool init_;
  bool test_mode_;
  base::WeakPtrFactory<Eviction> ptr_factory_;

  DISALLOW_COPY_AND_ASSIGN(Eviction);
};

}  // namespace storage

#endif  // STORAGE_STORAGE_BACKEND_BLOCKFILE_EVICTION_H_
