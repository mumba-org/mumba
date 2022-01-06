// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_LIB_STORAGE_IO_HANDLER_H_
#define MUMBA_LIB_STORAGE_IO_HANDLER_H_

#include <string>

#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/synchronization/waitable_event.h"
#include "net/base/net_errors.h"
#include "storage/proto/storage.pb.h"

namespace storage {
class Torrent;

template <typename R>
struct WaitableEvent : public base::RefCountedThreadSafe<WaitableEvent<R>> {
  R result;
  base::WaitableEvent wait_event;

  WaitableEvent(): wait_event(base::WaitableEvent::ResetPolicy::MANUAL, base::WaitableEvent::InitialState::NOT_SIGNALED) {
  }

  void Wait() {
    wait_event.Wait();
  }
  void Signal(R r) {
    result = r;
    wait_event.Signal();
  }
};

template <typename R>
struct Future {
  scoped_refptr<WaitableEvent<R>> sync;
  bool is_synchronous = false;

  Future(scoped_refptr<WaitableEvent<R>> sync): sync(sync) {}
  Future(scoped_refptr<WaitableEvent<R>> sync, bool synchronous): 
    sync(sync), 
    is_synchronous(synchronous) {}

  R get() {
    //if (!is_synchronous)
    sync->Wait();
    return sync->result;
  }
};

class IOHandler {
public:
  virtual ~IOHandler() {}
  virtual const base::FilePath& GetPath() const = 0;
  virtual scoped_refptr<Torrent> root_tree() const = 0;
  virtual bool is_owner() const = 0;
  virtual bool ShouldSeed(const storage_proto::Info& info) = 0;
  virtual void OpenDatabase(const scoped_refptr<Torrent>& torrent, base::Callback<void(int64_t)> cb) = 0;
  virtual void CreateDatabase(const scoped_refptr<Torrent>& torrent, std::vector<std::string> keyspaces, base::Callback<void(int64_t)> cb) = 0;
  virtual Future<int> CreateTorrent(const scoped_refptr<Torrent>& torrent, bool is_journal = false, int jrn_seq = -1) = 0;
  virtual Future<int> OpenTorrent(const scoped_refptr<Torrent>& torrent) = 0;
  virtual Future<int> CloseTorrent(const scoped_refptr<Torrent>& torrent, bool is_journal = false, int jrn_seq = -1) = 0;
  virtual Future<int> ReadTorrent(const scoped_refptr<Torrent>& torrent, void* buf, int64_t size, int64_t offset, bool is_journal = false, int jrn_seq = -1) = 0;
  virtual Future<int> WriteTorrent(const scoped_refptr<Torrent>& torrent, const void* buf, int64_t size, int64_t offset, bool is_journal = false, int jrn_seq = -1) = 0;
  virtual Future<int> DeleteTorrent(const scoped_refptr<Torrent>& torrent, bool is_journal = false) = 0;
  virtual int64_t GetTorrentSize(const scoped_refptr<Torrent>& torrent) = 0;
  virtual Future<int> SyncTorrentMetadata(const scoped_refptr<Torrent>& torrent) = 0;
};

}

#endif
