// Copyright (c) 2017 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef COMMON_SHARED_DATA_H_
#define COMMON_SHARED_DATA_H_

#include <memory>
#include "base/memory/ref_counted.h"
#include "base/memory/shared_memory.h"
#include "base/files/file.h"

namespace common {

class SharedData : public base::RefCountedThreadSafe<SharedData> {
public:
 
  SharedData(const base::SharedMemoryHandle& handle, uint32_t size);
  SharedData(uint32_t size);

  uint8_t* data() {
    if (!mapped_)
     Map();

    return reinterpret_cast<uint8_t*>(shmem_->memory());
  }

  uint32_t size() const {
    return size_;
  }

  base::SharedMemoryHandle handle() const {
    return shmem_->handle();
  }

  bool is_mapped() const { return mapped_; }
  bool is_shared() const { return shared_; }
  
  bool Map();
  bool Copy(const uint8_t* buf, uint32_t size);
  void Unmap();
  void Close();
  void Release();
  //bool ShareToProcess(base::ProcessHandle process, base::SharedMemoryHandle* handle);
  //bool GiveToProcess(base::ProcessHandle child_process, base::SharedMemoryHandle* handle);

protected:
 
 std::unique_ptr<base::SharedMemory> shmem_;
 //base::SharedMemoryHandle shared_handle_;

private:
  friend class base::RefCountedThreadSafe<SharedData>;
  virtual ~SharedData();
 
  uint32_t size_;
  bool mapped_;
  bool shared_;

  DISALLOW_COPY_AND_ASSIGN(SharedData);
};

}

#endif