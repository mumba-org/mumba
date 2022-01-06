// Copyright (c) 2017 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/common/shared_data.h"

namespace common {

SharedData::SharedData(const base::SharedMemoryHandle& handle, uint32_t size): 
  size_(size), 
  //peer_(handle), 
  mapped_(false),
  shared_(true) {//, 
  //shared_handle_(handle) {
  
  shmem_.reset(new base::SharedMemory(handle, false)); 
}

SharedData::SharedData(uint32_t size): 
  size_(size), 
  //peer_(base::kNullProcessHandle),
  mapped_(false),
  shared_(false) {//,
  //shared_handle_(base::SharedMemory::NULLHandle()) {
  
  shmem_.reset(new base::SharedMemory());
}

SharedData::~SharedData() {
  Release();
}
  
bool SharedData::Map() {
  bool result = false;
  if (size_ > 0) {
    if (!shared_) {
      result = shmem_->CreateAndMapAnonymous(size_);
      mapped_ = true;
    } else {
      result = shmem_->Map(size_);
      mapped_ = true;
    }
  }
  return result;
}

bool SharedData::Copy(const uint8_t* buf, uint32_t size) {
  if(size == 0 || size > size_)
    return false;

  if (!mapped_) {
    Map();
  }  

  return memcpy(shmem_->memory(), buf, size) != nullptr;
}

void SharedData::Unmap() {
  if (mapped_) {
    shmem_->Unmap();
    mapped_ = false;
  }
}

void SharedData::Close() {
  shmem_->Close();
}

// bool SharedData::ShareToProcess(base::ProcessHandle process, base::SharedMemoryHandle* handle) {
//   shared_ = shmem_->ShareToProcess(process, handle);
//   return shared_;
// }

// bool SharedData::GiveToProcess(base::ProcessHandle child_process, base::SharedMemoryHandle* shared_memory_handle) {
//  return shmem_->GiveToProcess(child_process, shared_memory_handle); 
// }

void SharedData::Release() {
 Close();
 Unmap();  
}


}