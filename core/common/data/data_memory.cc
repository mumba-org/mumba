// Copyright 2010 Google Inc.  All Rights Reserved
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

#include "core/common/data/data_memory.h"

#include <string.h>
#include <algorithm>
#include <cstdlib>

namespace common {

namespace {
static char dummy_buffer[0] = {};
}

void OverwriteWithPattern(char* p, size_t len, base::StringPiece pattern) {
  CHECK_LT(0, static_cast<int>(pattern.size()));
  for (size_t i = 0; i < len; ++i) {
    p[i] = pattern[i % pattern.size()];
  }
}

Buffer::~Buffer() {
#ifndef NDEBUG
  OverwriteWithPattern(reinterpret_cast<char*>(data_), size_, "BAD");
#endif
  if (allocator_ != NULL) allocator_->FreeInternal(this);
}

void BufferAllocator::LogAllocation(size_t requested,
                                    size_t minimal,
                                    Buffer* buffer) {
  //LOG(INFO) << "LogAllocation";
  if (buffer == NULL) {
    LOG(WARNING) << "Memory allocation failed in Supersonic. "
                 << "Number of bytes requested: " << requested
                 << ", minimal: " << minimal;
    return;
  }
  if (buffer->size() < requested) {
    LOG(WARNING) << "Memory allocation warning in Supersonic. "
                 << "Number of bytes requested to allocate: " << requested
                 << ", minimal: " << minimal
                 << ", and actually allocated: " << buffer->size();
  }
  //LOG(INFO) << "LogAllocation end";
}

size_t BufferAllocator::Available() const { 
  return std::numeric_limits<size_t>::max(); 
}

// TODO(onufry) - test whether the code still tests OK if we set this to true,
// or remove this code and add a test that Google allocator does not change it's
// contract - 16-aligned in -c opt and %16 == 8 in debug.
//DEFINE_bool(allocator_aligned_mode, false,
//            "Use 16-byte alignment instead of 8-byte, "
//            "unless explicitly specified otherwise - to boost SIMD");

HeapBufferAllocator::HeapBufferAllocator()
  : //aligned_mode_(true) {
    aligned_mode_(false) {//(FLAGS_allocator_aligned_mode) {
}

size_t HeapBufferAllocator::Available() const {
  return std::numeric_limits<size_t>::max();
}

Buffer* HeapBufferAllocator::AllocateInternal(
    const size_t requested,
    const size_t minimal,
    BufferAllocator* const originator) {
  DCHECK_LE(minimal, requested);
  void* data;
  size_t attempted = requested;
  while (true) {
    data = (attempted == 0) ? &dummy_buffer[0] : Malloc(attempted);
    if (data != NULL) {
      return CreateBuffer(data, attempted, originator);
    }
    if (attempted == minimal) return NULL;
    attempted = minimal + (attempted - minimal - 1) / 2;
  }
}

bool HeapBufferAllocator::ReallocateInternal(
    const size_t requested,
    const size_t minimal,
    Buffer* const buffer,
    BufferAllocator* const originator) {
  //LOG(INFO) << "ReallocateInternal";
  DCHECK_LE(minimal, requested);
  void* data;
  size_t attempted = requested;
  while (true) {
    if (attempted == 0) {
      //LOG(INFO) << "attempted 0: buffer size: " << buffer->size();
      if (buffer->size() > 0) free(buffer->data());
      data = &dummy_buffer[0];
    } else {
      if (buffer->size() > 0) {
        //LOG(INFO) << "buffer size > 0: " << buffer->size() << " realloc.";
        data = Realloc(buffer->data(), buffer->size(), attempted);
        //LOG(INFO) << "data is back here: " << data;
      } else {
        //LOG(INFO) << "buffer size == 0: " << buffer->size() << " malloc.";
        data = Malloc(attempted);
      }
    }
    if (data != NULL) {
      //LOG(INFO) << "data != NULL. calling update buffer";
      UpdateBuffer(data, attempted, buffer);
      //LOG(INFO) << "update buffer ok. buf data at: " << buffer->data() ;
      return true;
    }
    //LOG(INFO) << "data == null. attempted: " << attempted << " minimal: " << minimal;
    if (attempted == minimal) return false;
    attempted = minimal + (attempted - minimal - 1) / 2;
  }
  //LOG(INFO) << "ReallocateInternal end";
}

void HeapBufferAllocator::FreeInternal(Buffer* buffer) {
  if (buffer->size() > 0) free(buffer->data());
}

void* HeapBufferAllocator::Malloc(size_t size) {
  //LOG(INFO) << "Malloc. size:" << size;
  if (aligned_mode_) {
    //LOG(INFO) << "aligned mode: posix_memalign";
    void* data;
    if (posix_memalign(&data, 16, ((size + 15) / 16) * 16)) {
       LOG(ERROR) << "posix_memalign failed";
       return NULL;
    }
    //LOG(INFO) << "data start: " << data << " data end: " << reinterpret_cast<void*>(reinterpret_cast<char*>(data) + size);
    //CHECK(data);
    return data;
  } else {
    //LOG(INFO) << "unnaligned calling malloc for size: " << size;
    void* buf = malloc(size);
    //CHECK(buf);
    //LOG(INFO) << "buf start: " << buf << " buf end: " << reinterpret_cast<void*>(reinterpret_cast<char*>(buf) + size);
    return buf;
  }
  //LOG(INFO) << "Malloc end";
}

void* HeapBufferAllocator::Realloc(void* previousData, size_t previousSize,
                                   size_t newSize) {
  //LOG(INFO) << "Realloc";
  if (aligned_mode_) {
    //LOG(INFO) << "alligned mode";
    void* data = Malloc(newSize);
    if (data) {
// NOTE(ptab): We should use realloc here to avoid memmory coping,
// but it doesn't work on memory allocated by posix_memalign(...).
// realloc reallocates the memory but doesn't preserve the content.
// TODO(ptab): reiterate after some time to check if it is fixed (tcmalloc ?)
      memcpy(data, previousData, std::min(previousSize, newSize));
      free(previousData);
      return data;
    } else {
      return NULL;
    }
  } else {
    //base::AutoLock lock(lock_);
    //LOG(INFO) << "calling realloc. data:" << previousData << " newsize: " << newSize;
    //CHECK(previousData);
    void* buf = realloc(previousData, newSize);
    //LOG(INFO) << "realloc back. orig buf is: " << previousData << " ret buf is " << buf;
    //LOG(INFO) << "pos[0]: " << reinterpret_cast<int*>(buf)[0] << " pos[5]: " << reinterpret_cast<int*>(buf)[5] ;
    return buf;
  }
  //LOG(INFO) << "Realloc end";
}

size_t ClearingBufferAllocator::Available() const {
  return delegate_->Available();
}

Buffer* ClearingBufferAllocator::AllocateInternal(size_t requested,
                                                  size_t minimal,
                                                  BufferAllocator* originator) {
  Buffer* buffer = DelegateAllocate(delegate_, requested, minimal,
                                    originator);
  if (buffer != NULL) memset(buffer->data(), 0, buffer->size());
  return buffer;
}

bool ClearingBufferAllocator::ReallocateInternal(size_t requested,
                                                 size_t minimal,
                                                 Buffer* buffer,
                                                 BufferAllocator* originator) {
  size_t offset = (buffer != NULL ? buffer->size() : 0);
  bool success = DelegateReallocate(delegate_, requested, minimal, buffer,
                                    originator);
  if (success && buffer->size() > offset) {
    memset(static_cast<char*>(buffer->data()) + offset, 0,
           buffer->size() - offset);
  }
  return success;
}

void ClearingBufferAllocator::FreeInternal(Buffer* buffer) {
  DelegateFree(delegate_, buffer);
}

size_t Mediator::Available() const { 
  return std::numeric_limits<size_t>::max(); 
}

size_t MediatingBufferAllocator::Available() const {
  return std::min(delegate_->Available(), mediator_->Available());
}

Buffer* MediatingBufferAllocator::AllocateInternal(
    const size_t requested,
    const size_t minimal,
    BufferAllocator* const originator) {
  // Allow the mediator to trim the request.
  size_t granted;
  if (requested > 0) {
    granted = mediator_->Allocate(requested, minimal);
    if (granted < minimal) return NULL;
  } else {
    granted = 0;
  }
  Buffer* buffer = DelegateAllocate(delegate_, granted, minimal, originator);
  if (buffer == NULL) {
    mediator_->Free(granted);
  } else if (buffer->size() < granted) {
    mediator_->Free(granted - buffer->size());
  }
  return buffer;
}

bool MediatingBufferAllocator::ReallocateInternal(
    const size_t requested,
    const size_t minimal,
    Buffer* const buffer,
    BufferAllocator* const originator) {
  // Allow the mediator to trim the request. Be conservative; assume that
  // realloc may degenerate to malloc-memcpy-free.
  size_t granted;
  if (requested > 0) {
    granted = mediator_->Allocate(requested, minimal);
    if (granted < minimal) return false;
  } else {
    granted = 0;
  }
  size_t old_size = buffer->size();
  if (DelegateReallocate(delegate_, granted, minimal, buffer, originator)) {
    mediator_->Free(granted - buffer->size() + old_size);
    return true;
  } else {
    mediator_->Free(granted);
    return false;
  }
}

void MediatingBufferAllocator::FreeInternal(Buffer* buffer) {
  mediator_->Free(buffer->size());
  DelegateFree(delegate_, buffer);
}

MemoryLimit::MemoryLimit(BufferAllocator* const allocator)
      : quota_(std::numeric_limits<size_t>::max()),
          allocator_(allocator, &quota_) {}

MemoryLimit::MemoryLimit(size_t quota, BufferAllocator* const delegate)
      : quota_(quota),
        allocator_(delegate, &quota_) {}

MemoryLimit::MemoryLimit(size_t quota, bool enforced, BufferAllocator* const delegate)
      : quota_(quota, enforced),
        allocator_(delegate, &quota_) {}

MemoryLimit::~MemoryLimit() {}

size_t MemoryLimit::Available() const {
  return allocator_.Available();
}

Buffer* MemoryLimit::AllocateInternal(size_t requested,
                           size_t minimal,
                           BufferAllocator* originator) {
  return DelegateAllocate(&allocator_, requested, minimal, originator);
}

bool MemoryLimit::ReallocateInternal(size_t requested,
                          size_t minimal,
                          Buffer* buffer,
                          BufferAllocator* originator) {
  return DelegateReallocate(&allocator_, requested, minimal, buffer,
                            originator);
}

void MemoryLimit::FreeInternal(Buffer* buffer) {
  DelegateFree(&allocator_, buffer);
}

size_t SoftQuotaBypassingBufferAllocator::Available() const {
  const size_t usage = allocator_.GetUsage();
  size_t available = allocator_.Available();
  if (bypassed_amount_ > usage) {
    available = std::max(bypassed_amount_ - usage, available);
  }
  return available;
}

Buffer* SoftQuotaBypassingBufferAllocator::AllocateInternal(size_t requested,
                          size_t minimal,
                          BufferAllocator* originator) {
  // Try increasing the "minimal" parameter to allocate more aggresively
  // within the bypassed amount of soft quota.
  Buffer* result = DelegateAllocate(&allocator_,
                                    requested,
                                    AdjustMinimal(requested, minimal),
                                    originator);
  if (result != NULL) {
    return result;
  } else {
    return DelegateAllocate(&allocator_,
                            requested,
                            minimal,
                            originator);
  }
}

bool SoftQuotaBypassingBufferAllocator::ReallocateInternal(size_t requested,
                        size_t minimal,
                        Buffer* buffer,
                        BufferAllocator* originator) {
  if (DelegateReallocate(&allocator_,
                          requested,
                          AdjustMinimal(requested, minimal),
                          buffer,
                          originator)) {
    return true;
  } else {
    return DelegateReallocate(&allocator_,
                              requested,
                              minimal,
                              buffer,
                              originator);
  }
}

void SoftQuotaBypassingBufferAllocator::FreeInternal(Buffer* buffer) {
  DelegateFree(&allocator_, buffer);
}

MemoryStatisticsCollectorInterface::MemoryStatisticsCollectorInterface() {}
MemoryStatisticsCollectorInterface::~MemoryStatisticsCollectorInterface() {}

MemoryStatisticsCollectingBufferAllocator::MemoryStatisticsCollectingBufferAllocator(
      BufferAllocator* const delegate,
      MemoryStatisticsCollectorInterface* const memory_stats_collector)
      : delegate_(delegate),
        memory_stats_collector_(memory_stats_collector) {}

MemoryStatisticsCollectingBufferAllocator::~MemoryStatisticsCollectingBufferAllocator() {}

size_t MemoryStatisticsCollectingBufferAllocator::Available() const {
  return delegate_->Available();
}

Buffer* MemoryStatisticsCollectingBufferAllocator::AllocateInternal(
    const size_t requested,
    const size_t minimal,
    BufferAllocator* const originator) {
  Buffer* buffer = DelegateAllocate(delegate_, requested, minimal, originator);
  if (buffer != NULL) {
    memory_stats_collector_->AllocatedMemoryBytes(buffer->size());
  } else {
    memory_stats_collector_->RefusedMemoryBytes(minimal);
  }
  return buffer;
}

bool MemoryStatisticsCollectingBufferAllocator::ReallocateInternal(
    const size_t requested,
    const size_t minimal,
    Buffer* const buffer,
    BufferAllocator* const originator) {
  const size_t old_size = buffer->size();
  bool outcome = DelegateReallocate(delegate_, requested, minimal, buffer,
                                    originator);
  if (buffer->size() > old_size) {
    memory_stats_collector_->AllocatedMemoryBytes(buffer->size() - old_size);
  } else if (buffer->size() < old_size) {
    memory_stats_collector_->FreedMemoryBytes(old_size - buffer->size());
  } else if (!outcome && (minimal > buffer->size())) {
    memory_stats_collector_->RefusedMemoryBytes(minimal - buffer->size());
  }
  return outcome;
}

void MemoryStatisticsCollectingBufferAllocator::FreeInternal(Buffer* buffer) {
  DelegateFree(delegate_, buffer);
  memory_stats_collector_->FreedMemoryBytes(buffer->size());
}

GuaranteeMemory::GuaranteeMemory(size_t memory_quota,
                  BufferAllocator* delegate)
      : limit_(memory_quota, true, delegate),
        memory_guarantee_(memory_quota) {

}

GuaranteeMemory::~GuaranteeMemory() {}

size_t GuaranteeMemory::Available() const {
  return memory_guarantee_ - limit_.GetUsage();
}

Buffer* GuaranteeMemory::AllocateInternal(size_t requested,
                          size_t minimal,
                          BufferAllocator* originator) {
  if (requested > Available()) {
    return NULL;
  } else {
    return DelegateAllocate(&limit_, requested, requested, originator);
  }
}

bool GuaranteeMemory::ReallocateInternal(size_t requested,
                        size_t minimal,
                        Buffer* buffer,
                        BufferAllocator* originator) {
  size_t additional_memory = requested - (buffer != NULL ? buffer->size() : 0);
  return additional_memory <= Available()
      && DelegateReallocate(&limit_, requested, requested,
                            buffer, originator);
}

void GuaranteeMemory::FreeInternal(Buffer* buffer) {
  DelegateFree(&limit_, buffer);
}

}  // namespace db
