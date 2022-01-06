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
//
// Classes for memory management, used by materializations
// (arenas, segments, and STL collections parametrized via arena allocators)
// so that memory usage can be controlled at the application level.
//
// Materializations can be parametrized by specifying an instance of a
// BufferAllocator. The allocator implements
// memory management policy (e.g. setting allocation limits). Allocators may
// be shared between multiple materializations; e.g. you can designate a
// single allocator per a single user request, thus setting bounds on memory
// usage on a per-request basis.

// NOTE: this code is from google Supersonic project

#ifndef MUMBA_STORAGE_DB_MEMORY_H_
#define MUMBA_STORAGE_DB_MEMORY_H_

#include <stddef.h>
#include <algorithm>
#include <memory>
#include <limits>
#include <vector>
using std::vector;

#include "base/synchronization/lock.h"
#include "base/strings/string_piece.h"

namespace storage {

class BufferAllocator;

void OverwriteWithPattern(char* p, size_t len, base::StringPiece pattern);

// Wrapper for a block of data allocated by a BufferAllocator. Owns the block.
// (To release the block, destroy the buffer - it will then return it via the
// same allocator that has been used to create it).
class Buffer {
 public:
  ~Buffer();

  void* data() const { return data_; }   // The data buffer.
  size_t size() const { return size_; }  // In bytes.

 private:
  friend class BufferAllocator;

  Buffer(void* data, size_t size, BufferAllocator* allocator)
      : data_(data),//(CHECK_NOTNULL(data)),
        size_(size),
        allocator_(allocator) {
#ifndef NDEBUG
    OverwriteWithPattern(reinterpret_cast<char*>(data_), size_, "NEW");
#endif
  }

  // Called by a successful realloc.
  void Update(void* new_data, size_t new_size) {
#ifndef NDEBUG
    if (new_size > size_) {
      OverwriteWithPattern(reinterpret_cast<char*>(new_data) + size_,
                           new_size - size_, "NEW");
    }
#endif
    data_ = new_data;
    size_ = new_size;
  }

  void* data_;
  size_t size_;
  BufferAllocator* const allocator_;
  DISALLOW_COPY_AND_ASSIGN(Buffer);
};

// Allocators allow applications to control memory usage. They are
// used by materializations to allocate blocks of memory arenas.
// BufferAllocator is an abstract class that defines a common contract of
// all implementations of allocators. Specific allocators provide specific
// features, e.g. enforced resource limits, thread safety, etc.
class BufferAllocator {
 public:
  virtual ~BufferAllocator() {}

  // Called by the user when a new block of memory is needed. The 'requested'
  // parameter specifies how much memory (in bytes) the user would like to get.
  // The 'minimal' parameter specifies how much he is willing to settle for.
  // The allocator returns a buffer sized in the range [minimal, requested],
  // or NULL if the request can't be satisfied. When the buffer is destroyed,
  // its destructor calls the FreeInternal() method on its allocator.
  // CAVEAT: The allocator must outlive all buffers returned by it.
  //
  // Corner cases:
  // 1. If requested == 0, the allocator will always return a non-NULL Buffer
  //    with a non-NULL data pointer and zero capacity.
  // 2. If minimal == 0, the allocator will always return a non-NULL Buffer
  //    with a non-NULL data pointer, possibly with zero capacity.
  Buffer* BestEffortAllocate(size_t requested, size_t minimal) {
    DCHECK_LE(minimal, requested);
    Buffer* result = AllocateInternal(requested, minimal, this);
    LogAllocation(requested, minimal, result);
    return result;
  }

  // Called by the user when a new block of memory is needed. Equivalent to
  // BestEffortAllocate(requested, requested).
  Buffer* Allocate(size_t requested) {
    return BestEffortAllocate(requested, requested);
  }

  // Called by the user when a previously allocated block needs to be resized.
  // Mimics semantics of <cstdlib> realloc. The 'requested' and 'minimal'
  // represent the desired final buffer size, with semantics as in the Allocate.
  // If the 'buffer' parameter is NULL, the call is equivalent to
  // Allocate(requested, minimal). Otherwise, a reallocation of the buffer's
  // data is attempted. On success, the original 'buffer' parameter is returned,
  // but the buffer itself might have updated size and data. On failure,
  // returns NULL, and leaves the input buffer unmodified.
  // Reallocation might happen in-place, preserving the original data
  // pointer, but it is not guaranteed - e.g. this function might degenerate to
  // Allocate-Copy-Free. Either way, the content of the data buffer, up to the
  // minimum of the new and old size, is preserved.
  //
  // Corner cases:
  // 1. If requested == 0, the allocator will always return a non-NULL Buffer
  //    with a non-NULL data pointer and zero capacity.
  // 2. If minimal == 0, the allocator will always return a non-NULL Buffer
  //    with a non-NULL data pointer, possibly with zero capacity.
  Buffer* BestEffortReallocate(size_t requested,
                               size_t minimal,
                               Buffer* buffer) {
    DCHECK_LE(minimal, requested);
    ////LOG(INFO) << "BestEffortReallocate";
    Buffer* result;
    if (buffer == NULL) {
      result = AllocateInternal(requested, minimal, this);
      LogAllocation(requested, minimal, result);
      ////LOG(INFO) << "BestEffortReallocate end";
      return result;
    } else {
      result =  ReallocateInternal(requested, minimal, buffer, this) ?
          buffer : NULL;
      CHECK(buffer);    
      LogAllocation(requested, minimal, buffer);
      ////LOG(INFO) << "BestEffortReallocate end";
      return result;
    }
  }

  // Called by the user when a previously allocated block needs to be resized.
  // Equivalent to BestEffortReallocate(requested, requested, buffer).
  Buffer* Reallocate(size_t requested, Buffer* buffer) {
    ////LOG(INFO) << "Reallocate";
    return BestEffortReallocate(requested, requested, buffer);
  }

  // Returns the amount of memory (in bytes) still available for this allocator.
  // For unbounded allocators (like raw HeapBufferAllocator) this is the highest
  // size_t value possible.
  // TODO(user): consider making pure virtual.
  virtual size_t Available() const;

 protected:
  friend class Buffer;

  BufferAllocator() {}

  // Expose the constructor to subclasses of BufferAllocator.
  Buffer* CreateBuffer(void* data,
                       size_t size,
                       BufferAllocator* allocator) {
    return new Buffer(data, size, allocator);
  }

  // Expose Buffer::Update to subclasses of BufferAllocator.
  void UpdateBuffer(void* new_data, size_t new_size, Buffer* buffer) {
    ////LOG(INFO) << "UpdateBuffer";
    buffer->Update(new_data, new_size);
    ////LOG(INFO) << "UpdateBuffer end";
  }

  // Called by chained buffer allocators.
  Buffer* DelegateAllocate(BufferAllocator* delegate,
                           size_t requested,
                           size_t minimal,
                           BufferAllocator* originator) {
    return delegate->AllocateInternal(requested, minimal, originator);
  }

  // Called by chained buffer allocators.
  bool DelegateReallocate(BufferAllocator* delegate,
                          size_t requested,
                          size_t minimal,
                          Buffer* buffer,
                          BufferAllocator* originator) {
    return delegate->ReallocateInternal(requested, minimal, buffer, originator);
  }

  // Called by chained buffer allocators.
  void DelegateFree(BufferAllocator* delegate, Buffer* buffer) {
    delegate->FreeInternal(buffer);
  }

 private:
  // Implemented by concrete subclasses.
  virtual Buffer* AllocateInternal(size_t requested,
                                   size_t minimal,
                                   BufferAllocator* originator) = 0;

  // Implemented by concrete subclasses. Returns false on failure.
  virtual bool ReallocateInternal(size_t requested,
                                  size_t minimal,
                                  Buffer* buffer,
                                  BufferAllocator* originator) = 0;

  // Implemented by concrete subclasses.
  virtual void FreeInternal(Buffer* buffer) = 0;

  // Logs a warning message if the allocation failed or if it returned less than
  // the required number of bytes.
  void LogAllocation(size_t required, size_t minimal, Buffer* buffer);

  DISALLOW_COPY_AND_ASSIGN(BufferAllocator);
};

// Allocates buffers on the heap, with no memory limits. Uses standard C
// allocation functions (malloc, realloc, free).
class HeapBufferAllocator : public BufferAllocator {
 public:
    HeapBufferAllocator();
  explicit HeapBufferAllocator(bool aligned_mode)
      : aligned_mode_(aligned_mode) {}

  ~HeapBufferAllocator() override {}

  // Returns a singleton instance of the heap allocator.
  //static HeapBufferAllocator* Get() {
  //  static HeapBufferAllocator* allocator = new HeapBufferAllocator();
  //  return allocator;
  //}

  size_t Available() const override;

 private:
  // Allocates memory that is aligned to 16 way.
  // Use if you want to boost SIMD operations on the memory area.
  const bool aligned_mode_;

  base::Lock lock_;

  // A friend declaration for testing purposes. The function is in
  // datawarehouse/supersonic/testing/expression_test_helper.cc.
  // TODO(user): Refactor to make this unneccesary.
  friend BufferAllocator* CreateAligningHeapBufferAllocator();

  // Always allocates 'requested'-sized buffer, or returns NULL on OOM.
  Buffer* AllocateInternal(size_t requested,
                           size_t minimal,
                           BufferAllocator* originator) override;

  bool ReallocateInternal(size_t requested,
                          size_t minimal,
                          Buffer* buffer,
                          BufferAllocator* originator) override;

  void* Malloc(size_t size);
  void* Realloc(void* previousData, size_t previousSize, size_t newSize);

  void FreeInternal(Buffer* buffer) override;


  DISALLOW_COPY_AND_ASSIGN(HeapBufferAllocator);
};

// Wrapper around the delegate allocator, that clears all newly allocated
// (and reallocated) memory.
class ClearingBufferAllocator : public BufferAllocator {
 public:
  // Does not take ownership of the delegate.
  explicit ClearingBufferAllocator(BufferAllocator* delegate)
      : delegate_(delegate) {}

  size_t Available() const override;

 private:
  Buffer* AllocateInternal(size_t requested,
                           size_t minimal,
                           BufferAllocator* originator) override;

  bool ReallocateInternal(size_t requested,
                          size_t minimal,
                          Buffer* buffer,
                          BufferAllocator* originator) override;

  void FreeInternal(Buffer* buffer) override;

  BufferAllocator* delegate_;
  DISALLOW_COPY_AND_ASSIGN(ClearingBufferAllocator);
};

// Abstract policy for modifying allocation requests - e.g. enforcing quotas.
class Mediator {
 public:
  Mediator() {}
  virtual ~Mediator() {}

  // Called by an allocator when a allocation request is processed.
  // Must return a value in the range [minimal, requested], or zero. Returning
  // zero (if minimal is non-zero) indicates denial to allocate. Returning
  // non-zero indicates that the request should be capped at that value.
  virtual size_t Allocate(size_t requested, size_t minimal) = 0;

  // Called by an allocator when the specified amount (in bytes) is released.
  virtual void Free(size_t amount) = 0;

  // TODO(user): consider making pure virtual.
  virtual size_t Available() const;
};

// Optionally thread-safe skeletal implementation of a 'quota' abstraction,
// providing methods to allocate resources against the quota, and return them.
template<bool thread_safe>
class Quota : public Mediator {
 public:
  explicit Quota(bool enforced) : usage_(0), enforced_(enforced) {}
  virtual ~Quota() {}

  // Returns a value in range [minimal, requested] if not exceeding remaining
  // quota or if the quota is not enforced (soft quota), and adjusts the usage
  // value accordingly.  Otherwise, returns zero. The semantics of 'remaining
  // quota' are defined by subclasses (that must supply GetQuotaInternal()
  // method).
  virtual size_t Allocate(size_t requested, size_t minimal);

  virtual void Free(size_t amount);

  // Returns memory still available in the quota. For unenforced Quota objects,
  // you are still able to perform _minimal_ allocations when the available
  // quota is 0 (or less than "minimal" param).
  virtual size_t Available() const {
    //MutexLockMaybe lock(Quota<thread_safe>::mutex());
    const size_t quota = GetQuotaInternal();
    return (usage_ >= quota) ? 0 : (quota - usage_);
  }

  // Returns the current quota value.
  size_t GetQuota() const;

  // Returns the current usage value, defined as a sum of all the values
  // granted by calls to Allocate, less these released via calls to Free.
  size_t GetUsage() const;

  bool enforced() const {
    return enforced_;
  }

 protected:
  // Overridden by specific implementations, to define semantics of
  // the quota, i.e. the total amount of resources that the mediator will
  // allocate. Called directly from GetQuota that optionally provides
  // thread safety. An 'Allocate' request will succeed if
  // GetUsage() + minimal <= GetQuota() or if the quota is not enforced (soft
  // quota).
  virtual size_t GetQuotaInternal() const = 0;

  //Mutex* mutex() const { return thread_safe ? &mutex_ : NULL; }

  mutable base::Lock lock_;

 private:
  //mutable Mutex mutex_;

  size_t usage_;
  bool enforced_;
  DISALLOW_COPY_AND_ASSIGN(Quota);
};

// Optionally thread-safe static quota implementation (where quota is explicitly
// set to a concrete numeric value).
template<bool thread_safe>
class StaticQuota : public Quota<thread_safe> {
 public:
  explicit StaticQuota(size_t quota)
      : Quota<thread_safe>(true) {
    SetQuota(quota);
  }
  StaticQuota(size_t quota, bool enforced)
      : Quota<thread_safe>(enforced) {
    SetQuota(quota);
  }
  virtual ~StaticQuota() {}

  // Sets quota to the new value.
  void SetQuota(const size_t quota);

 protected:
  virtual size_t GetQuotaInternal() const { return quota_; }

 private:
  size_t quota_;
  mutable base::Lock lock_;
  DISALLOW_COPY_AND_ASSIGN(StaticQuota);
};

// Places resource limits on another allocator, using the specified Mediator
// (e.g. quota) implementation.
//
// If the mediator and the delegate allocator are thread-safe, this allocator
// is also thread-safe, to the extent that it will not introduce any
// state inconsistencies. However, without additional synchronization,
// allocation requests are not atomic end-to-end. This way, it is deadlock-
// resilient (even if you have cyclic relationships between allocators) and
// allows better concurrency. But, it may cause over-conservative
// allocations under memory contention, if you have multiple levels of
// mediating allocators. For example, if two requests that can't both be
// satisfied are submitted concurrently, it may happen that one of them succeeds
// but gets smaller buffer allocated than it would if the requests were strictly
// ordered. This is usually not a problem, however, as you don't really want to
// operate so close to memory limits that some of your allocations can't be
// satisfied. If you do have a simple, cascading graph of allocators though,
// and want to force requests be atomic end-to-end, put a
// ThreadSafeBufferAllocator at the entry point.
class MediatingBufferAllocator : public BufferAllocator {
 public:
  // Does not take ownership of the delegate, nor the mediator, allowing
  // both to be reused.
  MediatingBufferAllocator(BufferAllocator* const delegate,
                           Mediator* const mediator)
      : delegate_(delegate),
        mediator_(mediator) {}

  ~MediatingBufferAllocator() override {}

  size_t Available() const override;

 private:
  Buffer* AllocateInternal(size_t requested,
                           size_t minimal,
                           BufferAllocator* originator) override;

  bool ReallocateInternal(size_t requested,
                          size_t minimal,
                          Buffer* buffer,
                          BufferAllocator* originator) override;

  void FreeInternal(Buffer* buffer) override;

  BufferAllocator* delegate_;
  Mediator* const mediator_;
};

// Convenience non-thread-safe static memory bounds enforcer.
// Combines MediatingBufferAllocator with a StaticQuota.
class MemoryLimit : public BufferAllocator {
 public:
  // Creates a limiter based on the default, heap allocator. Quota is infinite.
  // (Can be set using SetQuota).
  explicit MemoryLimit(BufferAllocator* const allocator);

  // Creates a limiter relaying to the specified delegate allocator.
  MemoryLimit(size_t quota, BufferAllocator* const delegate);

  // Creates a (possibly non-enforcing) limiter relaying to the specified
  // delegate allocator.
  MemoryLimit(size_t quota, bool enforced, BufferAllocator* const delegate);

  ~MemoryLimit() override;

  size_t Available() const override;

  size_t GetQuota() const { return quota_.GetQuota(); }
  size_t GetUsage() const { return quota_.GetUsage(); }
  void SetQuota(const size_t quota) { quota_.SetQuota(quota); }

 private:
  Buffer* AllocateInternal(size_t requested,
                           size_t minimal,
                           BufferAllocator* originator) override;
  bool ReallocateInternal(size_t requested,
                          size_t minimal,
                          Buffer* buffer,
                          BufferAllocator* originator) override;
  void FreeInternal(Buffer* buffer) override;

  StaticQuota<false> quota_;
  MediatingBufferAllocator allocator_;
};

// An allocator that allows to bypass the (potential) soft quota below for a
// given amount of memory usage. The goal is to make the allocation methods and
// Available() work as if the allocator below had at least bypassed_amount of
// soft quota. Of course this class doesn't allow to exceed the hard quota.
class SoftQuotaBypassingBufferAllocator : public BufferAllocator {
 public:
  SoftQuotaBypassingBufferAllocator(BufferAllocator* allocator,
                                    size_t bypassed_amount)
      : allocator_(std::numeric_limits<size_t>::max(), allocator),
        bypassed_amount_(bypassed_amount) {}

  size_t Available() const override;

 private:
  // Calculates how much to increase the minimal parameter to allocate more
  // aggressively in the underlying allocator. This is to avoid getting only
  // very small allocations when we exceed the soft quota below. The request
  // with increased minimal size is more likely to fail because of exceeding
  // hard quota, so we also fall back to the original minimal size.
  size_t AdjustMinimal(size_t requested, size_t minimal) const {
    return std::min(requested, std::max(minimal, Available()));
  }

  Buffer* AllocateInternal(size_t requested,
                           size_t minimal,
                           BufferAllocator* originator) override;
  
  bool ReallocateInternal(size_t requested,
                          size_t minimal,
                          Buffer* buffer,
                          BufferAllocator* originator) override;

  void FreeInternal(Buffer* buffer) override;

  // Using MemoryLimit with "infinite" limit to get GetUsage().
  MemoryLimit allocator_;
  size_t bypassed_amount_;
};

// An interface for a MemoryStatisticsCollector - an object which collects
// information about the memory usage of the allocator. The collector will
// gather statistics about memory usage based on information received from the
// allocator.
class MemoryStatisticsCollectorInterface {
 public:
  MemoryStatisticsCollectorInterface();

  virtual ~MemoryStatisticsCollectorInterface();

  // Informs the collector that the allocator granted bytes memory. Note that in
  // the case of reallocation bytes should be the increase in total memory
  // usage, not the total size of the buffer after reallocation.
  virtual void AllocatedMemoryBytes(size_t bytes) = 0;

  // Informs the collector that the allocator received a request for at least
  // bytes memory, and rejected it (meaning that it granted nothing).
  virtual void RefusedMemoryBytes(size_t bytes) = 0;

  // Informs the collector that bytes memory have been released to the
  // allocator.
  virtual void FreedMemoryBytes(size_t bytes) = 0;

 private:
  DISALLOW_COPY_AND_ASSIGN(MemoryStatisticsCollectorInterface);
};

class MemoryStatisticsCollectingBufferAllocator : public BufferAllocator {
 public:
  // Does not take ownership of the delegate.
  // Takes ownership of memory_stats_collector.
  MemoryStatisticsCollectingBufferAllocator(
      BufferAllocator* const delegate,
      MemoryStatisticsCollectorInterface* const memory_stats_collector);

  ~MemoryStatisticsCollectingBufferAllocator() override;

  size_t Available() const override;

 private:
  
  Buffer* AllocateInternal(size_t requested,
                           size_t minimal,
                           BufferAllocator* originator) override;

  bool ReallocateInternal(size_t requested,
                          size_t minimal,
                          Buffer* buffer,
                          BufferAllocator* originator) override;

  void FreeInternal(Buffer* buffer) override;

  BufferAllocator* delegate_;
  std::unique_ptr<MemoryStatisticsCollectorInterface>
      memory_stats_collector_;
};

// Synchronizes access to AllocateInternal and FreeInternal, and exposes the
// mutex for use by subclasses. Allocation requests performed through this
// allocator are atomic end-to-end. Template parameter DelegateAllocatorType
// allows to specify a subclass of BufferAllocator for the delegate, to allow
// subclasses of ThreadSafeBufferAllocator to access additional methods provided
// by the allocator subclass. If this is not needed, it can be set to
// BufferAllocator.
template <class DelegateAllocatorType>
class ThreadSafeBufferAllocator : public BufferAllocator {
 public:
  // Does not take ownership of the delegate.
  explicit ThreadSafeBufferAllocator(DelegateAllocatorType* delegate)
      : delegate_(delegate) {}
  ~ThreadSafeBufferAllocator() override {}

  size_t Available() const override {
    //MutexLock lock(mutex());
    base::AutoLock lock(lock_);
    return delegate()->Available();
  }

 protected:
  //Mutex* mutex() const { return &mutex_; }
  // Expose the delegate allocator, with the precise type of the allocator
  // specified by the template parameter. The delegate() methods themselves
  // don't give any thread-safety guarantees. Protect all uses taking the Mutex
  // exposed by the mutex() method.
  DelegateAllocatorType* delegate() { return delegate_; }
  const DelegateAllocatorType* delegate() const { return delegate_; }

  mutable base::Lock lock_;

 private:
  Buffer* AllocateInternal(size_t requested,
                           size_t minimal,
                           BufferAllocator* originator) override {
    //MutexLock lock(mutex());
    base::AutoLock lock(lock_);
    return DelegateAllocate(delegate(), requested, minimal, originator);
  }

  bool ReallocateInternal(size_t requested,
                          size_t minimal,
                          Buffer* buffer,
                          BufferAllocator* originator) override {
    //MutexLock lock(mutex());
    base::AutoLock lock(lock_);
    return DelegateReallocate(delegate(), requested, minimal, buffer,
                              originator);
  }

  virtual void FreeInternal(Buffer* buffer) {
    //MutexLock lock(mutex());
    base::AutoLock lock(lock_);
    DelegateFree(delegate(), buffer);
  }

  DelegateAllocatorType* delegate_;
  //mutable Mutex mutex_;
 
  DISALLOW_COPY_AND_ASSIGN(ThreadSafeBufferAllocator);
};

// A version of ThreadSafeBufferAllocator that owns the supplied delegate
// allocator.
template <class DelegateAllocatorType>
class OwningThreadSafeBufferAllocator
    : public ThreadSafeBufferAllocator<DelegateAllocatorType> {
 public:
  explicit OwningThreadSafeBufferAllocator(DelegateAllocatorType* delegate)
      : ThreadSafeBufferAllocator<DelegateAllocatorType>(delegate),
        delegate_owned_(delegate) {}
  ~OwningThreadSafeBufferAllocator() override {}

 private:
  std::unique_ptr<DelegateAllocatorType> delegate_owned_;
};

class ThreadSafeMemoryLimit
    : public OwningThreadSafeBufferAllocator<MemoryLimit> {
 public:
  ThreadSafeMemoryLimit(size_t quota, bool enforced,
                        BufferAllocator* const delegate)
      : OwningThreadSafeBufferAllocator<MemoryLimit>(
            new MemoryLimit(quota, enforced, delegate)) {}
  ~ThreadSafeMemoryLimit() override {}

  size_t GetQuota() const {
    //MutexLock lock(mutex());
    base::AutoLock lock(lock_);
    return delegate()->GetQuota();
  }
  size_t GetUsage() const {
    //MutexLock lock(mutex());
    base::AutoLock lock(lock_);
    return delegate()->GetUsage();
  }
  void SetQuota(const size_t quota) {
    //MutexLock lock(mutex());
    base::AutoLock lock(lock_);
    delegate()->SetQuota(quota);
  }
};

// A BufferAllocator that can be given ownership of many objects of given type.
// These objects will then be deleted when the buffer allocator is destroyed.
// The objects added last are deleted first (LIFO).
template <typename OwnedType>
class OwningBufferAllocator : public BufferAllocator {
 public:
  // Doesn't take ownership of delegate.
  explicit OwningBufferAllocator(BufferAllocator* const delegate)
      : delegate_(delegate) {}

  ~OwningBufferAllocator() override {
    // Delete elements starting from the end.
    while (!owned_.empty()) {
      OwnedType* p = owned_.back();
      owned_.pop_back();
      delete p;
    }
  }

  // Add to the collection of objects owned by this allocator. The object added
  // last is deleted first.
  OwningBufferAllocator* Add(OwnedType* p) {
    owned_.push_back(p);
    return this;
  }

  size_t Available() const override {
    return delegate_->Available();
  }

 private:
  Buffer* AllocateInternal(size_t requested,
                           size_t minimal,
                           BufferAllocator* originator) override {
    return DelegateAllocate(delegate_, requested, minimal, originator);
  }

  bool ReallocateInternal(size_t requested,
                          size_t minimal,
                          Buffer* buffer,
                         BufferAllocator* originator) override {
    return DelegateReallocate(delegate_, requested, minimal, buffer,
                              originator);
  }

  virtual void FreeInternal(Buffer* buffer) {
    DelegateFree(delegate_, buffer);
  }

  // Not using PointerVector here because we want to guarantee certain order of
  // deleting elements (starting from the ones added last).
  vector<OwnedType*> owned_;
  BufferAllocator* delegate_;
};

// Buffer allocator that tries to guarantee the exact and consistent amount
// of memory. Uses hard MemoryLimit to enforce the upper bound but also
// guarantees consistent allocations by ignoring minimal requested amounts and
// always returning the full amount of memory requested if available.
// Allocations will fail if the memory requested would exceed the quota or if
// the underlying allocator fails to provide the memory.
class GuaranteeMemory : public BufferAllocator {
 public:
  // Doesn't take ownership of 'delegate'.
  GuaranteeMemory(size_t memory_quota,
                  BufferAllocator* delegate);

  ~GuaranteeMemory() override;

  size_t Available() const override;

 private:
  Buffer* AllocateInternal(size_t requested,
                           size_t minimal,
                           BufferAllocator* originator) override;

  bool ReallocateInternal(size_t requested,
                          size_t minimal,
                          Buffer* buffer,
                          BufferAllocator* originator)  override;

  void FreeInternal(Buffer* buffer) override;

  MemoryLimit limit_;
  size_t memory_guarantee_;
  DISALLOW_COPY_AND_ASSIGN(GuaranteeMemory);
};

// Implementation of inline and template methods

template<bool thread_safe>
size_t Quota<thread_safe>::Allocate(const size_t requested,
                                    const size_t minimal) {
  //MutexLockMaybe lock(mutex());
  base::AutoLock lock(lock_);
  DCHECK(minimal <= requested);
      //<< "\"minimal\" shouldn't be bigger than \"requested\"";
  const size_t quota = GetQuotaInternal();
  size_t allocation;
  if (usage_ > quota || minimal > quota - usage_) {
    // OOQ (Out of quota).
    if (!enforced() && minimal <= std::numeric_limits<size_t>::max() - usage_) {
      // The quota is unenforced and the value of "minimal" won't cause an
      // overflow. Perform a minimal allocation.
      allocation = minimal;
    } else {
      allocation = 0;
    }
    DLOG(WARNING) << "Out of quota. Requested: " << requested
                 << " bytes, or at least minimal: " << minimal
                 << ". Current quota value is: " << quota
                 << " while current usage is: " << usage_
                 << ". The quota is " << (enforced() ? "" : "not ")
                 << "enforced. "
                 << ((allocation == 0) ? "Did not allocate any memory."
                 : "Allocated the minimal value requested.");
  } else {
    allocation = std::min(requested, quota - usage_);
  }
  usage_ += allocation;
  return allocation;
}

template<bool thread_safe>
void Quota<thread_safe>::Free(size_t amount) {
  //MutexLockMaybe lock(mutex());
  base::AutoLock lock(lock_);
  usage_ -= amount;
  // threads allocate/free memory concurrently via the same Quota object that is
  // not protected with a mutex (thread_safe == false).
  if (usage_ > (std::numeric_limits<size_t>::max() - (1 << 28))) {
    DLOG(ERROR) << "Suspiciously big usage_ value: " << usage_
               << " (could be a result size_t wrapping around below 0, "
               << "for example as a result of race condition).";
  }
}

template<bool thread_safe>
size_t Quota<thread_safe>::GetQuota() const {
  //MutexLockMaybe lock(mutex());
  base::AutoLock lock(lock_);
  return GetQuotaInternal();
}

template<bool thread_safe>
size_t Quota<thread_safe>::GetUsage() const {
  //MutexLockMaybe lock(mutex());
  base::AutoLock lock(lock_);
  return usage_;
}

template<bool thread_safe>
void StaticQuota<thread_safe>::SetQuota(const size_t quota) {
  //MutexLockMaybe lock(Quota<thread_safe>::mutex());
  base::AutoLock lock(lock_);
  quota_ = quota;
}

}  // namespace storage

#endif  // MUMBA_STORAGE_DB_MEMORY_H_
