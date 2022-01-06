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
// Memory arena for variable-length datatypes and STL collections.

#ifndef MUMBA_COMMON_DATA_DATA_ARENA_H_
#define MUMBA_COMMON_DATA_DATA_ARENA_H_

#include <stddef.h>
#include <string.h>

#include <memory>
#include <new>
#include <vector>
using std::vector;

#include "base/memory/ref_counted.h"
#include <memory>
#include "base/strings/string_piece.h"
#include "core/common/data/data_memory.h"

using std::allocator;


namespace common {

// A helper class for storing variable-length blobs (e.g. strings). Once a blob
// is added to the arena, its index stays fixed. No reallocation happens.
// Instead, the arena keeps a list of buffers. When it needs to grow, it
// allocates a new buffer. Each subsequent buffer is 2x larger, than its
// predecessor, until the maximum specified buffer size is reached.
// The buffers are furnished by a designated allocator.
class Arena {
 public:
  // Creates a new arena, with a single buffer of size up-to
  // initial_buffer_size, upper size limit for later-allocated buffers capped
  // at max_buffer_size, and maximum capacity (i.e. total sizes of all buffers)
  // possibly limited by the buffer allocator. The allocator might cap the
  // initial allocation request arbitrarily (down to zero). As a consequence,
  // arena construction never fails due to OOM.
  //
  // Calls to AllocateBytes() will then give out bytes from the working buffer
  // until it is exhausted. Then, a subsequent working buffer will be allocated.
  // The size of the next buffer is normally 2x the size of the previous buffer.
  // It might be capped by the allocator, or by the max_buffer_size parameter.
  Arena(BufferAllocator* const buffer_allocator,
        size_t initial_buffer_size,
        size_t max_buffer_size);
  
  ~Arena();

  // Creates an arena using a default (heap) allocator with unbounded capacity.
  // Discretion advised.
  //explicit Arena(size_t initial_buffer_size, size_t max_buffer_size);

  // Adds content of the specified StringPiece to the arena, and returns a
  // pointer to it. The pointer is guaranteed to remain valid during the
  // lifetime of the arena. The StringPiece object itself is not copied. The
  // size information is not stored.
  // (Normal use case is that the caller already has an array of StringPieces,
  // where it keeps these pointers together with size information).
  // If this request would make the arena grow and the allocator denies that,
  // returns NULL and leaves the arena unchanged.
  const char* AddStringPieceContent(const base::StringPiece& value);

  // Reserves a blob of the specified size in the arena, and returns a pointer
  // to it. The caller can then fill the allocated memory. The pointer is
  // guaranteed to remain valid during the lifetime of the arena.
  // If this request would make the arena grow and the allocator denies that,
  // returns NULL and leaves the arena unchanged.
  void* AllocateBytes(const size_t size);

  // Removes all data from the arena. (Invalidates all pointers returned by
  // AddStringPiece and AllocateBytes). Does not cause memory allocation.
  // May reduce memory footprint, as it discards all allocated buffers but
  // the last one.
  // Unless allocations exceed max_buffer_size, repetitive filling up and
  // resetting normally lead to quickly settling memory footprint and ceasing
  // buffer allocations, as the arena keeps reusing a single, large buffer.
  void Reset();

  // Returns the memory footprint of this arena, in bytes, defined as a sum of
  // all buffer sizes. Always greater or equal to the total number of
  // bytes allocated out of the arena.
  size_t memory_footprint() const { return arena_footprint_; }

 private:
  // Encapsulates a single buffer in the arena.
  class Component;

  //Component* AddComponent(size_t requested_size, size_t minimum_size);
  scoped_refptr<Component> AddComponent(size_t requested_size, size_t minimum_size);

  BufferAllocator* const buffer_allocator_;
  std::vector<scoped_refptr<Component> > arena_;
  scoped_refptr<Component> current_;
  const size_t max_buffer_size_;
  size_t arena_footprint_;
  DISALLOW_COPY_AND_ASSIGN(Arena);
};

// STL-compliant allocator, for use with hash_maps and other structures
// needed by transformations. Enables memory control and improves performance.
// (The code is shamelessly stolen from base/arena-inl.h).
template<class T> class ArenaAllocator {
 public:
  typedef T value_type;
  typedef size_t size_type;
  typedef ptrdiff_t difference_type;

  typedef T* pointer;
  typedef const T* const_pointer;
  typedef T& reference;
  typedef const T& const_reference;
  pointer index(reference r) const  { return &r; }
  const_pointer index(const_reference r) const  { return &r; }
  size_type max_size() const  { return size_t(-1) / sizeof(T); }

  explicit ArenaAllocator(Arena* arena) : arena_(arena) {
    DCHECK(arena_);
  }

  ~ArenaAllocator() { }

  pointer allocate(size_type n, allocator<void>::const_pointer /*hint*/ = 0) {
    return reinterpret_cast<T*>(arena_->AllocateBytes(n * sizeof(T)));
  }

  void deallocate(pointer p, size_type n) {}

  void construct(pointer p, const T& val) {
    new(reinterpret_cast<void*>(p)) T(val);
  }

  void destroy(pointer p) { p->~T(); }

  template<class U> struct rebind {
    typedef ArenaAllocator<U> other;
  };

  template<class U> ArenaAllocator(const ArenaAllocator<U>& other)
      : arena_(other.arena()) { }

  template<class U> bool operator==(const ArenaAllocator<U>& other) const {
    return arena_ == other.arena();
  }

  template<class U> bool operator!=(const ArenaAllocator<U>& other) const {
    return arena_ != other.arena();
  }

 private:
  Arena* arena_;
};

// Implementation of inline and template methods

class Arena::Component : public base::RefCounted<Arena::Component> {
 public:
  explicit Component(Buffer* buffer);
  // Tries to reserve space in this component. Returns the pointer to the
  // reserved space if successful; NULL on failure (if there's no more room).
  void* AllocateBytes(const size_t size) {
    if (offset_ + size <= size_) {
      void* destination = data_ + offset_;
      offset_ += size;
      return destination;
    } else {
      return NULL;
    }
  }

  size_t size() const { return size_; }
  void Reset() { offset_ = 0; }

 private:
  friend class base::RefCounted<Arena::Component>;
  ~Component();
  
  std::unique_ptr<Buffer> buffer_;
  char* const data_;
  size_t offset_;
  const size_t size_;
  DISALLOW_COPY_AND_ASSIGN(Component);
};

inline const char* Arena::AddStringPieceContent(const base::StringPiece& value) {
  void* destination = AllocateBytes(value.size());
  if (destination == NULL) return NULL;
  //LOG(INFO) <<  " size: " << value.size();
  memcpy(destination, value.data(), value.size());
  return static_cast<const char*>(destination);
}

}  // namespace db

#endif  // SUPERSONIC_BASE_MEMORY_ARENA_H_
