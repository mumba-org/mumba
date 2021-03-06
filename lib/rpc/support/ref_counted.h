/*
 *
 * Copyright 2017 gRPC authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#ifndef GRPC_CORE_LIB_SUPPORT_REF_COUNTED_H
#define GRPC_CORE_LIB_SUPPORT_REF_COUNTED_H

#include <rpc/support/log.h>
#include <rpc/support/sync.h>

#include "rpc/debug/trace.h"
#include "rpc/support/debug_location.h"
#include "rpc/support/memory.h"

namespace grpc_core {

// A base class for reference-counted objects.
// New objects should be created via New() and start with a refcount of 1.
// When the refcount reaches 0, the object will be deleted via Delete().
class RefCounted {
 public:
  void Ref() { gpr_ref(&refs_); }

  void Unref() {
    if (gpr_unref(&refs_)) {
      Delete(this);
    }
  }

  // Not copyable nor movable.
  RefCounted(const RefCounted&) = delete;
  RefCounted& operator=(const RefCounted&) = delete;

 protected:
  // Allow Delete() to access destructor.
  template <typename T>
  friend void Delete(T*);

  RefCounted() { gpr_ref_init(&refs_, 1); }

  virtual ~RefCounted() {}

 private:
  gpr_refcount refs_;
};

// An alternative version of the RefCounted base class that
// supports tracing.  This is intended to be used in cases where the
// object will be handled both by idiomatic C++ code using smart
// pointers and legacy code that is manually calling Ref() and Unref().
// Once all of our code is converted to idiomatic C++, we may be able to
// eliminate this class.
class RefCountedWithTracing {
 public:
  void Ref() { gpr_ref(&refs_); }

  void Ref(const DebugLocation& location, const char* reason) {
    if (location.Log() && trace_flag_ != nullptr && trace_flag_->enabled()) {
      gpr_atm old_refs = gpr_atm_no_barrier_load(&refs_.count);
      gpr_log(GPR_DEBUG, "%s:%p %s:%d ref %" PRIdPTR " -> %" PRIdPTR " %s",
              trace_flag_->name(), this, location.file(), location.line(),
              old_refs, old_refs + 1, reason);
    }
    Ref();
  }

  void Unref() {
    if (gpr_unref(&refs_)) {
      Delete(this);
    }
  }

  void Unref(const DebugLocation& location, const char* reason) {
    if (location.Log() && trace_flag_ != nullptr && trace_flag_->enabled()) {
      gpr_atm old_refs = gpr_atm_no_barrier_load(&refs_.count);
      gpr_log(GPR_DEBUG, "%s:%p %s:%d unref %" PRIdPTR " -> %" PRIdPTR " %s",
              trace_flag_->name(), this, location.file(), location.line(),
              old_refs, old_refs - 1, reason);
    }
    Unref();
  }

  // Not copyable nor movable.
  RefCountedWithTracing(const RefCountedWithTracing&) = delete;
  RefCountedWithTracing& operator=(const RefCountedWithTracing&) = delete;

 protected:
  // Allow Delete() to access destructor.
  template <typename T>
  friend void Delete(T*);

  RefCountedWithTracing() : RefCountedWithTracing(nullptr) {}

  explicit RefCountedWithTracing(TraceFlag* trace_flag)
      : trace_flag_(trace_flag) {
    gpr_ref_init(&refs_, 1);
  }

  virtual ~RefCountedWithTracing() {}

 private:
  TraceFlag* trace_flag_ = nullptr;
  gpr_refcount refs_;
};

}  // namespace grpc_core

#endif /* GRPC_CORE_LIB_SUPPORT_REF_COUNTED_H */
