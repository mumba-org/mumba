// Copyright (c) 2011 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This file provides support for basic in-memory tracing of short events. We
// keep a static circular buffer where we store the last traced events, so we
// can review the cache recent behavior should we need it.

#ifndef STORAGE_STORAGE_BACKEND_BLOCKFILE_TRACE_H_
#define STORAGE_STORAGE_BACKEND_BLOCKFILE_TRACE_H_

#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "storage/storage_export.h"

namespace storage {

// Create and destroy the tracing buffer.
void InitTrace(void);
void DestroyTrace(void);

// Simple class to handle the trace buffer lifetime. Any object interested in
// tracing should keep a reference to the object returned by GetTraceObject().
class TraceObject : public base::RefCountedThreadSafe<TraceObject> {
  friend class base::RefCountedThreadSafe<TraceObject>;

 public:
  static TraceObject* GetTraceObject();
  void EnableTracing(bool enable);

 private:
  TraceObject();
  ~TraceObject();
  DISALLOW_COPY_AND_ASSIGN(TraceObject);
};

// Traces to the internal buffer.
STORAGE_EXPORT_PRIVATE void Trace(const char* format, ...);

}  // namespace storage

#endif  // STORAGE_STORAGE_BACKEND_BLOCKFILE_TRACE_H_
