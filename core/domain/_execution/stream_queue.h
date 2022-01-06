// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_EXECUTION_STREAM_QUEUE_H_
#define MUMBA_DOMAIN_EXECUTION_STREAM_QUEUE_H_

#include <string>

#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/containers/queue.h"
#include "core/domain/execution/stream.h"

namespace domain {

class StreamQueue {
public:
  using Streams = base::queue<scoped_refptr<Stream>>;

  StreamQueue();
  ~StreamQueue();

  size_t stream_count() const {
    return stream_count_;
  }

  void Append(const scoped_refptr<Stream>& stream);

private:
  
  Streams streams_;

  size_t stream_count_;

  DISALLOW_COPY_AND_ASSIGN(StreamQueue);
};

}

#endif