// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_NAMESPACE_STREAM_H_
#define MUMBA_DOMAIN_NAMESPACE_STREAM_H_

#include "base/macros.h"
#include "base/memory/weak_ptr.h"
#include "net/base/completion_once_callback.h"
#include "net/base/io_buffer.h"
#include "net/base/load_timing_info.h"
#include "net/base/net_export.h"
//#include "net/websockets/websocket_stream.h"

namespace domain {

class Stream {
public:
  virtual ~Stream() {}
};

class IPCStream : public Stream {
public:
  IPCStream();
  ~IPCStream() override;

private:
  DISALLOW_COPY_AND_ASSIGN(IPCStream);
};

class HTTPStream : public Stream {
public:
  HTTPStream();
  ~HTTPStream() override;

private:
  DISALLOW_COPY_AND_ASSIGN(HTTPStream);
};

}

#endif