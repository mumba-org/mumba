// Copyright 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_STORAGE_IO_ENTITY_
#define MUMBA_STORAGE_IO_ENTITY_

#include <memory>
#include <string>

#include "base/macros.h"
#include "net/base/io_buffer.h"
#include "storage/proto/storage.pb.h"
#include "google/protobuf/descriptor.h"
#include "google/protobuf/dynamic_message.h"

namespace storage {
class IOEntity {
public:
  virtual ~IOEntity() {}
  virtual const storage_proto::Info& info() const = 0;
  virtual void OnInfoHeaderChanged(const storage_proto::Info& info) = 0;
};

}

#endif