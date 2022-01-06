// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_CONTAINER_SERIALIZABLE_H_
#define MUMBA_HOST_CONTAINER_SERIALIZABLE_H_

#include <string>

#include "net/base/io_buffer.h"

namespace host {

class Serializable {
public:
  virtual ~Serializable() {}
  virtual scoped_refptr<net::IOBufferWithSize> Serialize() const = 0;
};

}

#endif