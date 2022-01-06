// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_COMMON_DATA_DATA_STREAM_H_
#define MUMBA_COMMON_DATA_DATA_STREAM_H_

#include "base/macros.h"
#include <memory>

namespace common {
class DataAtom;
// The ubiquotuous multi-atom representation object 
// and serialization entity

class DataStream {
public:
  DataStream(std::unique_ptr<DataAtom*[]> atoms, size_t alloc_size);
  ~DataStream();

  size_t size() const { return alloc_size_; }
  DataAtom* get(size_t offset) const;

private:

 std::unique_ptr<DataAtom*[]> atoms_;
 
 size_t alloc_size_;

 DISALLOW_COPY_AND_ASSIGN(DataStream);
};

class DataStreamBuilder {
public:
  DataStreamBuilder();
  ~DataStreamBuilder();

  std::unique_ptr<DataStream> Build();

private:
  DISALLOW_COPY_AND_ASSIGN(DataStreamBuilder);
};

}

#endif
