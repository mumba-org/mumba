// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/common/data/data_stream.h"

#include "core/common/data/data_atom.h"

namespace common {

DataStream::DataStream(std::unique_ptr<DataAtom*[]> atoms, size_t alloc_size): 
  atoms_(std::move(atoms)),
  alloc_size_(alloc_size) {

}

DataStream::~DataStream() {
  for (size_t i = 0; i < alloc_size_; i++) {
    if (atoms_[i]) {
      delete atoms_[i];
    }
  }
}

DataAtom* DataStream::get(size_t offset) const {
  DCHECK(offset < alloc_size_);
  return atoms_[offset];
}

DataStreamBuilder::DataStreamBuilder() {}

DataStreamBuilder::~DataStreamBuilder() {}

std::unique_ptr<DataStream> DataStreamBuilder::Build() {
  std::unique_ptr<DataAtom*[]> atoms(new DataAtom*[1]);
  atoms[0] = nullptr;
  return std::unique_ptr<DataStream>(new DataStream(std::move(atoms), 1));
}

}