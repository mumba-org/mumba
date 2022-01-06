// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_COMMON_DATA_DATA_SERIALIZER_H_
#define MUMBA_COMMON_DATA_DATA_SERIALIZER_H_

#include <string>

#include "base/macros.h"

namespace common {
class TableAtom;
class DataAtom;
class DataStream;
class ResultSet;
class DataContext;

// encoder for wire representation of a datum
class DataEncoder {
public:

  DataEncoder();
  
  bool EncodeTable(const TableAtom* ds, std::string* out);
  bool EncodeResultSet(ResultSet* rs, std::string* out);
  bool EncodeStream(DataStream* stream, std::string* out);
  bool EncodeAtom(DataAtom* atom, std::string* out);
  // TODO: A ideia principal é dar o encode no DataStream

private:

 DISALLOW_COPY_AND_ASSIGN(DataEncoder);
};

// decoder from wire representation of a datum
class DataDecoder {
public:
  DataDecoder(DataContext* context);
  
  bool DecodeTable(const std::string& data, TableAtom** out);
  bool DecodeTable(const char* data, size_t len, TableAtom** out);
  bool DecodeStream(const std::string& data, DataStream** out);
  bool DecodeAtom(const std::string& data, DataAtom** out);
  // TODO: A ideia principal é dar o decode no DataStream

private:
  
 DataContext* context_;
 
 DISALLOW_COPY_AND_ASSIGN(DataDecoder);
};



}

#endif

