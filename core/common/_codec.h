// Copyright (c) 2017 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_COMMON_CODEC_H_
#define MUMBA_COMMON_CODEC_H_

#include <string>

#include "base/macros.h"
#include <memory>

namespace common {

class Encoder {
public:  
  virtual ~Encoder() {}
  
  virtual const void* buffer() const = 0;
  virtual size_t buffer_size() const = 0;

  virtual void End(std::string* result) = 0;

  virtual void WriteBool(const std::string& name, bool b) = 0;
  virtual void WriteInt8(const std::string& name, int8_t i) = 0;
  virtual void WriteUint8(const std::string& name, uint8_t i) = 0;
  virtual void WriteInt16(const std::string& name, int16_t i) = 0;
  virtual void WriteUint16(const std::string& name, uint16_t i) = 0;
  virtual void WriteInt32(const std::string& name, int32_t i) = 0;
  virtual void WriteUint32(const std::string& name, uint32_t i) = 0;
  virtual void WriteInt64(const std::string& name, int64_t i) = 0;
  virtual void WriteUint64(const std::string& name, uint64_t i) = 0;
  virtual void WriteString(const std::string& name, const std::string& str) = 0;
  virtual void WriteBytes(const std::string& name, const uint8_t* data, size_t len) = 0;

  virtual void WriteBool(bool b) = 0;
  virtual void WriteInt8(int8_t i) = 0;
  virtual void WriteUint8(uint8_t i) = 0;
  virtual void WriteInt16(int16_t i) = 0;
  virtual void WriteUint16(uint16_t i) = 0;
  virtual void WriteInt32(int32_t i) = 0;
  virtual void WriteUint32(uint32_t i) = 0;
  virtual void WriteInt64(int64_t i) = 0;
  virtual void WriteUint64(uint64_t i) = 0;
  virtual void WriteString(const std::string& str) = 0;

  virtual void BeginArray(const std::string& name) = 0;
  virtual void EndArray() = 0;

  virtual void BeginObject() = 0;
  virtual void EndObject() = 0;
};

class Decoder {
public:
  virtual ~Decoder() {}
  virtual void ReadBool(const std::string& name, bool* b) = 0;
  virtual void ReadInt8(const std::string& name, int8_t* i) = 0;
  virtual void ReadUint8(const std::string& name, uint8_t* i) = 0;
  virtual void ReadInt16(const std::string& name, int16_t* i) = 0;
  virtual void ReadUint16(const std::string& name, uint16_t* i) = 0;
  virtual void ReadInt32(const std::string& name, int32_t* i) = 0;
  virtual void ReadUint32(const std::string& name, uint32_t* i) = 0;
  virtual void ReadInt64(const std::string& name, int64_t* i) = 0;
  virtual void ReadUint64(const std::string& name, uint64_t* i) = 0;
  virtual void ReadString(const std::string& name, std::string& str) = 0;
  virtual void ReadBytes(const std::string& name, const char** out) = 0;
  //virtual std::unique_ptr<ArrayIterator> array_iterator(const std::string& name) const = 0;
};

}

#endif