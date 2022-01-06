// Copyright (c) 2017 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_COMMON_CODEC_VELOCYPACK_H_
#define MUMBA_COMMON_CODEC_VELOCYPACK_H_

#include "core/common/codec.h"
#include "third_party/velocypack/include/velocypack/vpack.h"

using arangodb::velocypack::Builder;
using arangodb::velocypack::Value;
using arangodb::velocypack::ValueType;
using arangodb::velocypack::Slice;
using arangodb::velocypack::HexDump;
using arangodb::velocypack::ArrayIterator;

namespace common {

class VelocypackEncoder : public Encoder {
public:
  VelocypackEncoder();
  ~VelocypackEncoder() override;

  const void* buffer() const override;
  size_t buffer_size() const override;

  arangodb::velocypack::Builder& builder() { return builder_; }

  void End(std::string* result) override;
  void WriteBool(const std::string& name, bool b) override;
  void WriteInt8(const std::string& name, int8_t i) override;
  void WriteUint8(const std::string& name, uint8_t i) override;
  void WriteInt16(const std::string& name, int16_t i) override;
  void WriteUint16(const std::string& name, uint16_t i) override;
  void WriteInt32(const std::string& name, int32_t i) override;
  void WriteUint32(const std::string& name, uint32_t i) override;
  void WriteInt64(const std::string& name, int64_t i) override;
  void WriteUint64(const std::string& name, uint64_t i) override;
  void WriteString(const std::string& name, const std::string& str) override;
  void WriteBytes(const std::string& name, const uint8_t* data, size_t len) override;
  void WriteBool(bool b) override;
  void WriteInt8(int8_t i) override;
  void WriteUint8(uint8_t i) override;
  void WriteInt16(int16_t i) override;
  void WriteUint16(uint16_t i) override;
  void WriteInt32(int32_t i) override;
  void WriteUint32(uint32_t i) override;
  void WriteInt64(int64_t i) override;
  void WriteUint64(uint64_t i) override;
  void WriteString(const std::string& str) override;
  void BeginArray(const std::string& name) override;
  void EndArray() override;
  void BeginObject() override;
  void EndObject() override;

private:
  Builder builder_;
};

class VelocypackDecoder : public Decoder {
public:
  VelocypackDecoder(const uint8_t* data, size_t len);
  ~VelocypackDecoder() override;

  void ReadBool(const std::string& name, bool* b) override;
  void ReadInt8(const std::string& name, int8_t* i) override;
  void ReadUint8(const std::string& name, uint8_t* i) override;
  void ReadInt16(const std::string& name, int16_t* i) override;
  void ReadUint16(const std::string& name, uint16_t* i) override;
  void ReadInt32(const std::string& name, int32_t* i) override;
  void ReadUint32(const std::string& name, uint32_t* i) override;
  void ReadInt64(const std::string& name, int64_t* i) override;
  void ReadUint64(const std::string& name, uint64_t* i) override;
  void ReadString(const std::string& name, std::string& str) override;
  void ReadBytes(const std::string& name, const char** out) override;
  
  std::unique_ptr<ArrayIterator> array_iterator(const std::string& name) const {
    Slice array(slice_.get(name));
    return std::unique_ptr<ArrayIterator>(new ArrayIterator(array));
  }

private:
  
  template <typename T>
  inline T ReadNumber(const Slice& s) const {
    T i;
  
    if (s.isSmallInt())
      i = static_cast<T>(s.getSmallInt());
    else if (s.isInt())
      i = static_cast<T>(s.getInt());
    else if(s.isUInt())
      i = static_cast<T>(s.getUInt());
    else
      i = 0; 

    return i;
  }

  Slice slice_;
};
  
}

#endif