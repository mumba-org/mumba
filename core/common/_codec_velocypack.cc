// Copyright (c) 2017 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/common/codec_velocypack.h"

#include "base/logging.h"

namespace common {

VelocypackEncoder::VelocypackEncoder() {
  builder_.add(Value(ValueType::Object));
}

VelocypackEncoder::~VelocypackEncoder() {}

const void* VelocypackEncoder::buffer() const { 
  return reinterpret_cast<const void *>(builder_.slice().begin()); 
}

size_t VelocypackEncoder::buffer_size() const { 
  return builder_.slice().byteSize(); 
}

void VelocypackEncoder::End(std::string* result) {
  builder_.close();
  result->assign(reinterpret_cast<const char *>(builder_.slice().begin()), builder_.slice().byteSize());
}

void VelocypackEncoder::WriteBool(const std::string& name, bool b) {
  builder_.add(name, Value(b));
}

void VelocypackEncoder::WriteInt8(const std::string& name, int8_t i) {
  builder_.add(name, Value(static_cast<int>(i)));
}

void VelocypackEncoder::WriteUint8(const std::string& name, uint8_t i) {
  builder_.add(name, Value(i, ValueType::UInt));
}

void VelocypackEncoder::WriteInt16(const std::string& name, int16_t i) {
  builder_.add(name, Value(static_cast<int>(i)));
}

void VelocypackEncoder::WriteUint16(const std::string& name, uint16_t i) {
  builder_.add(name, Value(i, ValueType::UInt));
}

void VelocypackEncoder::WriteInt32(const std::string& name, int32_t i) {
  builder_.add(name, Value(i));
}

void VelocypackEncoder::WriteUint32(const std::string& name, uint32_t i) {
  builder_.add(name, Value(i, ValueType::UInt));
}

void VelocypackEncoder::WriteInt64(const std::string& name, int64_t i) {
  builder_.add(name, Value(i, ValueType::Int));
}

void VelocypackEncoder::WriteUint64(const std::string& name, uint64_t i) {
  builder_.add(name, Value(static_cast<int64_t>(i), ValueType::Int));
}

void VelocypackEncoder::WriteString(const std::string& name, const std::string& str) {
  builder_.add(name, Value(str));
}

void VelocypackEncoder::WriteBytes(const std::string& name, const uint8_t* data, size_t len) {
  builder_.add(name, Value(data, ValueType::External)); 
}

void VelocypackEncoder::WriteBool(bool b) {
  builder_.add(Value(b));
}

void VelocypackEncoder::WriteInt8(int8_t i) {
  builder_.add(Value(static_cast<int>(i)));
}

void VelocypackEncoder::WriteUint8(uint8_t i) {
  builder_.add(Value(i, ValueType::UInt));
}

void VelocypackEncoder::WriteInt16(int16_t i) {
  builder_.add(Value(static_cast<int>(i)));
}

void VelocypackEncoder::WriteUint16(uint16_t i) {
  builder_.add(Value(i, ValueType::UInt));
}

void VelocypackEncoder::WriteInt32(int32_t i) {
  builder_.add(Value(i));
}

void VelocypackEncoder::WriteUint32(uint32_t i) {
  builder_.add(Value(i, ValueType::UInt));
}

void VelocypackEncoder::WriteInt64(int64_t i) {
  builder_.add(Value(i, ValueType::Int));
}

void VelocypackEncoder::WriteUint64(uint64_t i) {
  builder_.add(Value(static_cast<int64_t>(i), ValueType::Int));
}

void VelocypackEncoder::WriteString(const std::string& str) {
  builder_.add(Value(str));
}

void VelocypackEncoder::BeginArray(const std::string& name) {
  builder_.add(name, Value(ValueType::Array));
}

void VelocypackEncoder::EndArray() {
  builder_.close();
}

void VelocypackEncoder::BeginObject() {
  builder_.add(Value(ValueType::Object));
}

void VelocypackEncoder::EndObject() {
  builder_.close();
}


VelocypackDecoder::VelocypackDecoder(const uint8_t* data, size_t len): slice_(data) {
}

VelocypackDecoder::~VelocypackDecoder() {}

void VelocypackDecoder::ReadBool(const std::string& name, bool* b) {
 Slice value(slice_.get(name));
 *b = value.getBool();
}

void VelocypackDecoder::ReadInt8(const std::string& name, int8_t* i) {
 Slice value(slice_.get(name));
 *i = ReadNumber<int8_t>(value);
}

void VelocypackDecoder::ReadUint8(const std::string& name, uint8_t* i) {
 Slice value(slice_.get(name));
 *i = ReadNumber<uint8_t>(value);
}

void VelocypackDecoder::ReadInt16(const std::string& name, int16_t* i) {
 Slice value(slice_.get(name));
 *i = ReadNumber<int16_t>(value);
}

void VelocypackDecoder::ReadUint16(const std::string& name, uint16_t* i) {
 Slice value(slice_.get(name));
 *i = ReadNumber<uint16_t>(value);
}

void VelocypackDecoder::ReadInt32(const std::string& name, int32_t* i) {
 Slice value(slice_.get(name));
 *i = ReadNumber<int32_t>(value);
}

void VelocypackDecoder::ReadUint32(const std::string& name, uint32_t* i) {
 Slice value(slice_.get(name));
 *i = ReadNumber<uint32_t>(value);
}

void VelocypackDecoder::ReadInt64(const std::string& name, int64_t* i) {
  Slice value(slice_.get(name));
 *i = ReadNumber<int64_t>(value);
}

void VelocypackDecoder::ReadUint64(const std::string& name, uint64_t* i) {
 Slice value(slice_.get(name));
 *i = ReadNumber<uint64_t>(value);
}

void VelocypackDecoder::ReadString(const std::string& name, std::string& str) {
  Slice value(slice_.get(name));
  str = value.copyString();
}

void VelocypackDecoder::ReadBytes(const std::string& name, const char** out) {
  Slice value(slice_.get(name));
  *out = value.getExternal();
}

}