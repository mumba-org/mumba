// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "storage/data_common.h"

namespace storage {

namespace {

const int kVARLENGTH_MEDIAN_SIZE = 255;

}

ColumnData::ColumnData() {}

ColumnData::~ColumnData() {}

void ColumnData::Init(BufferAllocator* allocator, size_t length, bool is_var_length) {
  Init(allocator, length, is_var_length, length * kVARLENGTH_MEDIAN_SIZE);
}

void ColumnData::Init(BufferAllocator* allocator, size_t length, bool is_var_length, size_t var_length_size) {
  is_var_length_ = is_var_length;
  if (is_var_length) {
    arena_.reset(new Arena(allocator, var_length_size, std::numeric_limits<size_t>::max()));
  }
  //LOG(INFO) << "allocando " << length << " bytes";
  data_buffer_.reset(allocator->Allocate(length));
}

void ColumnData::GrowBuffer(BufferAllocator* allocator, size_t len) {
  base::AutoLock lock(lock_);
  CHECK(allocator);
  Buffer* buf = data_buffer_.get();
  CHECK(buf);
  size_t newsize = len + data_buffer_->size();
  //LOG(INFO) << "reallocando " << newsize << " bytes";
  allocator->Reallocate(newsize, buf);
  //LOG(INFO) << "saindo de growbuffer. buf at: " << buf->data();
}

Schema::Schema(): cur_pos_(0) {}


Schema::~Schema() {
  //for (auto it = schemas_.begin(); it != schemas_.end(); ++it) {
  //  delete *it;
  //}
}

bool Schema::Deserialize(zetasql::TypeFactory* factory, const storage_proto::Table& table) {
  for (const auto& column_proto : table.column()) {
    const zetasql::Type* type = nullptr;
    switch (column_proto.type()) {
      case storage_proto::COLUMN_INT32:
        type = zetasql::types::Int32Type();
        break;
      case storage_proto::COLUMN_INT64:
        type = zetasql::types::Int64Type();
        break;
      case storage_proto::COLUMN_UINT32:
        type = zetasql::types::Uint32Type();
        break;
      case storage_proto::COLUMN_UINT64:
        type = zetasql::types::Uint64Type();
        break;
      case storage_proto::COLUMN_BOOL:
        type = zetasql::types::BoolType();
        break;
      case storage_proto::COLUMN_FLOAT:
        type = zetasql::types::FloatType();
        break;
      case storage_proto::COLUMN_DOUBLE:
        type = zetasql::types::DoubleType();
        break;
      case storage_proto::COLUMN_STRING:
        type = zetasql::types::StringType();
        break;
      case storage_proto::COLUMN_BYTES:
        type = zetasql::types::BytesType();
        break;
      case storage_proto::COLUMN_DATE:
        type = zetasql::types::DateType();
        break;
      case storage_proto::COLUMN_TIMESTAMP:
        type = zetasql::types::TimestampType();
        break;
      case storage_proto::COLUMN_TIME:
        type = zetasql::types::TimeType();
        break;
      case storage_proto::COLUMN_DATETIME:
        type = zetasql::types::DatetimeType();
        break;
      case storage_proto::COLUMN_GEOGRAPHY:
        type = zetasql::types::GeographyType();
        break;
      case storage_proto::COLUMN_NUMERIC:
        type = zetasql::types::NumericType();
        break;
      case storage_proto::COLUMN_STRUCT:
        type = zetasql::types::EmptyStructType();
        break;
      case storage_proto::COLUMN_INT32_ARRAY:
        type = zetasql::types::Int32ArrayType();
        break;
      case storage_proto::COLUMN_INT64_ARRAY:
        type = zetasql::types::Int64ArrayType();
        break;
      case storage_proto::COLUMN_UINT32_ARRAY:
        type = zetasql::types::Uint32ArrayType();
        break;
      case storage_proto::COLUMN_UINT64_ARRAY:
        type = zetasql::types::Uint64ArrayType();
        break;
      case storage_proto::COLUMN_BOOL_ARRAY:
        type = zetasql::types::BoolArrayType();
        break;
      case storage_proto::COLUMN_FLOAT_ARRAY:
        type = zetasql::types::FloatArrayType();
        break;
      case storage_proto::COLUMN_DOUBLE_ARRAY:
        type = zetasql::types::DoubleArrayType();
        break;
      case storage_proto::COLUMN_STRING_ARRAY:
        type = zetasql::types::StringArrayType();
        break;
      case storage_proto::COLUMN_BYTES_ARRAY:
        type = zetasql::types::BytesArrayType();
        break;
      case storage_proto::COLUMN_TIMESTAMP_ARRAY:
        type = zetasql::types::TimestampArrayType();
        break;
      case storage_proto::COLUMN_DATETIME_ARRAY:
        type = zetasql::types::DatetimeArrayType();
        break;
      case storage_proto::COLUMN_GEOGRAPHY_ARRAY:
        type = zetasql::types::GeographyArrayType();
        break;
      case storage_proto::COLUMN_NUMERIC_ARRAY:
        type = zetasql::types::NumericArrayType();
        break;
      default:
        NOTREACHED();
    }
    AddColumn(column_proto.name(), type);
  }
  return true;
}

void Schema::AddColumn(const std::string& name, const zetasql::Type *type) {
  types_.push_back(type);
  pos_.emplace(std::make_pair(name, cur_pos_));
  cur_pos_++;
}


}