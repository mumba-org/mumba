// Copyright 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "storage/data_column.h"
#include "storage/db/db.h"

namespace storage {

DataColumn::DataColumn(): type_(nullptr) {

}

DataColumn::~DataColumn() {
 
}

std::string DataColumn::Name() const {
  return name_;
}

std::string DataColumn::FullName() const {
  return name_;
}

const zetasql::Type* DataColumn::GetType() const {
  return type_;
}

bool DataColumn::Deserialize(zetasql::TypeFactory* factory, const storage_proto::Column& column) {
  name_ = column.name();
  switch (column.type()) {
    case storage_proto::COLUMN_INT32:
     type_ = zetasql::types::Int32Type();
     break;
    case storage_proto::COLUMN_INT64:
     type_ = zetasql::types::Int64Type();
     break;
    case storage_proto::COLUMN_UINT32:
     type_ = zetasql::types::Uint32Type();
     break;
    case storage_proto::COLUMN_UINT64:
     type_ = zetasql::types::Uint64Type();
     break;
    case storage_proto::COLUMN_BOOL:
     type_ = zetasql::types::BoolType();
     break;
    case storage_proto::COLUMN_FLOAT:
     type_ = zetasql::types::FloatType();
     break;
    case storage_proto::COLUMN_DOUBLE:
     type_ = zetasql::types::DoubleType();
     break;
    case storage_proto::COLUMN_STRING:
     type_ = zetasql::types::StringType();
     break;
    case storage_proto::COLUMN_BYTES:
     type_ = zetasql::types::BytesType();
     break;
    case storage_proto::COLUMN_DATE:
     type_ = zetasql::types::DateType();
     break;
    case storage_proto::COLUMN_TIMESTAMP:
     type_ = zetasql::types::TimestampType();
     break;
    case storage_proto::COLUMN_TIME:
     type_ = zetasql::types::TimeType();
     break;
    case storage_proto::COLUMN_DATETIME:
     type_ = zetasql::types::DatetimeType();
     break;
    case storage_proto::COLUMN_GEOGRAPHY:
     type_ = zetasql::types::GeographyType();
     break;
    case storage_proto::COLUMN_NUMERIC:
     type_ = zetasql::types::NumericType();
     break;
    case storage_proto::COLUMN_STRUCT:
     type_ = zetasql::types::EmptyStructType();
     break;
     case storage_proto::COLUMN_INT32_ARRAY:
     type_ = zetasql::types::Int32ArrayType();
     break;
    case storage_proto::COLUMN_INT64_ARRAY:
     type_ = zetasql::types::Int64ArrayType();
     break;
    case storage_proto::COLUMN_UINT32_ARRAY:
     type_ = zetasql::types::Uint32ArrayType();
     break;
    case storage_proto::COLUMN_UINT64_ARRAY:
     type_ = zetasql::types::Uint64ArrayType();
     break;
    case storage_proto::COLUMN_BOOL_ARRAY:
     type_ = zetasql::types::BoolArrayType();
     break;
    case storage_proto::COLUMN_FLOAT_ARRAY:
     type_ = zetasql::types::FloatArrayType();
     break;
    case storage_proto::COLUMN_DOUBLE_ARRAY:
     type_ = zetasql::types::DoubleArrayType();
     break;
    case storage_proto::COLUMN_STRING_ARRAY:
     type_ = zetasql::types::StringArrayType();
     break;
    case storage_proto::COLUMN_BYTES_ARRAY:
     type_ = zetasql::types::BytesArrayType();
     break;
    case storage_proto::COLUMN_TIMESTAMP_ARRAY:
     type_ = zetasql::types::TimestampArrayType();
     break;
    case storage_proto::COLUMN_DATETIME_ARRAY:
     type_ = zetasql::types::DatetimeArrayType();
     break;
    case storage_proto::COLUMN_GEOGRAPHY_ARRAY:
     type_ = zetasql::types::GeographyArrayType();
     break;
    case storage_proto::COLUMN_NUMERIC_ARRAY:
     type_ = zetasql::types::NumericArrayType();
     break;
    default:
     NOTREACHED();
  }

  return true;
}

}