// Copyright 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_STORAGE_DATA_COLUMN_
#define MUMBA_STORAGE_DATA_COLUMN_

#include <memory>
#include <string>

#include "base/macros.h"
#include "storage/data_common.h"
#include "zetasql/public/catalog.h"
#include "zetasql/base/status.h"
#include "storage/proto/storage.pb.h"
#include "storage/storage_export.h"

namespace storage {

class STORAGE_EXPORT DataColumn : public zetasql::Column {
public:
  DataColumn();
  ~DataColumn();

  void Init(BufferAllocator* allocator, const zetasql::Type* type, const std::string& name, size_t rows) {
    type_ = type;
    name_ = name;
    allocated_rows_ = rows;
    column_data_.reset(new ColumnData());
    //column_data_->Init(allocator, CalculateSize(rows), type->is_var_length());
    column_data_->Init(allocator, CalculateSize(rows), i::IsVarLengthForType(type));
  }

  ColumnData* column_data() const { return column_data_.get(); }
  Arena* arena() const { return column_data_->arena(); }

  template <typename T>
  T* typed_data() {
    return column_data_->typed_data<T>();
  }

  template <typename T>
  const T* typed_data() const {
    return column_data_->typed_data<T>();
  }

  // get a typed buffer starting at [index]
  template <typename T>
  T* typed_offset(size_t offset) const {
      //return reinterpret_cast<T *>(column_data_->typed_data_offset(offset, type().type_log2size()));
      return reinterpret_cast<T *>(column_data_->typed_data_offset(offset, i::Log2SizeForDataType(GetType())));
  }

  template <typename T>
  T* data(size_t offset) {
    return &typed_data<T>()[offset];
  }

  template <typename T>
  const T* data(size_t offset) const {
    return &typed_data<T>()[offset];
  }

  template <zetasql::TypeKind type>
  typename TypeTraits<type>::cpp_type const * data(size_t offset) const {
    //return &typed_data<typename TypeTraits<type>::cpp_type>()[offset];
    return typed_offset<typename TypeTraits<type>::cpp_type>(offset);
  }

  template <zetasql::TypeKind type>
  typename TypeTraits<type>::cpp_type value(size_t offset) const {
    return typed_data<typename TypeTraits<type>::cpp_type>()[offset];
  }

  base::StringPiece* var_length_data() const {
    return column_data_->var_length_data(); 
  }

  size_t allocated_rows() const { 
    return allocated_rows_;
  }

  void AllocateRows(BufferAllocator* allocator, size_t rows) {
    //LOG(INFO) << "AllocateRows";
    column_data_->GrowBuffer(allocator, CalculateSize(rows));
    allocated_rows_ += rows;
    //LOG(INFO) << "AllocateRows end";
  }
 
  std::string Name() const override;

  std::string FullName() const override;

  const zetasql::Type* GetType() const override;

  bool IsPseudoColumn() const override { 
    return false; 
  }

  bool IsWritableColumn() const override { 
    return true; 
  }

  bool Deserialize(zetasql::TypeFactory* factory, const storage_proto::Column& column);

private:

  size_t CalculateSize(size_t rows) {
    //LOG(INFO) << "int size: " << schema().type_size() << " rows: " << rows << " total = " << schema().type_size() * rows; 
    return i::SizeForDataType(GetType()) * rows;
  }

  std::string name_;

  const zetasql::Type* type_;

  std::unique_ptr<ColumnData> column_data_;

  size_t allocated_rows_;

  DISALLOW_COPY_AND_ASSIGN(DataColumn);  
};

}

#endif