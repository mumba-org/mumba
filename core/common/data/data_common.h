// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_COMMON_DATA_DATA_COMMON_H_
#define MUMBA_COMMON_DATA_DATA_COMMON_H_

#include <unordered_map>

#include "core/common/data/data_types.h"
#include "core/common/data/data_arena.h"
#include "core/common/data/data_memory.h"

namespace common {
class DataTableRowWriter;


namespace i {

template<int type>
inline void SetTypedValueRef(const ValueRef<type> ref, DataTableRowWriter* writer);

template<>
inline void SetTypedValueRef<UNDEF>(const ValueRef<UNDEF> ref, DataTableRowWriter* writer) {
    // Does nothing.
}

inline int Log2Floor(uint32_t n) {
  return n == 0 ? -1 : 31 ^ __builtin_clz(n);
}

// TODO: this should be calculated only once, and at compile time
inline bool IsVarLengthForDataType(DataType type) {
  switch (type) {
    case DataType::BOOL:
    case DataType::INT:
    case DataType::UINT:
    case DataType::UINT32:
    case DataType::UINT64:
    case DataType::INT32:
    case DataType::INT64:
    case DataType::FLOAT:
    case DataType::DOUBLE:
    case DataType::DATETIME:
    case DataType::DATE:
      return false;
      break;
    case DataType::BINARY:
    case DataType::STRING:
    case DataType::UUID:
      return true;
      break;
    case DataType::UNDEF:  
    default:
      NOTREACHED();
  }
  return false;
}


inline bool IsIntegerForDataType(DataType type) {
  switch (type) {
    case DataType::BOOL:
    case DataType::FLOAT:
    case DataType::DOUBLE:
    case DataType::BINARY:
    case DataType::STRING:
    case DataType::UUID:
      return false;
      break;
    case DataType::INT:
    case DataType::UINT:
    case DataType::UINT32:
    case DataType::UINT64:
    case DataType::INT32:
    case DataType::INT64:
    case DataType::DATETIME:
    case DataType::DATE:
      return true;
      break;
    case DataType::UNDEF:  
    default:
      NOTREACHED();
  }
  return 0;
}

inline bool IsFloatingPointForDataType(DataType type) {
  switch (type) {
    case DataType::BOOL:
    case DataType::INT:
    case DataType::UINT:
    case DataType::UINT32:
    case DataType::UINT64:
    case DataType::INT32:
    case DataType::INT64:
    case DataType::DATETIME:
    case DataType::DATE:
    case DataType::BINARY:
    case DataType::STRING:
    case DataType::UUID:
      return false;
      break;
    case DataType::FLOAT:
    case DataType::DOUBLE:  
      return true;
      break;
    case DataType::UNDEF:  
    default:
      NOTREACHED();
  }
  return 0;
}


// TODO: this should be calculated only once, and at compile time
inline size_t SizeForDataType(DataType type) {
  switch (type) {
    case DataType::BOOL:
     return sizeof(bool);
     break;
    case DataType::INT:
     return sizeof(int);
     break;
    case DataType::UINT:
     return sizeof(unsigned int);
     break;
    case DataType::UINT32:
     return sizeof(uint32_t);
     break;
    case DataType::UINT64:
     return sizeof(uint64_t);
     break;
    case DataType::INT32:
     return sizeof(int32_t);
     break;
    case DataType::INT64:
     return sizeof(int64_t);
     break;
    case DataType::FLOAT:
     return sizeof(float);
     break;
    case DataType::DOUBLE:
     return sizeof(double);
     break;
    case DataType::DATETIME: // TODO: CHECK THIS
     return sizeof(int64_t);
     break;
    case DataType::DATE: // TODO: CHECK THIS
     return sizeof(int64_t);
     break; 
    case DataType::BINARY:
     return sizeof(base::StringPiece);
     break;
    case DataType::STRING:
     return sizeof(base::StringPiece);
     break;
    case DataType::UUID:
     return sizeof(base::StringPiece);
     break;
    case DataType::UNDEF: 
    default:
     NOTREACHED();
  }
  return 0;
}

//template <typename T>
//size_t SizeForDataType(T data_type) {
//  typename TypeTraits<T>::cpp_type;//(data_type);
//  return 0;
//}

// TODO: this should be calculated only once, and at compile time
//template <typename T>
inline size_t Log2SizeForDataType(DataType data_type) {
  return Log2Floor(SizeForDataType(data_type));
}

} // namespace i

// heap buffer with the typed array
// this is suppose to be immutable.. so we just alloc
// the raw buffer in the begining, and free in the end.
// nothing fancy

// TODO: if we abstract the memory backend, we may use
//       local or shared memory.. and a shared memory equivalent
//       would help a lot, if we need to pass this through IPC
class ColumnData {
public:
  ColumnData();
  ~ColumnData();

  void Init(BufferAllocator* allocator, size_t length, bool is_var_length);
  void Init(BufferAllocator* allocator, size_t length, bool is_var_length, size_t var_length_size);

  size_t length() const { return data_buffer_->size(); }

  Arena* arena() const { return arena_.get(); }

  template <typename T>
  T* typed_data() const {
    return static_cast<T*>(data_buffer_->data());
  }
  
  char* typed_data_offset(size_t offset, size_t type_size) const {
    //LOG(INFO) << "start: " << static_cast<char*>(data_buffer_->data()) << " end: " << static_cast<char*>(data_buffer_->data()) + length() << " read offset: " << static_cast<char*>(data_buffer_->data()) + (offset << type_size);
    return static_cast<char*>(data_buffer_->data()) + (offset << type_size);
  }

  // get a buffer to complex var length types (STRING, BINARY)
  base::StringPiece* var_length_data() const {
    return static_cast<base::StringPiece*>(data_buffer_->data());
  }

  void GrowBuffer(BufferAllocator* allocator, size_t len);

private:
   
  base::Lock lock_; 

  // Holds data.
  std::unique_ptr<Buffer> data_buffer_;
  // Holds variable length data. Null for other columns.
  std::unique_ptr<Arena> arena_;

  bool is_var_length_;

  DISALLOW_COPY_AND_ASSIGN(ColumnData);
};

class ColumnSchema {
public:
  ColumnSchema(const std::string& name, DataType dtype): 
    name_(name), 
    type_(dtype), 
    type_size_(i::SizeForDataType(dtype)), 
    type_log2size_(i::Log2SizeForDataType(dtype)),
    integer_(i::IsIntegerForDataType(dtype)),
    floating_point_(i::IsFloatingPointForDataType(dtype)),
    var_length_(i::IsVarLengthForDataType(dtype)) {}

  ColumnSchema(ColumnSchema&& other): 
    name_(std::move(other.name_)), 
    type_(std::move(other.type_)),
    type_size_(std::move(other.type_size_)),
    type_log2size_(std::move(other.type_log2size_)),
    integer_(std::move(other.integer_)),
    floating_point_(std::move(other.floating_point_)),
    var_length_(std::move(other.var_length_)) {
  }

  const std::string& name() const { return name_; }
  DataType type() const { return type_; }
  size_t type_size() const { return type_size_; }
  size_t type_log2size() const { return type_log2size_; }
  
  bool is_integer() const { return integer_; }
  bool is_floating_point() const { return floating_point_; }
  bool is_var_length() const { return var_length_; }

private:
  
  std::string name_;
  
  DataType type_;

  size_t type_size_;

  size_t type_log2size_;

  bool integer_;
  bool floating_point_;
  bool var_length_;
  
  DISALLOW_COPY_AND_ASSIGN(ColumnSchema);
};

class TableSchema {
public:
  TableSchema();
  ~TableSchema();

  void Add(ColumnSchema* schema) {
    schemas_.push_back(schema);
    pos_.emplace(std::make_pair(schema->name(), cur_pos_));
    cur_pos_++;
  }

  const ColumnSchema* Get(size_t index) const {
    return schemas_[index];
  }

  const ColumnSchema* Get(const std::string& name) const {
    for (auto it = schemas_.begin(); it != schemas_.end(); ++it) {
      if (name == (*it)->name())
        return *it;
    }
    return nullptr;
  }

  size_t GetOffset(const std::string& name) const {
    auto it = pos_.find(name);
    if (it != pos_.end())
      return it->second;
    return 0;
  }

  // number of column schemas
  size_t count() const { return schemas_.size(); }

private:
  
  std::vector<ColumnSchema *> schemas_;

  std::unordered_map<std::string, size_t> pos_;

  size_t cur_pos_;

  DISALLOW_COPY_AND_ASSIGN(TableSchema);  
};

}

#endif