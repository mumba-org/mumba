// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_STORAGE_DATA_COMMON_H_
#define MUMBA_STORAGE_DATA_COMMON_H_

#include <unordered_map>

#include "storage/data_types.h"
#include "storage/db/arena.h"
#include "storage/db/memory.h"
#include "storage/proto/storage.pb.h"

namespace storage {

const size_t kALLOCATED_ROWS_OFFSET = 20;

class BlockRowWriter;


namespace i {

template<int type>
inline void SetTypedValueRef(const ValueRef<type> ref, BlockRowWriter* writer);

template<>
inline void SetTypedValueRef<zetasql::TYPE_UNKNOWN>(const ValueRef<zetasql::TYPE_UNKNOWN> ref, BlockRowWriter* writer) {
    // Does nothing.
}

inline int Log2Floor(uint32_t n) {
  return n == 0 ? -1 : 31 ^ __builtin_clz(n);
}

// TODO: this should be calculated only once, and at compile time
inline bool IsVarLengthForType(const zetasql::Type* type) {
  switch (type->kind()) {
    case zetasql::TYPE_BOOL:
    case zetasql::TYPE_UINT32:
    case zetasql::TYPE_UINT64:
    case zetasql::TYPE_INT32:
    case zetasql::TYPE_INT64:
    case zetasql::TYPE_FLOAT:
    case zetasql::TYPE_DOUBLE:
    case zetasql::TYPE_DATETIME:
    case zetasql::TYPE_DATE:
    case zetasql::TYPE_TIME:
    case zetasql::TYPE_TIMESTAMP:
    case zetasql::TYPE_NUMERIC:
    case zetasql::TYPE_GEOGRAPHY:
      return false;
      break;
    case zetasql::TYPE_BYTES:
    case zetasql::TYPE_STRING:
    case zetasql::TYPE_ENUM:
    case zetasql::TYPE_ARRAY:
    case zetasql::TYPE_STRUCT:
    case zetasql::TYPE_PROTO:
      return true;
      break;
    default:
      NOTREACHED();
  }
  return false;
}


inline bool IsIntegerForDataType(const zetasql::Type* type) {
  switch (type->kind()) {
    case zetasql::TYPE_BOOL:
    case zetasql::TYPE_FLOAT:
    case zetasql::TYPE_DOUBLE:
    case zetasql::TYPE_NUMERIC:
    case zetasql::TYPE_GEOGRAPHY:
    case zetasql::TYPE_BYTES:
    case zetasql::TYPE_STRING:
    case zetasql::TYPE_ARRAY:
    case zetasql::TYPE_STRUCT:
    case zetasql::TYPE_PROTO:
      return false;
      break;
    case zetasql::TYPE_UINT32:
    case zetasql::TYPE_UINT64:
    case zetasql::TYPE_INT32:
    case zetasql::TYPE_INT64:
    case zetasql::TYPE_DATETIME:
    case zetasql::TYPE_DATE:
    case zetasql::TYPE_TIMESTAMP:
    case zetasql::TYPE_TIME:
    case zetasql::TYPE_ENUM:
      return true;
      break;
    case zetasql::TYPE_UNKNOWN:  
    default:
      NOTREACHED();
  }
  return 0;
}

inline bool IsFloatingPointForDataType(const zetasql::Type* type) {
  switch (type->kind()) {
    case zetasql::TYPE_BOOL:
    case zetasql::TYPE_BYTES:
    case zetasql::TYPE_STRING:
    case zetasql::TYPE_ARRAY:
    case zetasql::TYPE_STRUCT:
    case zetasql::TYPE_PROTO:
    case zetasql::TYPE_UINT32:
    case zetasql::TYPE_UINT64:
    case zetasql::TYPE_INT32:
    case zetasql::TYPE_INT64:
    case zetasql::TYPE_DATETIME:
    case zetasql::TYPE_DATE:
    case zetasql::TYPE_TIMESTAMP:
    case zetasql::TYPE_TIME:
    case zetasql::TYPE_ENUM:
      return false;
      break;
    case zetasql::TYPE_FLOAT:
    case zetasql::TYPE_DOUBLE:
    case zetasql::TYPE_NUMERIC:
    case zetasql::TYPE_GEOGRAPHY:
      return true;
      break;
    case zetasql::TYPE_UNKNOWN:  
    default:
      NOTREACHED();
  }
  return 0;
}



// TODO: this should be calculated only once, and at compile time
inline size_t SizeForDataType(const zetasql::Type* type) {
  switch (type->kind()) {
    case zetasql::TYPE_BOOL:
     return sizeof(bool);
     break;
    case zetasql::TYPE_ENUM: // TODO: CHECK THIS
     return sizeof(uint32_t);
     break;
    case zetasql::TYPE_UINT32:
     return sizeof(uint32_t);
     break;
    case zetasql::TYPE_UINT64:
     return sizeof(uint64_t);
     break;
    case zetasql::TYPE_INT32:
     return sizeof(int32_t);
     break;
    case zetasql::TYPE_INT64:
     return sizeof(int64_t);
     break;
    case zetasql::TYPE_FLOAT:
     return sizeof(float);
     break;
    case zetasql::TYPE_DOUBLE:
     return sizeof(double);
     break; 
    case zetasql::TYPE_NUMERIC:
     return sizeof(double);
     break;
    case zetasql::TYPE_GEOGRAPHY: // TODO: CHECK THIS
     return sizeof(double);
     break;
    case zetasql::TYPE_DATETIME: // TODO: CHECK THIS
     return sizeof(int64_t);
     break;
    case zetasql::TYPE_DATE: // TODO: CHECK THIS
     return sizeof(int32_t);
     break;
    case zetasql::TYPE_TIME: // TODO: CHECK THIS
     return sizeof(int64_t);
     break;
    case zetasql::TYPE_TIMESTAMP: // TODO: CHECK THIS
     return sizeof(int64_t);
     break; 
    case zetasql::TYPE_BYTES:
     return sizeof(base::StringPiece);
     break;
    case zetasql::TYPE_STRING:
     return sizeof(base::StringPiece);
     break;
    case zetasql::TYPE_ARRAY:
     return sizeof(base::StringPiece);
     break;
    case zetasql::TYPE_STRUCT:
     return sizeof(base::StringPiece);
     break;
    case zetasql::TYPE_PROTO:
     return sizeof(base::StringPiece);
     break;
    case zetasql::TYPE_UNKNOWN: 
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
inline size_t Log2SizeForDataType(const zetasql::Type* type) {
  return Log2Floor(SizeForDataType(type));
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
    ////LOG(INFO) << "start: " << static_cast<char*>(data_buffer_->data()) << " end: " << static_cast<char*>(data_buffer_->data()) + length() << " read offset: " << static_cast<char*>(data_buffer_->data()) + (offset << type_size);
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

//class ColumnSchema {
// public:
//   ColumnSchema(const std::string& name, DataType dtype): 
//     name_(name), 
//     type_(dtype), 
//     type_size_(i::SizeForDataType(dtype)), 
//     type_log2size_(i::Log2SizeForDataType(dtype)),
//     integer_(i::IsIntegerForDataType(dtype)),
//     floating_point_(i::IsFloatingPointForDataType(dtype)),
//     var_length_(i::IsVarLengthForDataType(dtype)) {}

//   ColumnSchema(ColumnSchema&& other): 
//     name_(std::move(other.name_)), 
//     type_(std::move(other.type_)),
//     type_size_(std::move(other.type_size_)),
//     type_log2size_(std::move(other.type_log2size_)),
//     integer_(std::move(other.integer_)),
//     floating_point_(std::move(other.floating_point_)),
//     var_length_(std::move(other.var_length_)) {
//   }

//   const std::string& name() const { return name_; }
//   DataType type() const { return type_; }
//   size_t type_size() const { return type_size_; }
//   size_t type_log2size() const { return type_log2size_; }
  
//   bool is_integer() const { return integer_; }
//   bool is_floating_point() const { return floating_point_; }
//   bool is_var_length() const { return var_length_; }

// private:
  
//   std::string name_;
  
//   DataType type_;

//   size_t type_size_;

//   size_t type_log2size_;

//   bool integer_;
//   bool floating_point_;
//   bool var_length_;
  
//   DISALLOW_COPY_AND_ASSIGN(ColumnSchema);
// };

class Schema {
public:
  Schema();
  ~Schema();

  //void Add(const zetasql::Type* type) {
  //  types_.push_back(type);
  //  pos_.emplace(std::make_pair(type->ShortTypeName(zetasql::PRODUCT_INTERNAL), cur_pos_));
  //  cur_pos_++;
  //}

  const zetasql::Type* Get(size_t index) const {
    return types_[index];
  }
  
  std::string GetName(size_t index) const {
    for (auto it = pos_.begin(); it != pos_.end(); ++it) {
      if (it->second == index) {
        return it->first;
      }
    }
    return std::string();
  }

  const zetasql::Type* Get(const std::string& name) const {
    for (auto it = types_.begin(); it != types_.end(); ++it) {
      if (name == (*it)->ShortTypeName(zetasql::PRODUCT_INTERNAL))
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
  size_t count() const { return types_.size(); }

  bool Deserialize(zetasql::TypeFactory* factory, const storage_proto::Table& table);

  void AddColumn(const std::string& name, const zetasql::Type *type);

private:
  
  std::vector<const zetasql::Type *> types_;

  std::unordered_map<std::string, size_t> pos_;

  size_t cur_pos_;

  DISALLOW_COPY_AND_ASSIGN(Schema);  
};

}

#endif