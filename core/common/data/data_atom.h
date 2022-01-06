// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_COMMON_DATA_DATA_ATOM_H_
#define MUMBA_COMMON_DATA_DATA_ATOM_H_

#include <map>

#include "base/macros.h"
#include <memory>
#include "base/strings/string_piece.h"
#include "base/strings/string_number_conversions.h"
#include "core/common/data/data_common.h"
#include "base/uuid.h"

namespace common {
class DataAtom;

namespace {
  const size_t kALLOCATED_SLOTS_FACTOR = 10;  
}

class DataContext {
public:
  virtual ~DataContext() {}
  virtual BufferAllocator* allocator() = 0;
  virtual std::unique_ptr<DataAtom> NewArray(DataType data_type) = 0;
  virtual std::unique_ptr<DataAtom> NewObject() = 0;
  virtual std::unique_ptr<DataAtom> NewBool(bool value) = 0;
  virtual std::unique_ptr<DataAtom> NewBinary(base::StringPiece data) = 0;
  virtual std::unique_ptr<DataAtom> NewString(base::StringPiece data) = 0;
};

class DataAtom {
public:
  virtual ~DataAtom() {}

  DataAtomType type() const { return type_; }

  std::string type_string() const;

  DataContext* context() const { return context_; }

  bool is_null() const { return type_ == kNULL_ATOM;}
  bool is_bool() const { return type_ == kBOOL_ATOM;}
  bool is_int() const { return type_ == kINT_ATOM; }
  bool is_uint() const { return type_ == kUINT_ATOM; }
  bool is_uint32() const { return type_ == kUINT32_ATOM; }
  bool is_uint64() const { return type_ == kUINT64_ATOM; }
  bool is_int32() const { return type_ == kINT32_ATOM; }
  bool is_int64() const { return type_ == kINT64_ATOM; }
  bool is_datetime() const { return type_ == kDATETIME_ATOM; }
  bool is_date() const { return type_ == kDATE_ATOM; }
  bool is_float() const { return type_ == kFLOAT_ATOM; }
  bool is_double() const { return type_ == kDOUBLE_ATOM; }
  bool is_binary() const { return type_ == kBINARY_ATOM; }
  bool is_string() const { return type_ == kSTRING_ATOM; }
  bool is_uuid() const { return type_ == kUUID_ATOM; }
  bool is_call() const { return type_ == kCALL_ATOM; }
  bool is_control() const { return type_ == kCONTROL_ATOM; }
  bool is_array() const { return type_ == kARRAY_ATOM;}
  bool is_object() const { return type_ == kOBJECT_ATOM; }
  bool is_table() const { return type_ == kTABLE_ATOM; }
  
  bool is_simple() const { 
    return is_bool() || is_uint() || is_uint32() || 
     is_uint64() || is_int32() || is_int64() || 
     is_datetime() || is_date() || is_float() ||
     is_double() || is_binary() || is_string() || 
     is_uuid();
  }

  bool is_buffer() const {
    return is_binary() || is_string() || is_uuid();
  }

  virtual std::string ToString() const;

protected:
  DataAtom(DataContext* context, DataAtomType type);
  DataAtom(DataContext* context);
private:

  DataContext* context_;

  DataAtomType type_;

  DISALLOW_COPY_AND_ASSIGN(DataAtom);
};

template <int dtype>
class SimpleAtom : public DataAtom {
public:
  typedef typename TypeTraits<static_cast<DataType>(dtype)>::cpp_type cpp_type;
  
  virtual ~SimpleAtom() override {}

  DataType data_type() const { return static_cast<DataType>(dtype); }

  cpp_type get() const {
    return value_;
  }

  void set(cpp_type value) {
    value_ = value;
  }

  std::string ToString() const override {
    std::string result;

    switch(data_type()) {
      case BOOL:
        result = value_ ? "true" : "false";
        break;
      case FLOAT:
        result = base::NumberToString(static_cast<double>(value_));
        break;
      case INT:
      case UINT:
      case INT32:
      case INT64:
      case UINT32:
      case UINT64:
      case DOUBLE:
        result = base::NumberToString(value_);
        break;
      case DATETIME:
        //Time t = base::Time::FromDoubleT(static_cast<double>(value_));
        result = "[DATETIME]";
        break;
      case DATE:
        result = "[DATE]";
        break;
      case BINARY:
      case STRING:
      case UUID:
      case UNDEF:
      default:
       break;
    }
    return result;
  }

protected:
  SimpleAtom(DataContext* context): DataAtom(context, TypeTraits<static_cast<DataType>(dtype)>::atom_type) {}
  SimpleAtom(DataContext* context, cpp_type init_value): 
    DataAtom(context, TypeTraits<static_cast<DataType>(dtype)>::atom_type),
    value_(init_value) {}

private:  
  cpp_type value_; 
};

class BoolAtom : public SimpleAtom<BOOL> {
public:
  BoolAtom(DataContext* context): SimpleAtom(context, false) {}
  BoolAtom(DataContext* context, bool v): SimpleAtom(context, v) {}
  ~BoolAtom() override {}

private:

};

class IntAtom : public SimpleAtom<INT> {
public:
  IntAtom(DataContext* context): SimpleAtom(context, 0) {}
  IntAtom(DataContext* context, int v): SimpleAtom(context, v) {}
  ~IntAtom() override {}

private:

};

class UintAtom : public SimpleAtom<UINT> {
public:
  UintAtom(DataContext* context): SimpleAtom(context, 0) {}
  UintAtom(DataContext* context, unsigned v): SimpleAtom(context, v) {}
  ~UintAtom() override {}// override {}

private:

};

class Uint32Atom : public SimpleAtom<UINT32> {
public:
  Uint32Atom(DataContext* context): SimpleAtom(context, 0) {}
  Uint32Atom(DataContext* context, uint32_t v): SimpleAtom(context, v) {}
  ~Uint32Atom() override {}

private:

};

class Uint64Atom : public SimpleAtom<UINT64> {
public:
  Uint64Atom(DataContext* context): SimpleAtom(context, 0) {}
  Uint64Atom(DataContext* context, uint64_t v): SimpleAtom(context, v) {}
  ~Uint64Atom() override {}

private:

};

class Int32Atom : public SimpleAtom<INT32> {
public:
  Int32Atom(DataContext* context): SimpleAtom(context, 0) {}
  Int32Atom(DataContext* context, int32_t v): SimpleAtom(context, v) {}
  ~Int32Atom() override {}// override {}

private:

};

class Int64Atom : public SimpleAtom<INT64> {
public:
  Int64Atom(DataContext* context): SimpleAtom(context, 0) {}
  Int64Atom(DataContext* context, int64_t v): SimpleAtom(context, v) {}
  ~Int64Atom() override {}

private:

};

class DatetimeAtom : public SimpleAtom<DATETIME> {
public:
  DatetimeAtom(DataContext* context): SimpleAtom(context, 0) {}
  DatetimeAtom(DataContext* context, int64_t v): SimpleAtom(context, v) {}
  ~DatetimeAtom() override {}

private:

};

class DateAtom : public SimpleAtom<DATE> {
public:
  DateAtom(DataContext* context): SimpleAtom(context, 0) {}
  DateAtom(DataContext* context, int32_t v): SimpleAtom(context, v) {}
  ~DateAtom() override {}

private:

};

class FloatAtom : public SimpleAtom<FLOAT> {
public:
  FloatAtom(DataContext* context): SimpleAtom(context, 0.0f) {}
  FloatAtom(DataContext* context, float v): SimpleAtom(context, v) {}
  ~FloatAtom() override {}
  
private:

};

class DoubleAtom : public SimpleAtom<DOUBLE> {
public:
  DoubleAtom(DataContext* context): SimpleAtom(context, 0.0f)  {}
  DoubleAtom(DataContext* context, double v): SimpleAtom(context, v)  {}
  ~DoubleAtom() override {}
  
private:

};

template <int dtype>
class BufferAtom : public DataAtom {
public:

  typedef typename TypeTraits<static_cast<DataType>(dtype)>::cpp_type cpp_type;
  
  DataType data_type() const { return static_cast<DataType>(dtype); }

  size_t size() const { return buf_data_->length(); }

  cpp_type get() const {
    return buf_data_->typed_data<cpp_type>()[0]; 
  }

  void set(const cpp_type& value) {
    DatumCopy<static_cast<DataType>(dtype), true> copy;
    if (!copy(value, buf_data_->typed_data<cpp_type>(), buf_data_->arena())) {
      DLOG(ERROR) << "BufferAtom: error setting value";
      //return false;
    }
  }

  std::string ToString() const override {
    base::StringPiece buf = get();
    return std::string(buf.data(), buf.size());
  }

protected:

  BufferAtom(DataContext* context): 
    DataAtom(context, TypeTraits<static_cast<DataType>(dtype)>::atom_type),
    buf_data_(new ColumnData()),
    data_type_size_(i::SizeForDataType(static_cast<DataType>(dtype))),
    current_size_(data_type_size_) {

    buf_data_->Init(context->allocator(), current_size_, true, 255);
  }

  BufferAtom(DataContext* context, size_t buflen): 
    DataAtom(context, TypeTraits<static_cast<DataType>(dtype)>::atom_type),
    buf_data_(new ColumnData()),
    data_type_size_(i::SizeForDataType(static_cast<DataType>(dtype))),
    current_size_(data_type_size_ * 1) {

    buf_data_->Init(context->allocator(), current_size_, true, buflen);
  }

private:
  std::unique_ptr<ColumnData> buf_data_;
  size_t data_type_size_;
  size_t current_size_;
};

class BinaryAtom : public BufferAtom<BINARY> {
public:
  BinaryAtom(DataContext* context): BufferAtom(context) {}
  ~BinaryAtom() override {}
  
private:
  
};

class StringAtom : public BufferAtom<STRING> {
public:
  StringAtom(DataContext* context): BufferAtom(context) {}
  ~StringAtom() override {}
  
private:

};

class UUIDAtom : public BufferAtom<UUID> {
public:
  UUIDAtom(DataContext* context): BufferAtom(context, 16) {}
  ~UUIDAtom() override {}

  base::UUID uuid() const {
    base::StringPiece buf = get();
    return base::UUID(reinterpret_cast<const uint8_t *>(buf.data()));
  }

  std::string ToString() const override;
  
private:

};
// This will eventually replace 'CallInfo'
// the call result will be a Atom, Array or Object

// Also this can be very handy for RPC.. also repr a call
class CallAtom : public DataAtom {
public:
  CallAtom(DataContext* context): DataAtom(context, kCALL_ATOM) {}
  ~CallAtom() override {}

private:

};

class ControlAtom : public DataAtom {
public:
  ControlAtom(DataContext* context): DataAtom(context, kCONTROL_ATOM) {}
  ~ControlAtom() override {}

private:

};

// Its the same stuff as a Collumn in DataTable
// a set of elements with the element type
class ArrayAtom : public DataAtom {
public:
  ArrayAtom(DataContext* context, DataType data_type, size_t count);
  ~ArrayAtom() override;

  DataType data_type() const { return data_type_; }

  size_t size() const { return allocated_size_; }

  bool is_var_lenght() const {
    return is_var_lenght_;
  }

  template <DataType type>
  typename TypeTraits<type>::cpp_type get(size_t offset) const {
    return typed_data<typename TypeTraits<type>::cpp_type>()[offset];    
  }

  int32_t Int32(size_t offset) { return get<INT32>(offset); }
  int64_t Int64(size_t offset) { return get<INT64>(offset); }
  uint32_t Uint32(size_t offset) { return get<UINT32>(offset); }
  uint64_t Uint64(size_t offset) { return get<UINT64>(offset); }
  float Float(size_t offset) { return get<FLOAT>(offset); }
  double Double(size_t offset) { return get<DOUBLE>(offset); }
  bool Bool(size_t offset) { return get<BOOL>(offset); }
  int32_t Date(size_t offset) { return get<DATE>(offset); }
  int64_t Datetime(size_t offset) { return get<DATETIME>(offset); }
  base::StringPiece String(size_t offset) {
    return get<STRING>(offset);
  }
  base::StringPiece Binary(size_t offset) {
    return get<BINARY>(offset);
  }

  template <DataType type>
  void set(size_t offset, typename TypeTraits<type>::cpp_type value) {
    if(allocated_size_ <= offset) {
      // we have a alloc factor to avoid asking for heap allocation
      // for every new slot after the initial slot alloc is exausted
      // (TODO: make this number cache friendly/alligned according to the type size)
      size_t size = ((offset + 1) - allocated_size_) * kALLOCATED_SLOTS_FACTOR;
      Grow(size);
    }
    auto pos = data<typename TypeTraits<type>::cpp_type>(offset);
    *pos = value;
  }

  void SetInt32(size_t offset, int32_t value) { set<INT32>(offset, value); }
  void SetInt64(size_t offset, int64_t value) { set<INT64>(offset, value); }
  void SetUint32(size_t offset, uint32_t value) { set<UINT32>(offset, value); }
  void SetUint64(size_t offset, uint64_t value) { set<UINT64>(offset, value); }
  void SetFloat(size_t offset, float value) { set<FLOAT>(offset, value); }
  void SetDouble(size_t offset, double value) { set<DOUBLE>(offset, value); }
  void SetBool(size_t offset, bool value) { set<BOOL>(offset, value); }
  void SetDate(size_t offset, int32_t value) { set<DATE>(offset, value); }
  void SetDatetime(size_t offset, int64_t value) { set<DATETIME>(offset, value); }
  
  void SetString(size_t offset, const base::StringPiece& value) {
    set<STRING>(offset, value);
  }

  void SetBinary(size_t offset, const base::StringPiece& value) {
    set<BINARY>(offset, value);
  }

private:
  
  // private mostly because they are not memory safe to expose as api
  template <typename T>
  T* typed_data() {
    return array_data_->typed_data<T>();
  }

  template <typename T>
  const T* typed_data() const {
    return array_data_->typed_data<T>();
  }

  template <typename T>
  T* typed_offset(size_t offset) const {
    return reinterpret_cast<T *>(array_data_->typed_data_offset(offset, type_log2size_));
  }

  template <typename T>
  T* data(size_t offset) {
    return &typed_data<T>()[offset];
  }

  template <typename T>
  const T* data(size_t offset) const {
    return &typed_data<T>()[offset];
  }

  template <DataType type>
  typename TypeTraits<type>::cpp_type const * data(size_t offset) const {
    return typed_offset<typename TypeTraits<type>::cpp_type>(offset);
  }

  void Grow(size_t size) {
    array_data_->GrowBuffer(context()->allocator(), data_type_size_ * size);
    allocated_size_ += size;
  }

  //BufferAllocator* allocator_;
  std::unique_ptr<ColumnData> array_data_;
  size_t allocated_size_;
  // TODO: consider a 'TypeInfo' with those
  DataType data_type_;
  size_t data_type_size_;
  size_t type_log2size_;
  bool is_var_lenght_;
};

class ObjectAtom : public DataAtom {
public:
  ObjectAtom(DataContext* context, TableSchema* schema);
  ~ObjectAtom() override;

  const TableSchema& schema() const { return *schema_; }

  template <DataType type>
  typename TypeTraits<type>::cpp_type get(size_t offset) const {
    return typed_data<typename TypeTraits<type>::cpp_type>(offset)[0];    
  }

  template <DataType type>
  void set(size_t offset, typename TypeTraits<type>::cpp_type value) {
    // if(allocated_size_ <= offset) {
    //   // we have a alloc factor to avoid asking for heap allocation
    //   // for every new slot after the initial slot alloc is exausted
    //   // (TODO: make this number cache friendly/alligned according to the type size)
    //   size_t size = ((offset + 1) - allocated_size_) * kALLOCATED_SLOTS_FACTOR;
    //   Grow(offset, size);
    // }
    auto pos = data<typename TypeTraits<type>::cpp_type>(offset);
    *pos = value;
  }

  int32_t Int32(size_t offset) { return get<INT32>(offset); }
  int64_t Int64(size_t offset) { return get<INT64>(offset); }
  uint32_t Uint32(size_t offset) { return get<UINT32>(offset); }
  uint64_t Uint64(size_t offset) { return get<UINT64>(offset); }
  float Float(size_t offset) { return get<FLOAT>(offset); }
  double Double(size_t offset) { return get<DOUBLE>(offset); }
  bool Bool(size_t offset) { return get<BOOL>(offset); }
  int32_t Date(size_t offset) { return get<DATE>(offset); }
  int64_t Datetime(size_t offset) { return get<DATETIME>(offset); }
  base::StringPiece String(size_t offset) { return get<STRING>(offset); }
  base::StringPiece Binary(size_t offset) { return get<BINARY>(offset);}

  int32_t Int32(const std::string& name) { 
    size_t offset = schema_->GetOffset(name);
    return get<INT32>(offset); 
  }
  
  int64_t Int64(const std::string& name) {
    size_t offset = schema_->GetOffset(name);
    return get<INT64>(offset); 
  }
  
  uint32_t Uint32(const std::string& name) { 
    size_t offset = schema_->GetOffset(name);
    return get<UINT32>(offset); 
  }
  
  uint64_t Uint64(const std::string& name) {
    size_t offset = schema_->GetOffset(name);
    return get<UINT64>(offset); 
  }
  
  float Float(const std::string& name) {
    size_t offset = schema_->GetOffset(name);
    return get<FLOAT>(offset); 
  }
  
  double Double(const std::string& name) {
    size_t offset = schema_->GetOffset(name);
    return get<DOUBLE>(offset); 
  }
  
  bool Bool(const std::string& name) {
    size_t offset = schema_->GetOffset(name);
    return get<BOOL>(offset); 
  }
  
  int32_t Date(const std::string& name) {
    size_t offset = schema_->GetOffset(name);
    return get<DATE>(offset); 
  }
  
  int64_t Datetime(const std::string& name) {
    size_t offset = schema_->GetOffset(name);
    return get<DATETIME>(offset); 
  }
  
  base::StringPiece String(const std::string& name) {
    size_t offset = schema_->GetOffset(name);
    return get<STRING>(offset); 
  }
  
  base::StringPiece Binary(const std::string& name) {
    size_t offset = schema_->GetOffset(name);
    return get<BINARY>(offset);
  }

  void SetInt32(size_t offset, int32_t value) { set<INT32>(offset, value); }
  void SetInt64(size_t offset, int64_t value) { set<INT64>(offset, value); }
  void SetUint32(size_t offset, uint32_t value) { set<UINT32>(offset, value); }
  void SetUint64(size_t offset, uint64_t value) { set<UINT64>(offset, value); }
  void SetFloat(size_t offset, float value) { set<FLOAT>(offset, value); }
  void SetDouble(size_t offset, double value) { set<DOUBLE>(offset, value); }
  void SetBool(size_t offset, bool value) { set<BOOL>(offset, value); }
  void SetDate(size_t offset, int32_t value) { set<DATE>(offset, value); }
  void SetDatetime(size_t offset, int64_t value) { set<DATETIME>(offset, value); }
  void SetString(size_t offset, const base::StringPiece& value) { /*set<STRING>(offset, value);*/}
  void SetBinary(size_t offset, const base::StringPiece& value) { /*set<BINARY>(offset, value); */}

  void SetInt32(const std::string& name, int32_t value) { 
    size_t offset = schema_->GetOffset(name);
    set<INT32>(offset, value); 
  }
  void SetInt64(const std::string& name, int64_t value) { 
    size_t offset = schema_->GetOffset(name);
    set<INT64>(offset, value); 
  }
  void SetUint32(const std::string& name, uint32_t value) { 
    size_t offset = schema_->GetOffset(name);
    set<UINT32>(offset, value); 
  }
  void SetUint64(const std::string& name, uint64_t value) { 
    size_t offset = schema_->GetOffset(name);
    set<UINT64>(offset, value); 
  }
  void SetFloat(const std::string& name, float value) { 
    size_t offset = schema_->GetOffset(name);
    set<FLOAT>(offset, value); 
  }
  void SetDouble(const std::string& name, double value) { 
    size_t offset = schema_->GetOffset(name);
    set<DOUBLE>(offset, value);
  }
  void SetBool(const std::string& name, bool value) { 
    size_t offset = schema_->GetOffset(name);
    set<BOOL>(offset, value); 
  }
  void SetDate(const std::string& name, int32_t value) { 
    size_t offset = schema_->GetOffset(name);
    set<DATE>(offset, value); 
  }
  void SetDatetime(const std::string& name, int64_t value) { 
    size_t offset = schema_->GetOffset(name);
    set<DATETIME>(offset, value); 
  }
  void SetString(const std::string& name, const base::StringPiece& value) { /*set<STRING>(offset, value);*/}
  void SetBinary(const std::string& name, const base::StringPiece& value) { /*set<BINARY>(offset, value); */}

private:
  
  template <typename T>
  T* typed_data(size_t col_offset) {
    return cols_[col_offset].typed_data<T>();
  }

  template <typename T>
  const T* typed_data(size_t col_offset) const {
    return cols_[col_offset].typed_data<T>();
  }

  template <typename T>
  T* typed_offset(size_t col_offset) const {
    return reinterpret_cast<T *>(cols_[col_offset].typed_data_offset(0, i::Log2Floor(sizeof(T))));
  }

  template <typename T>
  T* data(size_t col_offset) {
    return &typed_data<T>(col_offset)[0];
  }

  template <typename T>
  const T* data(size_t col_offset) const {
    return &typed_data<T>(col_offset)[0];
  }

  template <DataType type>
  typename TypeTraits<type>::cpp_type const * data(size_t col_offset) const {
    return typed_offset<typename TypeTraits<type>::cpp_type>(col_offset);
  }

  void Grow(size_t col_offset, size_t size) {
    //cols_[col_offset]->GrowBuffer(context()->allocator(), data_type_size_ * size);
    //allocated_size_ += size;
  }

  std::unique_ptr<TableSchema> schema_;
  std::unique_ptr<ColumnData[]> cols_;
};

// for building objects
class ObjectAtomBuilder {
public:
  ObjectAtomBuilder();
  ~ObjectAtomBuilder();

  bool is_empty() const {
    //return values_.empty();
    return false;
  }

  void Add(const std::string& key, DataAtom* value);
  void Delete(const std::string& key);

  std::unique_ptr<ObjectAtom> Build();

private:

//  std::map<std::string, DataAtom> values_;

  DISALLOW_COPY_AND_ASSIGN(ObjectAtomBuilder);
};

class ArrayAtomBuilder {
public:
  ArrayAtomBuilder();
  ~ArrayAtomBuilder();

  bool is_empty() const {
    //return values_.empty();
    return false;
  }

  size_t size() const {
    //return values_.size();
    return 0;
  }

  void Add(DataAtom* value);
  void Insert(size_t offset, DataAtom* value);
  void Delete(size_t offset);

  //std::unique_ptr<DataArray> Build();

private:

 // std::vector<DataAtom> values_;

  DISALLOW_COPY_AND_ASSIGN(ArrayAtomBuilder);
};

// class DataTableBuilder {
// public:
//   DataTableBuilder();
//   ~DataTableBuilder();

// private:
//   DISALLOW_COPY_AND_ASSIGN(DataTableBuilder);
// };

}

#endif
