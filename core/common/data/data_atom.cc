// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/common/data/data_atom.h"

#include "base/strings/string_number_conversions.h"

namespace common {

DataAtom::DataAtom(DataContext* context, DataAtomType type): context_(context), type_(type) {

}

DataAtom::DataAtom(DataContext* context): context_(context), type_(kNULL_ATOM) {

}

std::string DataAtom::ToString() const { 
  return std::string(); 
}

std::string DataAtom::type_string() const {
  switch (type_) {
    case kNULL_ATOM:
      return "null";
    case kBOOL_ATOM:
      return "bool";
    case kINT_ATOM:
      return "int";
    case kUINT_ATOM:
      return "uint";
    case kFLOAT_ATOM:
      return "float";
    case kDOUBLE_ATOM:
      return "double";
    case kUINT32_ATOM:
      return "uint32";
    case kUINT64_ATOM:
      return "uint64";
    case kINT32_ATOM:
      return "int32";
    case kINT64_ATOM:
      return "int64";
    case kDATETIME_ATOM:
      return "datetime";
    case kDATE_ATOM:
      return "date";
    case kBINARY_ATOM:
      return "binary";
    case kSTRING_ATOM:
      return "string";
    case kUUID_ATOM:
      return "uuid";
    case kCONTROL_ATOM:
      return "control";
    case kCALL_ATOM:
      return "call";
    case kARRAY_ATOM:
      return "array";
    case kOBJECT_ATOM:
      return "object";
    case kTABLE_ATOM:
      return "table";
  }
  return base::IntToString(type_);
}

//DataAtom::~DataAtom() {

//}

//DataBool::DataBool(): SimpleAtom<BOOL>(kBOOL_ATOM) {

//}

//DataBool::~DataBool() {

//}

//CallAtom::CallAtom(DataContext* context): DataAtom(context, kCALL_ATOM) {

//}

//CallAtom::~CallAtom() {

//}

// template <int A> 
// DataArray<A>::DataArray(BufferAllocator* allocator, DataType data_type, size_t count): 
//   DataAtom(Type::kARRAY),
//   allocator_(allocator),
//   array_data_(new ColumnData()),
//   allocated_size_(count),
//   data_type_(data_type),
//   data_type_size_(i::SizeForDataType(data_type)),
//   type_log2size_(i::Log2SizeForDataType(data_type)),
//   is_var_lenght_(i::IsVarLengthForDataType(data_type)) {
//    array_data_->Init(allocator_, data_type_size_ * allocated_size_, is_var_lenght_);
// }

// template <int A>
// DataArray<A>::~DataArray() {

// }

// template <int A>
// void DataArray<A>::Grow(size_t size) {
//   array_data_->GrowBuffer(allocator_, data_type_size_ * size);
//   allocated_size_ += size;
// }

std::string UUIDAtom::ToString() const {
  return uuid().to_string();
}

ArrayAtom::ArrayAtom(DataContext* context, DataType data_type, size_t count):
    DataAtom(context, kARRAY_ATOM),
    //allocator_(allocator),
    array_data_(new ColumnData()),
    allocated_size_(count),
    data_type_(data_type),
    data_type_size_(i::SizeForDataType(data_type)),
    type_log2size_(i::Log2SizeForDataType(data_type)),
    is_var_lenght_(i::IsVarLengthForDataType(data_type)) {
      array_data_->Init(context->allocator(), data_type_size_ * allocated_size_, is_var_lenght_);
 }
  
ArrayAtom::~ArrayAtom() {}

ObjectAtom::ObjectAtom(DataContext* context, TableSchema* schema): 
  DataAtom(context, kOBJECT_ATOM),
  schema_(schema), 
  cols_(new ColumnData[schema->count()]){

}

ObjectAtom::~ObjectAtom() {}

ObjectAtomBuilder::ObjectAtomBuilder() {

}

ObjectAtomBuilder::~ObjectAtomBuilder() {

}

void ObjectAtomBuilder::Add(const std::string& key, DataAtom* value) {
  
}

void ObjectAtomBuilder::Delete(const std::string& key) {
  
}

std::unique_ptr<ObjectAtom> ObjectAtomBuilder::Build() {
  return std::unique_ptr<ObjectAtom>();
}

ArrayAtomBuilder::ArrayAtomBuilder() {

}

ArrayAtomBuilder::~ArrayAtomBuilder() {

}

void ArrayAtomBuilder::Add(DataAtom* value) {

}

void ArrayAtomBuilder::Insert(size_t offset, DataAtom* value) {

}

void ArrayAtomBuilder::Delete(size_t offset) {

}

//std::unique_ptr<DataArray> ArrayAtomBuilder::Build() {
//  return std::unique_ptr<DataArray>();
//}


}