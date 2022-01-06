// Copyright 2017 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_STORAGE_DATA_TYPES_H_
#define MUMBA_STORAGE_DATA_TYPES_H_

#include <stddef.h>
#include <type_traits>

#include "base/macros.h"
#include "base/strings/string_piece.h"
#include "storage/db/arena.h"
#include "third_party/zetasql/public/type.h"

namespace storage {

struct BasicNumericTypeTraits {
  static const bool is_variable_length = false;
  static const bool is_numeric = true;
  static const bool is_unsigned = false;
};

struct BasicIntegerTypeTraits : public BasicNumericTypeTraits {
  static const bool is_integer = true;
  static const bool is_floating_point = false;
};

struct BasicFloatingPointTypeTraits : public BasicNumericTypeTraits {
  static const bool is_integer = false;
  static const bool is_floating_point = true;
};

struct BasicVariableLengthTypeTraits {
  typedef base::StringPiece cpp_type;
  typedef std::string hold_type;
  static const bool is_variable_length = true;
  static const bool is_numeric = false;
  static const bool is_integer = false;
  static const bool is_floating_point = false;
  static hold_type CppTypeToHoldType(const cpp_type& data) {
    return data.as_string();
  }
  // Note that this reference is critical since the created StringPiece points
  // to that data.
  static cpp_type HoldTypeToCppType(const hold_type& data) {
    return base::StringPiece(data);
  }
};

template<zetasql::TypeKind datatype> struct BasicTypeTraits {};

// Specializations.

template<> struct BasicTypeTraits<zetasql::TYPE_INT32> : public BasicIntegerTypeTraits {
  typedef int32_t cpp_type;
  typedef int32_t hold_type;
 
  static hold_type CppTypeToHoldType(cpp_type data) {
    return data;
  }
  static cpp_type HoldTypeToCppType(hold_type data) {
    return data;
  }
};

template<> struct BasicTypeTraits<zetasql::TYPE_INT64> : public BasicIntegerTypeTraits {
  typedef int64_t cpp_type;
  typedef int64_t hold_type;
 
  static hold_type CppTypeToHoldType(cpp_type data) {
    return data;
  }
  static cpp_type HoldTypeToCppType(hold_type data) {
    return data;
  }
};

template<> struct BasicTypeTraits<zetasql::TYPE_UINT32> : public BasicIntegerTypeTraits {
  typedef uint32_t cpp_type;
  typedef uint32_t hold_type;
  static const bool is_unsigned = true;
 
  static hold_type CppTypeToHoldType(cpp_type data) {
    return data;
  }
  static cpp_type HoldTypeToCppType(hold_type data) {
    return data;
  }
};

template<> struct BasicTypeTraits<zetasql::TYPE_UINT64> : public BasicIntegerTypeTraits {
  typedef uint64_t cpp_type;
  typedef uint64_t hold_type;
  static const bool is_unsigned = true;
 
  static hold_type CppTypeToHoldType(cpp_type data) {
    return data;
  }
  static cpp_type HoldTypeToCppType(hold_type data) {
    return data;
  }
};

template<> struct BasicTypeTraits<zetasql::TYPE_FLOAT> : public BasicFloatingPointTypeTraits {
  typedef float cpp_type;
  typedef float hold_type;
 
  static hold_type CppTypeToHoldType(cpp_type data) {
    return data;
  }
  static cpp_type HoldTypeToCppType(hold_type data) {
    return data;
  }
};

template<> struct BasicTypeTraits<zetasql::TYPE_DOUBLE>
    : public BasicFloatingPointTypeTraits {
  typedef double cpp_type;
  typedef double hold_type;
  
  static hold_type CppTypeToHoldType(cpp_type data) {
    return data;
  }
  static cpp_type HoldTypeToCppType(hold_type data) {
    return data;
  }
};

template<> struct BasicTypeTraits<zetasql::TYPE_NUMERIC>
    : public BasicFloatingPointTypeTraits {
  typedef double cpp_type;
  typedef double hold_type;
  
  static hold_type CppTypeToHoldType(cpp_type data) {
    return data;
  }
  static cpp_type HoldTypeToCppType(hold_type data) {
    return data;
  }
};


template<> struct BasicTypeTraits<zetasql::TYPE_GEOGRAPHY>
    : public BasicFloatingPointTypeTraits {
  typedef double cpp_type;
  typedef double hold_type;
  
  static hold_type CppTypeToHoldType(cpp_type data) {
    return data;
  }
  static cpp_type HoldTypeToCppType(hold_type data) {
    return data;
  }
};

template<> struct BasicTypeTraits<zetasql::TYPE_BOOL> {
  typedef bool cpp_type;
  typedef bool hold_type;
  static const bool is_variable_length = false;
  static const bool is_numeric = false;
  static const bool is_integer = false;
  static const bool is_floating_point = false;
  static hold_type CppTypeToHoldType(cpp_type data) {
    return data;
  }
  static cpp_type HoldTypeToCppType(hold_type data) {
    return data;
  }
};

template<> struct BasicTypeTraits<zetasql::TYPE_STRING>
    : public BasicVariableLengthTypeTraits {
 
};  

template<> struct BasicTypeTraits<zetasql::TYPE_BYTES>
    : public BasicVariableLengthTypeTraits {
 
};

template<> struct BasicTypeTraits<zetasql::TYPE_ARRAY>
    : public BasicVariableLengthTypeTraits {
 
};

template<> struct BasicTypeTraits<zetasql::TYPE_STRUCT>
    : public BasicVariableLengthTypeTraits {
 
};

template<> struct BasicTypeTraits<zetasql::TYPE_PROTO>
    : public BasicVariableLengthTypeTraits {
 
};

template<> struct BasicTypeTraits<zetasql::TYPE_DATETIME> {
  typedef int64_t cpp_type;
  typedef int64_t hold_type;
  static const bool is_variable_length = false;
  static const bool is_numeric = false;
  static const bool is_integer = false;
  static const bool is_floating_point = false;
  static hold_type CppTypeToHoldType(cpp_type data) {
    return data;
  }
  static cpp_type HoldTypeToCppType(hold_type data) {
    return data;
  }
};

template<> struct BasicTypeTraits<zetasql::TYPE_DATE> {
  typedef int32_t cpp_type;
  typedef int32_t hold_type;
  static const bool is_variable_length = false;
  static const bool is_numeric = false;
  static const bool is_integer = false;
  static const bool is_floating_point = false;
  static hold_type CppTypeToHoldType(cpp_type data) {
    return data;
  }
  static cpp_type HoldTypeToCppType(hold_type data) {
    return data;
  }
};

template<> struct BasicTypeTraits<zetasql::TYPE_TIMESTAMP> {
  typedef int32_t cpp_type;
  typedef int32_t hold_type;
  static const bool is_variable_length = false;
  static const bool is_numeric = false;
  static const bool is_integer = false; // ?
  static const bool is_floating_point = false;
  static hold_type CppTypeToHoldType(cpp_type data) {
    return data;
  }
  static cpp_type HoldTypeToCppType(hold_type data) {
    return data;
  }
};

template<> struct BasicTypeTraits<zetasql::TYPE_TIME> {
  typedef int32_t cpp_type;
  typedef int32_t hold_type;
  static const bool is_variable_length = false;
  static const bool is_numeric = false;
  static const bool is_integer = false;
  static const bool is_floating_point = false;
  static hold_type CppTypeToHoldType(cpp_type data) {
    return data;
  }
  static cpp_type HoldTypeToCppType(hold_type data) {
    return data;
  }
};

// The following specialized templates enable compile-time inference of type
// properties (size, name, C++ type, etc.)
template<zetasql::TypeKind datatype> struct TypeTraits
    : public BasicTypeTraits<datatype> {
  // hold_type is the same as cpp_type for non-variable length types. If the
  // type is variable length, the cpp_type does not own the contents, while
  // hold_type does.
  typedef typename BasicTypeTraits<datatype>::cpp_type cpp_type;
  typedef typename BasicTypeTraits<datatype>::hold_type hold_type;
  static const zetasql::TypeKind type = datatype;
  static const size_t size = sizeof(cpp_type);
  //static const google::protobuf::EnumValueDescriptor* descriptor() {
  //  return DataType_descriptor()->FindValueByNumber(datatype);
  //}
  //static const char* name() {
  //  return descriptor()->name().c_str();
  //}
  static hold_type CppTypeToHoldType(const cpp_type& data) {
    return BasicTypeTraits<datatype>::CppTypeToHoldType(data);
  }
  // Note that we need to pass reference since StringPiece needs to original
  // string and not the copied string.
  static cpp_type HoldTypeToCppType(const hold_type& data) {
    return BasicTypeTraits<datatype>::HoldTypeToCppType(data);
  }
};

// Lets to obtain the DataType enumeration that corresponds to the specified
// C++ type.
template<typename T> struct InverseTypeTraits {};

template<> struct InverseTypeTraits<int32_t> {
  static const zetasql::TypeKind dataset_type = zetasql::TYPE_INT32;
};

template<> struct InverseTypeTraits<uint32_t> {
  static const zetasql::TypeKind dataset_type = zetasql::TYPE_UINT32;
};

template<> struct InverseTypeTraits<int64_t> {
  static const zetasql::TypeKind dataset_type = zetasql::TYPE_INT64;
};

template<> struct InverseTypeTraits<uint64_t> {
  static const zetasql::TypeKind dataset_type = zetasql::TYPE_UINT64;
};

template<> struct InverseTypeTraits<float> {
  static const zetasql::TypeKind dataset_type = zetasql::TYPE_FLOAT;
};

template<> struct InverseTypeTraits<double> {
  static const zetasql::TypeKind dataset_type = zetasql::TYPE_DOUBLE;
};

template<> struct InverseTypeTraits<bool> {
  static const zetasql::TypeKind dataset_type = zetasql::TYPE_BOOL;
};

template<> struct InverseTypeTraits<base::StringPiece> {
  static const zetasql::TypeKind dataset_type = zetasql::TYPE_BYTES;
};

// Global constant that represents a NULL value for each type.
const struct __Null {} __ = {};

template<int type>
class ValueRef {
 public:
  typedef typename TypeTraits<static_cast<zetasql::TypeKind>(type)>::cpp_type cpp_type;

  ValueRef(const cpp_type& value) : value_(&value) {}                  
  ValueRef(const __Null null) : value_(NULL) {}                        
  bool is_null() const { return value_ == NULL; }
  const cpp_type& value() const {
    DCHECK(!is_null());
    return *value_;
  }
 private:
  const cpp_type* value_;
};

template<>
class ValueRef<zetasql::TYPE_STRING> {
 public:
  ValueRef(const base::StringPiece& value)                                   
      : value_(value),
        is_null_(false) {}
  ValueRef(const char* value)                                          
      : value_(value),
        is_null_(value == NULL) {}
  ValueRef(const std::string& value)                                        
      : value_(value),
        is_null_(false) {}
  ValueRef(const __Null null)                                          
      : value_(), is_null_(true) {}

  bool is_null() const { return is_null_; }
  const base::StringPiece& value() const {
    DCHECK(!is_null());
    return value_;
  }
 private:
  base::StringPiece value_;
  bool is_null_;
};

template<>
class ValueRef<zetasql::TYPE_BYTES> : public ValueRef<zetasql::TYPE_STRING> {
 public:
  ValueRef(const base::StringPiece& value) : ValueRef<zetasql::TYPE_STRING>(value) {}      
  ValueRef(const char* value) : ValueRef<zetasql::TYPE_STRING>(value) {}             
  ValueRef(const std::string& value) : ValueRef<zetasql::TYPE_STRING>(value)  {}          
  ValueRef(const __Null null) : ValueRef<zetasql::TYPE_STRING>(null) {}              
};

template<>
class ValueRef<zetasql::TYPE_ARRAY> : public ValueRef<zetasql::TYPE_STRING> {
 public:
  ValueRef(const base::StringPiece& value) : ValueRef<zetasql::TYPE_STRING>(value) {}      
  ValueRef(const char* value) : ValueRef<zetasql::TYPE_STRING>(value) {}             
  ValueRef(const std::string& value) : ValueRef<zetasql::TYPE_STRING>(value)  {}          
  ValueRef(const __Null null) : ValueRef<zetasql::TYPE_STRING>(null) {}              
};

template<>
class ValueRef<zetasql::TYPE_STRUCT> : public ValueRef<zetasql::TYPE_STRING> {
 public:
  ValueRef(const base::StringPiece& value) : ValueRef<zetasql::TYPE_STRING>(value) {}      
  ValueRef(const char* value) : ValueRef<zetasql::TYPE_STRING>(value) {}             
  ValueRef(const std::string& value) : ValueRef<zetasql::TYPE_STRING>(value)  {}          
  ValueRef(const __Null null) : ValueRef<zetasql::TYPE_STRING>(null) {}              
};

template<>
class ValueRef<zetasql::TYPE_PROTO> : public ValueRef<zetasql::TYPE_STRING> {
 public:
  ValueRef(const base::StringPiece& value) : ValueRef<zetasql::TYPE_STRING>(value) {}      
  ValueRef(const char* value) : ValueRef<zetasql::TYPE_STRING>(value) {}             
  ValueRef(const std::string& value) : ValueRef<zetasql::TYPE_STRING>(value)  {}          
  ValueRef(const __Null null) : ValueRef<zetasql::TYPE_STRING>(null) {}              
};

//template<> struct ValueRef<UNDEF> {};

template<>
class ValueRef<zetasql::TYPE_UNKNOWN> {
public:
  bool is_null() const { return true; }
  const __Null value() const { return {}; }
};

template<zetasql::TypeKind type>
struct ShallowDatumCopy {
  void operator()(const typename TypeTraits<type>::cpp_type& input, typename TypeTraits<type>::cpp_type* output) {
    DCHECK(output);// << "The output must not be NULL";
    //LOG(INFO) << "setando: " << input;
    *output = input;
  }
};

template<zetasql::TypeKind type,
         bool deep_copy = TypeTraits<type>::is_variable_length,
         bool is_variable_length = TypeTraits<type>::is_variable_length>
struct DatumCopy {
  bool operator()(const typename TypeTraits<type>::cpp_type& input,
                  typename TypeTraits<type>::cpp_type* const output,
                  Arena* const arena) {
    ShallowDatumCopy<type> copy;
    copy(input, output);
    return true;
  }
};

// Partial specialization for variable-length types, copying of which involves
// writing a copy of the variable-length data buffer into output column's arena.
// Only used if type is both variable-length and deep copying is requested.
template <zetasql::TypeKind type>
struct DatumCopy<type, true, true> {
  // Can return false only if data being copied is of
  // variable-length type, deep copying is requested, and the destination arena
  // can't accommodate a copy of a variable-length data buffer.
  bool operator()(const base::StringPiece& input,
                  base::StringPiece* const output,
                  Arena* const arena) {
    DCHECK(output);// << "The output must not be NULL";
    //LOG(INFO) << "setando : '" << input << "'";
    // For variable-length types cpp_type is StringPiece.
    //LOG(INFO) << "allocando " << input.size() << " bytes na arena\narena size: " << arena->memory_footprint();
    const char* copy = arena->AddStringPieceContent(input);
    //LOG(INFO) << "arena deep copy : '" << copy << "'";
    if (copy == NULL) {
      DLOG(WARNING) << "Deep copy failed, size of input is " << input.size();
      return false;
    } else {
      //LOG(INFO) << "setando: " << copy << " len: " << input.size();
      output->set(copy, input.size());
      return true;
    }
  }
};

}

#endif