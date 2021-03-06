// Copyright 2017 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_COMMON_DATA_DATA_TYPES_H_
#define MUMBA_COMMON_DATA_DATA_TYPES_H_

#include <stddef.h>
#include <type_traits>

#include "base/macros.h"
#include "base/strings/string_piece.h"
#include "core/common/data/data_arena.h"

namespace common {

enum DataType {
 UNDEF = -1, 
 BOOL = 0,
 UINT = 1,
 UINT32 = 2,
 UINT64 = 3,
 INT = 4,
 INT32 = 5,
 INT64 = 6,
 FLOAT = 7,
 DOUBLE = 8,
 DATETIME = 9,
 DATE = 10,
 BINARY = 11,
 STRING = 12,
 UUID = 13
};

enum DataAtomType {
  // simple types
  kNULL_ATOM = 0,
  kBOOL_ATOM = 1,
  kINT_ATOM = 2,
  kUINT_ATOM = 3,
  kUINT32_ATOM = 4,
  kUINT64_ATOM = 5,
  kINT32_ATOM = 6,
  kINT64_ATOM = 7,
  kDATETIME_ATOM = 8,
  kDATE_ATOM = 9,
  kFLOAT_ATOM = 10,
  kDOUBLE_ATOM = 11,
  kBINARY_ATOM = 12,
  kSTRING_ATOM = 13,
  kUUID_ATOM = 14,
  // complex/composite types
  kCONTROL_ATOM = 15, // control command (put, get, query, launch, etc..)
  kCALL_ATOM = 16,
  kARRAY_ATOM = 18,
  kOBJECT_ATOM = 19,
  kTABLE_ATOM = 20
};



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

template<DataType datatype> struct BasicTypeTraits {};

// Specializations.

template<> struct BasicTypeTraits<DataType::INT> : public BasicIntegerTypeTraits {
  typedef int cpp_type;
  typedef int hold_type;
  static const DataAtomType atom_type = kINT_ATOM;

  static hold_type CppTypeToHoldType(cpp_type data) {
    return data;
  }
  static cpp_type HoldTypeToCppType(hold_type data) {
    return data;
  }
};

template<> struct BasicTypeTraits<DataType::INT32> : public BasicIntegerTypeTraits {
  typedef int32_t cpp_type;
  typedef int32_t hold_type;
  static const DataAtomType atom_type = kINT32_ATOM;

  static hold_type CppTypeToHoldType(cpp_type data) {
    return data;
  }
  static cpp_type HoldTypeToCppType(hold_type data) {
    return data;
  }
};

template<> struct BasicTypeTraits<DataType::INT64> : public BasicIntegerTypeTraits {
  typedef int64_t cpp_type;
  typedef int64_t hold_type;
  static const DataAtomType atom_type = kINT64_ATOM;

  static hold_type CppTypeToHoldType(cpp_type data) {
    return data;
  }
  static cpp_type HoldTypeToCppType(hold_type data) {
    return data;
  }
};

template<> struct BasicTypeTraits<DataType::UINT> : public BasicIntegerTypeTraits {
  typedef unsigned int cpp_type;
  typedef unsigned int hold_type;
  static const bool is_unsigned = true;
  static const DataAtomType atom_type = kUINT_ATOM;

  static hold_type CppTypeToHoldType(cpp_type data) {
    return data;
  }
  static cpp_type HoldTypeToCppType(hold_type data) {
    return data;
  }
};

template<> struct BasicTypeTraits<DataType::UINT32> : public BasicIntegerTypeTraits {
  typedef uint32_t cpp_type;
  typedef uint32_t hold_type;
  static const bool is_unsigned = true;
  static const DataAtomType atom_type = kUINT32_ATOM;

  static hold_type CppTypeToHoldType(cpp_type data) {
    return data;
  }
  static cpp_type HoldTypeToCppType(hold_type data) {
    return data;
  }
};

template<> struct BasicTypeTraits<DataType::UINT64> : public BasicIntegerTypeTraits {
  typedef uint64_t cpp_type;
  typedef uint64_t hold_type;
  static const bool is_unsigned = true;
  static const DataAtomType atom_type = kUINT64_ATOM;

  static hold_type CppTypeToHoldType(cpp_type data) {
    return data;
  }
  static cpp_type HoldTypeToCppType(hold_type data) {
    return data;
  }
};

template<> struct BasicTypeTraits<DataType::FLOAT> : public BasicFloatingPointTypeTraits {
  typedef float cpp_type;
  typedef float hold_type;
  static const DataAtomType atom_type = kFLOAT_ATOM;

  static hold_type CppTypeToHoldType(cpp_type data) {
    return data;
  }
  static cpp_type HoldTypeToCppType(hold_type data) {
    return data;
  }
};

template<> struct BasicTypeTraits<DataType::DOUBLE>
    : public BasicFloatingPointTypeTraits {
  typedef double cpp_type;
  typedef double hold_type;
  static const DataAtomType atom_type = kDOUBLE_ATOM;
  
  static hold_type CppTypeToHoldType(cpp_type data) {
    return data;
  }
  static cpp_type HoldTypeToCppType(hold_type data) {
    return data;
  }
};

template<> struct BasicTypeTraits<DataType::BOOL> {
  typedef bool cpp_type;
  typedef bool hold_type;
  static const DataAtomType atom_type = kBOOL_ATOM;
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

template<> struct BasicTypeTraits<DataType::STRING>
    : public BasicVariableLengthTypeTraits {
  static const DataAtomType atom_type = kSTRING_ATOM;
};  // NOLINT

template<> struct BasicTypeTraits<DataType::BINARY>
    : public BasicVariableLengthTypeTraits {
  static const DataAtomType atom_type = kBINARY_ATOM;
};  // NOLINT

template<> struct BasicTypeTraits<DataType::UUID>
    : public BasicVariableLengthTypeTraits {
  static const DataAtomType atom_type = kUUID_ATOM;
};  // NOLINT


template<> struct BasicTypeTraits<DataType::DATETIME> {
  typedef int64_t cpp_type;
  typedef int64_t hold_type;
  static const DataAtomType atom_type = kDATETIME_ATOM;
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

template<> struct BasicTypeTraits<DataType::DATE> {
  typedef int32_t cpp_type;
  typedef int32_t hold_type;
  static const DataAtomType atom_type = kDATE_ATOM;
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
template<DataType datatype> struct TypeTraits
    : public BasicTypeTraits<datatype> {
  // hold_type is the same as cpp_type for non-variable length types. If the
  // type is variable length, the cpp_type does not own the contents, while
  // hold_type does.
  typedef typename BasicTypeTraits<datatype>::cpp_type cpp_type;
  typedef typename BasicTypeTraits<datatype>::hold_type hold_type;
  static const DataType type = datatype;
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
  static const DataType dataset_type = DataType::INT32;
};

template<> struct InverseTypeTraits<uint32_t> {
  static const DataType dataset_type = DataType::UINT32;
};

template<> struct InverseTypeTraits<int64_t> {
  static const DataType dataset_type = DataType::INT64;
};

template<> struct InverseTypeTraits<uint64_t> {
  static const DataType dataset_type = DataType::UINT64;
};

template<> struct InverseTypeTraits<float> {
  static const DataType dataset_type = DataType::FLOAT;
};

template<> struct InverseTypeTraits<double> {
  static const DataType dataset_type = DataType::DOUBLE;
};

template<> struct InverseTypeTraits<bool> {
  static const DataType dataset_type = DataType::BOOL;
};

template<> struct InverseTypeTraits<base::StringPiece> {
  static const DataType dataset_type = DataType::BINARY;
};

// Global constant that represents a NULL value for each type.
const struct __Null {} __ = {};

template<int type>
class ValueRef {
 public:
  typedef typename TypeTraits<static_cast<DataType>(type)>::cpp_type cpp_type;

  ValueRef(const cpp_type& value) : value_(&value) {}                  // NOLINT
  ValueRef(const __Null null) : value_(NULL) {}                        // NOLINT
  bool is_null() const { return value_ == NULL; }
  const cpp_type& value() const {
    DCHECK(!is_null());
    return *value_;
  }
 private:
  const cpp_type* value_;
};

template<>
class ValueRef<STRING> {
 public:
  ValueRef(const base::StringPiece& value)                                   // NOLINT
      : value_(value),
        is_null_(false) {}
  ValueRef(const char* value)                                          // NOLINT
      : value_(value),
        is_null_(value == NULL) {}
  ValueRef(const std::string& value)                                        // NOLINT
      : value_(value),
        is_null_(false) {}
  ValueRef(const __Null null)                                          // NOLINT
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
class ValueRef<BINARY> : public ValueRef<STRING> {
 public:
  ValueRef(const base::StringPiece& value) : ValueRef<STRING>(value) {}      // NOLINT
  ValueRef(const char* value) : ValueRef<STRING>(value) {}             // NOLINT
  ValueRef(const std::string& value) : ValueRef<STRING>(value)  {}          // NOLINT
  ValueRef(const __Null null) : ValueRef<STRING>(null) {}              // NOLINT
};

//template<> struct ValueRef<UNDEF> {};

template<>
class ValueRef<UNDEF> {
public:
  bool is_null() const { return true; }
  const __Null value() const { return {}; }
};

template<DataType type>
struct ShallowDatumCopy {
  void operator()(const typename TypeTraits<type>::cpp_type& input, typename TypeTraits<type>::cpp_type* output) {
    DCHECK(output);// << "The output must not be NULL";
    //LOG(INFO) << "setando: " << input;
    *output = input;
  }
};

template<DataType type,
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
template <DataType type>
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

// template<> struct InverseTypeTraits<DataType> {
//   static const DataType supersonic_type = DATA_TYPE;
// };

}

#endif