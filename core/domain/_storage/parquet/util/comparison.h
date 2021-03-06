// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

#ifndef PARQUET_UTIL_COMPARISON_H
#define PARQUET_UTIL_COMPARISON_H

#include <algorithm>

#include "core/shared/domain/storage/parquet/exception.h"
#include "core/shared/domain/storage/parquet/schema.h"
#include "core/shared/domain/storage/parquet/types.h"

namespace domain {

class Comparator {
 public:
  virtual ~Comparator() {}
  static std::shared_ptr<Comparator> Make(const ColumnDescriptor* descr);
};

// The default comparison is SIGNED
template <typename DType>
class CompareDefault : public Comparator {
 public:
  typedef typename DType::c_type T;
  CompareDefault() {}
  virtual bool operator()(const T& a, const T& b) { return a < b; }
};

template <>
class CompareDefault<ParquetInt96Type> : public Comparator {
 public:
  CompareDefault() {}
  virtual bool operator()(const Int96& a, const Int96& b) {
    // Only the MSB bit is by Signed comparison
    // For little-endian, this is the last bit of Int96 type
    const int32_t amsb = static_cast<const int32_t>(a.value[2]);
    const int32_t bmsb = static_cast<const int32_t>(b.value[2]);
    if (amsb != bmsb) {
      return (amsb < bmsb);
    } else if (a.value[1] != b.value[1]) {
      return (a.value[1] < b.value[1]);
    }
    return (a.value[0] < b.value[0]);
  }
};

template <>
class CompareDefault<ParquetByteArrayType> : public Comparator {
 public:
  CompareDefault() {}
  virtual bool operator()(const ByteArray& a, const ByteArray& b) {
    const int8_t* aptr = reinterpret_cast<const int8_t*>(a.ptr);
    const int8_t* bptr = reinterpret_cast<const int8_t*>(b.ptr);
    return std::lexicographical_compare(aptr, aptr + a.len, bptr, bptr + b.len);
  }
};

template <>
class CompareDefault<ParquetFLBAType> : public Comparator {
 public:
  explicit CompareDefault(int length) : type_length_(length) {}
  virtual bool operator()(const FLBA& a, const FLBA& b) {
    const int8_t* aptr = reinterpret_cast<const int8_t*>(a.ptr);
    const int8_t* bptr = reinterpret_cast<const int8_t*>(b.ptr);
    return std::lexicographical_compare(aptr, aptr + type_length_, bptr,
                                        bptr + type_length_);
  }
  int32_t type_length_;
};

typedef CompareDefault<ParquetBooleanType> CompareDefaultBoolean;
typedef CompareDefault<ParquetInt32Type> CompareDefaultInt32;
typedef CompareDefault<ParquetInt64Type> CompareDefaultInt64;
typedef CompareDefault<ParquetInt96Type> CompareDefaultInt96;
typedef CompareDefault<ParquetFloatType> CompareDefaultFloat;
typedef CompareDefault<ParquetDoubleType> CompareDefaultDouble;
typedef CompareDefault<ParquetByteArrayType> CompareDefaultByteArray;
typedef CompareDefault<ParquetFLBAType> CompareDefaultFLBA;

#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wattributes"
#endif

PARQUET_EXTERN_TEMPLATE CompareDefault<ParquetBooleanType>;
PARQUET_EXTERN_TEMPLATE CompareDefault<ParquetInt32Type>;
PARQUET_EXTERN_TEMPLATE CompareDefault<ParquetInt64Type>;
PARQUET_EXTERN_TEMPLATE CompareDefault<ParquetInt96Type>;
PARQUET_EXTERN_TEMPLATE CompareDefault<ParquetFloatType>;
PARQUET_EXTERN_TEMPLATE CompareDefault<ParquetDoubleType>;
PARQUET_EXTERN_TEMPLATE CompareDefault<ParquetByteArrayType>;
PARQUET_EXTERN_TEMPLATE CompareDefault<ParquetFLBAType>;

#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif

// Define Unsigned Comparators
class CompareUnsignedInt32 : public CompareDefaultInt32 {
 public:
  bool operator()(const int32_t& a, const int32_t& b) override {
    const uint32_t ua = a;
    const uint32_t ub = b;
    return (ua < ub);
  }
};

class CompareUnsignedInt64 : public CompareDefaultInt64 {
 public:
  bool operator()(const int64_t& a, const int64_t& b) override {
    const uint64_t ua = a;
    const uint64_t ub = b;
    return (ua < ub);
  }
};

class CompareUnsignedInt96 : public CompareDefaultInt96 {
 public:
  bool operator()(const Int96& a, const Int96& b) override {
    if (a.value[2] != b.value[2]) {
      return (a.value[2] < b.value[2]);
    } else if (a.value[1] != b.value[1]) {
      return (a.value[1] < b.value[1]);
    }
    return (a.value[0] < b.value[0]);
  }
};

class CompareUnsignedByteArray : public CompareDefaultByteArray {
 public:
  bool operator()(const ByteArray& a, const ByteArray& b) override {
    const uint8_t* aptr = reinterpret_cast<const uint8_t*>(a.ptr);
    const uint8_t* bptr = reinterpret_cast<const uint8_t*>(b.ptr);
    return std::lexicographical_compare(aptr, aptr + a.len, bptr, bptr + b.len);
  }
};

class CompareUnsignedFLBA : public CompareDefaultFLBA {
 public:
  explicit CompareUnsignedFLBA(int length) : CompareDefaultFLBA(length) {}
  bool operator()(const FLBA& a, const FLBA& b) override {
    const uint8_t* aptr = reinterpret_cast<const uint8_t*>(a.ptr);
    const uint8_t* bptr = reinterpret_cast<const uint8_t*>(b.ptr);
    return std::lexicographical_compare(aptr, aptr + type_length_, bptr,
                                        bptr + type_length_);
  }
};

}  // namespace domain

#endif  // PARQUET_UTIL_COMPARISON_H
