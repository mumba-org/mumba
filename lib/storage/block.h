// Copyright 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_STORAGE_BLOCK_
#define MUMBA_STORAGE_BLOCK_

#include <unordered_map>

#include "base/strings/string_piece.h"
#include "storage/data_types.h"
#include "storage/data_common.h"
#include "storage/data_column.h"
#include "storage/db/arena.h"
#include "storage/db/memory.h"
#include "storage/proto/storage.pb.h"

namespace storage {

class Block {
public:
 Block(BufferAllocator* allocator,
       Schema* schema, 
       size_t initial_rows = kALLOCATED_ROWS_OFFSET);

 Block(BufferAllocator* allocator,
       std::unique_ptr<Schema> schema, 
       size_t initial_rows = kALLOCATED_ROWS_OFFSET);

 Block(std::unique_ptr<BufferAllocator> allocator,
       std::unique_ptr<Schema> schema, 
       size_t initial_rows = kALLOCATED_ROWS_OFFSET);

 ~Block(); 

 const Schema& schema() const { return *schema_; }

 bool readonly() const { return readonly_; }

 size_t allocated_size() const;

 DataColumn& column(size_t index);
 const DataColumn& column(size_t index) const;
 
 void AddRow() {
  if(!HasEnoughRoomForRows()) {
    MakeRoomForRows(kALLOCATED_ROWS_OFFSET);
  }
  row_count_++;
 }

 template <zetasql::TypeKind type>
 bool Set(size_t col_offset, size_t row_offset, const typename TypeTraits<type>::cpp_type& value) {
  DatumCopy<type, true> copy;  
  DataColumn& col = column(col_offset);

  if (!copy(value,
            col.data<typename TypeTraits<type>::cpp_type>(row_offset),
            col.arena())) {
    return false;
  }
  return true;
 }

 template <zetasql::TypeKind type>
 bool Set(size_t col_offset, const typename TypeTraits<type>::cpp_type& value) {
    size_t row_offset = row_count_ -1;
    return Set<type>(col_offset, row_offset, value);
 }

 template <zetasql::TypeKind type>
 inline void CopyColumn(size_t col_offset, std::vector<const typename TypeTraits<type>::cpp_type&>* out) {
   typename TypeTraits<type>::cpp_type* col = column(col_offset).typed_data<typename TypeTraits<type>::cpp_type>();
   for (size_t i = 0; i < row_count(); i++) {
    out->push_back(col[i]);
   }
 }

 size_t column_count() const;
 size_t row_count() const;
 
private:
 
 bool HasEnoughRoomForRows() const {
  return (row_count_ + 1) - columns_[0]->allocated_rows() <= 0;
 }


 void MakeRoomForRows(size_t rows);

 std::unique_ptr<BufferAllocator> owned_allocator_;

 BufferAllocator* allocator_;

 std::unique_ptr<Schema> owned_schema_;
 
 Schema* schema_;

 std::vector<std::unique_ptr<DataColumn>> columns_;

 size_t row_count_;

 bool readonly_;

 DISALLOW_COPY_AND_ASSIGN(Block);
};

class BlockRowWriter {
public:
  BlockRowWriter(): 
    block_(nullptr),
    row_offset_(0), 
    col_offset_(0) {

  }
  
  ~BlockRowWriter() {}

  void Init(Block* block) {
    block_ = block;
  }

  template <zetasql::TypeKind type>
  inline BlockRowWriter& Set(size_t col_offset, size_t row_offset, const typename TypeTraits<type>::cpp_type& value) {
    block_->Set<type>(col_offset, row_offset, value);
    return *this;
  }

  template <zetasql::TypeKind type>
  inline BlockRowWriter& Set(size_t col_offset, const typename TypeTraits<type>::cpp_type& value) {
    block_->Set<type>(col_offset, row_offset_, value);
    return *this;
  }

  template <zetasql::TypeKind type>
  inline BlockRowWriter& Set(const std::string& name, const typename TypeTraits<type>::cpp_type& value) {
    size_t col_offset = block_->schema().GetOffset(name);
    block_->Set<type>(col_offset, row_offset_, value);
    return *this;
  }

  template <zetasql::TypeKind type>
  inline BlockRowWriter& Set(const typename TypeTraits<type>::cpp_type& value) {
    block_->Set<type>(col_offset_, row_offset_, value);
    col_offset_++;
    return *this;
  }

  inline void AddRow() {
     block_->AddRow();
     col_offset_ = 0;
     row_offset_ = block_->row_count() - 1;
  }

  BlockRowWriter& Int32(int32_t value) { return Set<zetasql::TYPE_INT32>(value); }
  BlockRowWriter& Int64(int64_t value) { return Set<zetasql::TYPE_INT64>(value); }
  BlockRowWriter& Uint32(uint32_t value) { return Set<zetasql::TYPE_UINT32>(value); }
  BlockRowWriter& Uint64(uint64_t value) { return Set<zetasql::TYPE_UINT64>(value); }
  BlockRowWriter& Float(float value) { return Set<zetasql::TYPE_FLOAT>(value); }
  BlockRowWriter& Double(double value) { return Set<zetasql::TYPE_DOUBLE>(value); }
  BlockRowWriter& Numeric(double value) { return Set<zetasql::TYPE_NUMERIC>(value); }
  BlockRowWriter& Geography(double value) { return Set<zetasql::TYPE_GEOGRAPHY>(value); }
  BlockRowWriter& Bool(bool value) { return Set<zetasql::TYPE_BOOL>(value); }
  BlockRowWriter& Date(int32_t value) { return Set<zetasql::TYPE_DATE>(value); }
  BlockRowWriter& Datetime(int64_t value) { return Set<zetasql::TYPE_DATETIME>(value); }
  BlockRowWriter& Time(int64_t value) { return Set<zetasql::TYPE_TIME>(value); }
  BlockRowWriter& Timestamp(int64_t value) { return Set<zetasql::TYPE_TIMESTAMP>(value); }
  BlockRowWriter& String(const base::StringPiece& value) {
    return Set<zetasql::TYPE_STRING>(value);
  }

  BlockRowWriter& Bytes(const base::StringPiece& value) {
    return Set<zetasql::TYPE_BYTES>(value);
  }
  // fix 
  BlockRowWriter& Array(const base::StringPiece& value) {
    return Set<zetasql::TYPE_ARRAY>(value);
  }
  // fix
  BlockRowWriter& Struct(const base::StringPiece& value) {
    return Set<zetasql::TYPE_STRUCT>(value);
  }
  // fix
  BlockRowWriter& Proto(const base::StringPiece& value) {
    return Set<zetasql::TYPE_PROTO>(value);
  }
private:
  Block* block_;
  size_t row_offset_;
  size_t col_offset_;
};

template <int A = zetasql::TYPE_UNKNOWN, int B = zetasql::TYPE_UNKNOWN, int C = zetasql::TYPE_UNKNOWN, int D = zetasql::TYPE_UNKNOWN,
          int E = zetasql::TYPE_UNKNOWN, int F = zetasql::TYPE_UNKNOWN, int G = zetasql::TYPE_UNKNOWN, int H = zetasql::TYPE_UNKNOWN,
          int I = zetasql::TYPE_UNKNOWN, int J = zetasql::TYPE_UNKNOWN, int K = zetasql::TYPE_UNKNOWN, int L = zetasql::TYPE_UNKNOWN,
          int M = zetasql::TYPE_UNKNOWN, int N = zetasql::TYPE_UNKNOWN, int O = zetasql::TYPE_UNKNOWN, int P = zetasql::TYPE_UNKNOWN,
          int Q = zetasql::TYPE_UNKNOWN, int R = zetasql::TYPE_UNKNOWN, int S = zetasql::TYPE_UNKNOWN, int T = zetasql::TYPE_UNKNOWN>

class BlockBuilder {
  typedef BlockBuilder<A, B, C, D, E, F, G, H, I, J,
                           K, L, M, N, O, P, Q, R, S, T> This;
public:

  BlockBuilder(BufferAllocator* allocator, Schema* schema, size_t initial_rows = kALLOCATED_ROWS_OFFSET): 
    block_(new Block(allocator, schema, initial_rows)),
    writer_() {
    writer_.Init(block_.get());  
  }

  template <zetasql::TypeKind type>
  void Set(size_t col_offset, size_t row_offset, const typename TypeTraits<type>::cpp_type& value) {
    return writer_.Set<type>(col_offset, row_offset, value);
  }

  template <zetasql::TypeKind type>
  void Set(size_t col_offset, const typename TypeTraits<type>::cpp_type& value) {
    return writer_.Set<type>(col_offset, value);
  }

  template <zetasql::TypeKind type>
  void Set(const std::string& name, const typename TypeTraits<type>::cpp_type& value) {
    return writer_.Set<type>(name, value); 
  }

  template <zetasql::TypeKind type>
  inline void CopyColumn(size_t col_offset, std::vector<const typename TypeTraits<type>::cpp_type&>* out) {
    return block_->CopyColumn<type>(col_offset, out);
  }

  This& AddRow(ValueRef<A> a = ValueRef<zetasql::TYPE_UNKNOWN>(),
               ValueRef<B> b = ValueRef<zetasql::TYPE_UNKNOWN>(),
               ValueRef<C> c = ValueRef<zetasql::TYPE_UNKNOWN>(),
               ValueRef<D> d = ValueRef<zetasql::TYPE_UNKNOWN>(),
               ValueRef<E> e = ValueRef<zetasql::TYPE_UNKNOWN>(),
               ValueRef<F> f = ValueRef<zetasql::TYPE_UNKNOWN>(),
               ValueRef<G> g = ValueRef<zetasql::TYPE_UNKNOWN>(),
               ValueRef<H> h = ValueRef<zetasql::TYPE_UNKNOWN>(),
               ValueRef<I> i = ValueRef<zetasql::TYPE_UNKNOWN>(),
               ValueRef<J> j = ValueRef<zetasql::TYPE_UNKNOWN>(),
               ValueRef<K> k = ValueRef<zetasql::TYPE_UNKNOWN>(),
               ValueRef<L> l = ValueRef<zetasql::TYPE_UNKNOWN>(),
               ValueRef<M> m = ValueRef<zetasql::TYPE_UNKNOWN>(),
               ValueRef<N> n = ValueRef<zetasql::TYPE_UNKNOWN>(),
               ValueRef<O> o = ValueRef<zetasql::TYPE_UNKNOWN>(),
               ValueRef<P> p = ValueRef<zetasql::TYPE_UNKNOWN>(),
               ValueRef<Q> q = ValueRef<zetasql::TYPE_UNKNOWN>(),
               ValueRef<R> r = ValueRef<zetasql::TYPE_UNKNOWN>(),
               ValueRef<S> s = ValueRef<zetasql::TYPE_UNKNOWN>(),
               ValueRef<T> t = ValueRef<zetasql::TYPE_UNKNOWN>()){

    writer_.AddRow();

    i::SetTypedValueRef(a, &writer_);
    i::SetTypedValueRef(b, &writer_);
    i::SetTypedValueRef(c, &writer_);
    i::SetTypedValueRef(d, &writer_);
    i::SetTypedValueRef(e, &writer_);
    i::SetTypedValueRef(f, &writer_);
    i::SetTypedValueRef(g, &writer_);
    i::SetTypedValueRef(h, &writer_);
    i::SetTypedValueRef(i, &writer_);
    i::SetTypedValueRef(j, &writer_);
    i::SetTypedValueRef(k, &writer_);
    i::SetTypedValueRef(l, &writer_);
    i::SetTypedValueRef(m, &writer_);
    i::SetTypedValueRef(n, &writer_);
    i::SetTypedValueRef(o, &writer_);
    i::SetTypedValueRef(p, &writer_);
    i::SetTypedValueRef(q, &writer_);
    i::SetTypedValueRef(r, &writer_);
    i::SetTypedValueRef(s, &writer_);
    i::SetTypedValueRef(t, &writer_);

    return *this;
  }

  inline void NewRow() {
    writer_.AddRow();
  }

  Block* Build() {
    //block_->NewRow();
    return block_.release();
  }

private:
  
  // template<int type>
  // inline void SetTypedValueRef(const ValueRef<type> ref) {
  //   //if (ref.is_null()) {
  //   //  writer->Null();
  //   //} else {
  //   if (!ref.is_null()) {
  //     writer_.Set<static_cast<DataType>(type)>(block_.get(), ref.value());
  //   }
  // }

  std::unique_ptr<Block> block_;  

  BlockRowWriter writer_;

  DISALLOW_COPY_AND_ASSIGN(BlockBuilder);
};

class BlockPrinter {
public:
  BlockPrinter(Block* block);
  
  void Print();
  void PrintTo(std::string& out);
  
private:
 Block* block_;

 DISALLOW_COPY_AND_ASSIGN(BlockPrinter);
};

namespace i {

template<int type>
inline void SetTypedValueRef(const ValueRef<type> ref, BlockRowWriter* writer) {
    //if (ref.is_null()) {
    //  writer->Null();
    //} else {
    if (!ref.is_null()) {
      writer->Set<static_cast<zetasql::TypeKind>(type)>(ref.value());
    } else {
      DLOG(ERROR) << "ref is null";
    }
}  

} // namespace i


}

#endif