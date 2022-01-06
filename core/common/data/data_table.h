// Copyright 2017 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_COMMON_DATA_DATA_TABLE_H_
#define MUMBA_COMMON_DATA_DATA_TABLE_H_

#include <string>
#include <vector>
#include <unordered_map>

#include "base/macros.h"
#include <memory>
#include "base/synchronization/lock.h"
#include "base/uuid.h"
#include "core/common/data/data_atom.h"
#include "core/common/data/data_source.h"
#include "core/common/data/data_types.h"
#include "core/common/data/data_memory.h"
#include "core/common/data/data_arena.h"
#include "core/common/data/data_common.h"

namespace common {
class TableAtomRowWriter;
class TableAtom;
class ResultSet;
// by how many rows, we allocate in advance
const size_t kALLOCATED_ROWS_OFFSET = 20;

//class TableAtomBuilder;
// TODO: make this more or less the same types as seen in Javascript
//       but also as available to SQLITE


class TableColumn {
public:
  TableColumn();
  ~TableColumn();

  void Init(BufferAllocator* allocator, const ColumnSchema* schema, size_t rows) {
    schema_ = schema;
    allocated_rows_ = rows;
    column_data_.reset(new ColumnData());
    column_data_->Init(allocator, CalculateSize(rows), schema->is_var_length());
  }

  const ColumnSchema& schema() const { return *schema_; }
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
      return reinterpret_cast<T *>(column_data_->typed_data_offset(offset, schema().type_log2size()));
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
    //return &typed_data<typename TypeTraits<type>::cpp_type>()[offset];
    return typed_offset<typename TypeTraits<type>::cpp_type>(offset);
  }

  template <DataType type>
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

private:

  size_t CalculateSize(size_t rows) {
    //LOG(INFO) << "int size: " << schema().type_size() << " rows: " << rows << " total = " << schema().type_size() * rows; 
    return schema().type_size() * rows;
  }

  const ColumnSchema* schema_;

  std::unique_ptr<ColumnData> column_data_;

  size_t allocated_rows_;

  DISALLOW_COPY_AND_ASSIGN(TableColumn);  
};

// Equivalent to a "Block" in supersonic
// or a "DataFrame" in R

// TODO: Precisamos criar "DataTableRowVisitor" e "TableColumnVisitor"
//       assim poderemos ter métodos no javascript que podem ser aplicados
//       no estilo funcional, e percorrer ou por rows, ou por columns

// TODO: Abrir o DataTable para que possa ser percorrido pro scripts
//       javascript
//       Criar os bindings necessários
class TableAtomRowWriter;

class TableAtom : public DataAtom,
                  public DataSource {
public:
 
 std::unique_ptr<TableAtom> FromResultSet(ResultSet* rs);

 TableAtom(
    DataContext* context, 
    TableSchema* schema, 
    size_t initial_rows = kALLOCATED_ROWS_OFFSET);

 ~TableAtom() override; 

// const base::UUID& uuid() const { return uuid_; }

 const TableSchema& schema() const { return *schema_; }

 bool readonly() const { return readonly_; }

 TableColumn& column(size_t index) { return columns_[index]; }
 const TableColumn& column(size_t index) const { return columns_[index]; }
 size_t allocated_size() const {
  size_t allocated_sz = 0;
  for (size_t i = 0; i < schema_->count(); i++) {
    allocated_sz += columns_[i].column_data()->length();
    if (columns_[i].schema().is_var_length()) {
      allocated_sz += columns_[i].arena()->memory_footprint();
    }
  }
  return allocated_sz;
 }

 void AddRow() {
  if(!HasEnoughRoomForRows()) {
    MakeRoomForRows(kALLOCATED_ROWS_OFFSET);
  }
  row_count_++;
 }

 template <DataType type>
 bool Set(size_t col_offset, size_t row_offset, const typename TypeTraits<type>::cpp_type& value) {
  DatumCopy<type, true> copy;  
  TableColumn& col = column(col_offset);

  if (!copy(value,
            col.data<typename TypeTraits<type>::cpp_type>(row_offset),
            col.arena())) {
    return false;
  }
  return true;
 }

 template <DataType type>
 bool Set(size_t col_offset, const typename TypeTraits<type>::cpp_type& value) {
    size_t row_offset = row_count_ -1;
    return Set<type>(col_offset, row_offset, value);
 }

 template <DataType type>
 inline void CopyColumn(size_t col_offset, std::vector<const typename TypeTraits<type>::cpp_type&>* out) {
   typename TypeTraits<type>::cpp_type* col = column(col_offset).typed_data<typename TypeTraits<type>::cpp_type>();
   for (size_t i = 0; i < row_count(); i++) {
    out->push_back(col[i]);
   }
 }

 // Datasource
 size_t column_count() const override;
 size_t row_count() const override;
 bool Encode(std::string* out) override;
 
private:
 
 bool HasEnoughRoomForRows() const {
  return (row_count_ + 1) - columns_[0].allocated_rows() <= 0;
 }

 void MakeRoomForRows(size_t rows); 
 
 //base::UUID uuid_;

 std::unique_ptr<TableSchema> schema_;
  
 std::unique_ptr<TableColumn[]> columns_;

 //DataContext* context_;

 size_t row_count_;

 bool readonly_;

 DISALLOW_COPY_AND_ASSIGN(TableAtom);
};

class TableAtomRowWriter {
public:
  TableAtomRowWriter(): 
    table_(nullptr), 
    row_offset_(0), 
    col_offset_(0) {

  }
  
  ~TableAtomRowWriter() {}

  void Init(TableAtom* table) {
    table_ = table;
  }

  template <DataType type>
  inline TableAtomRowWriter& Set(size_t col_offset, size_t row_offset, const typename TypeTraits<type>::cpp_type& value) {
    table_->Set<type>(col_offset, row_offset, value);
    return *this;
  }

  template <DataType type>
  inline TableAtomRowWriter& Set(size_t col_offset, const typename TypeTraits<type>::cpp_type& value) {
    table_->Set<type>(col_offset, row_offset_, value);
    return *this;
  }

  template <DataType type>
  inline TableAtomRowWriter& Set(const std::string& name, const typename TypeTraits<type>::cpp_type& value) {
    size_t col_offset = table_->schema().GetOffset(name);
    table_->Set<type>(col_offset, row_offset_, value);
    return *this;
  }

  template <DataType type>
  inline TableAtomRowWriter& Set(const typename TypeTraits<type>::cpp_type& value) {
    table_->Set<type>(col_offset_, row_offset_, value);
    col_offset_++;
    return *this;
  }

  inline void AddRow() {
     table_->AddRow();
     col_offset_ = 0;
     row_offset_ = table_->row_count() - 1;
  }

  TableAtomRowWriter& Int32(int32_t value) { return Set<INT32>(value); }
  TableAtomRowWriter& Int64(int64_t value) { return Set<INT64>(value); }
  TableAtomRowWriter& Uint32(uint32_t value) { return Set<UINT32>(value); }
  TableAtomRowWriter& Uint64(uint64_t value) { return Set<UINT64>(value); }
  TableAtomRowWriter& Float(float value) { return Set<FLOAT>(value); }
  TableAtomRowWriter& Double(double value) { return Set<DOUBLE>(value); }
  TableAtomRowWriter& Bool(bool value) { return Set<BOOL>(value); }
  TableAtomRowWriter& Date(int32_t value) { return Set<DATE>(value); }
  TableAtomRowWriter& Datetime(int64_t value) { return Set<DATETIME>(value); }
  TableAtomRowWriter& String(const base::StringPiece& value) {
    return Set<STRING>(value);
  }

  TableAtomRowWriter& Binary(const base::StringPiece& value) {
    return Set<BINARY>(value);
  }

private:
  TableAtom* table_;
  size_t row_offset_;
  size_t col_offset_;
};

template <int A = UNDEF, int B = UNDEF, int C = UNDEF, int D = UNDEF,
          int E = UNDEF, int F = UNDEF, int G = UNDEF, int H = UNDEF,
          int I = UNDEF, int J = UNDEF, int K = UNDEF, int L = UNDEF,
          int M = UNDEF, int N = UNDEF, int O = UNDEF, int P = UNDEF,
          int Q = UNDEF, int R = UNDEF, int S = UNDEF, int T = UNDEF>

class TableAtomBuilder {
  typedef TableAtomBuilder<A, B, C, D, E, F, G, H, I, J,
                         K, L, M, N, O, P, Q, R, S, T> This;
public:

  TableAtomBuilder(DataContext* context, TableSchema* schema, size_t initial_rows = kALLOCATED_ROWS_OFFSET): 
    table_(new TableAtom(context, schema, initial_rows)),
    writer_() {
    writer_.Init(table_.get());  
  }

  template <DataType type>
  void Set(size_t col_offset, size_t row_offset, const typename TypeTraits<type>::cpp_type& value) {
    return writer_.Set<type>(col_offset, row_offset, value);
  }

  template <DataType type>
  void Set(size_t col_offset, const typename TypeTraits<type>::cpp_type& value) {
    return writer_.Set<type>(col_offset, value);
  }

  template <DataType type>
  void Set(const std::string& name, const typename TypeTraits<type>::cpp_type& value) {
    return writer_.Set<type>(name, value); 
  }

  template <DataType type>
  inline void CopyColumn(size_t col_offset, std::vector<const typename TypeTraits<type>::cpp_type&>* out) {
    return table_->CopyColumn<type>(col_offset, out);
  }

  This& AddRow(ValueRef<A> a = ValueRef<UNDEF>(),
               ValueRef<B> b = ValueRef<UNDEF>(),
               ValueRef<C> c = ValueRef<UNDEF>(),
               ValueRef<D> d = ValueRef<UNDEF>(),
               ValueRef<E> e = ValueRef<UNDEF>(),
               ValueRef<F> f = ValueRef<UNDEF>(),
               ValueRef<G> g = ValueRef<UNDEF>(),
               ValueRef<H> h = ValueRef<UNDEF>(),
               ValueRef<I> i = ValueRef<UNDEF>(),
               ValueRef<J> j = ValueRef<UNDEF>(),
               ValueRef<K> k = ValueRef<UNDEF>(),
               ValueRef<L> l = ValueRef<UNDEF>(),
               ValueRef<M> m = ValueRef<UNDEF>(),
               ValueRef<N> n = ValueRef<UNDEF>(),
               ValueRef<O> o = ValueRef<UNDEF>(),
               ValueRef<P> p = ValueRef<UNDEF>(),
               ValueRef<Q> q = ValueRef<UNDEF>(),
               ValueRef<R> r = ValueRef<UNDEF>(),
               ValueRef<S> s = ValueRef<UNDEF>(),
               ValueRef<T> t = ValueRef<UNDEF>()){

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

  TableAtom* Build() {
    //table_->NewRow();
    return table_.release();
  }

private:
  
  // template<int type>
  // inline void SetTypedValueRef(const ValueRef<type> ref) {
  //   //if (ref.is_null()) {
  //   //  writer->Null();
  //   //} else {
  //   if (!ref.is_null()) {
  //     writer_.Set<static_cast<DataType>(type)>(table_.get(), ref.value());
  //   }
  // }

  TableAtomRowWriter writer_;

  std::unique_ptr<TableAtom> table_;  

  DISALLOW_COPY_AND_ASSIGN(TableAtomBuilder);
};

class TableAtomPrinter {
public:
  TableAtomPrinter(TableAtom* datum);
  
  void Print();
  void PrintTo(std::string& out);
  
private:
 TableAtom* table_;

 DISALLOW_COPY_AND_ASSIGN(TableAtomPrinter);
};

namespace i {

template<int type>
inline void SetTypedValueRef(const ValueRef<type> ref, TableAtomRowWriter* writer) {
    //if (ref.is_null()) {
    //  writer->Null();
    //} else {
    if (!ref.is_null()) {
      writer->Set<static_cast<DataType>(type)>(ref.value());
    } else {
      DLOG(ERROR) << "ref is null";
    }
}  

} // namespace i

} // namespace common

#endif