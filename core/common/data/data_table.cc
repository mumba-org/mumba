// Copyright 2017 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/common/data/data_table.h"

#include <algorithm>

#include "base/logging.h"
#include "base/strings/stringprintf.h"
#include "core/common/data/result_set.h"
#include "core/common/data/data_serializer.h"

namespace common {
  
//ColumnSchema::ColumnSchema(const std::string& name, DataType type): 
//  name_(name), 
//  type_(type), 
//  type_size_(SizeForDataType(type)), 
//  type_log2size_(Log2SizeForDataType(type)) {

//}


TableColumn::TableColumn(): schema_(nullptr) {}

TableColumn::~TableColumn() {}

std::unique_ptr<TableAtom> TableAtom::FromResultSet(ResultSet* rs) {
  return rs->BuildTable(context());
}

TableAtom::TableAtom(DataContext* context, TableSchema* schema, size_t initial_rows):
  DataAtom(context, kTABLE_ATOM),
  //uuid_(base::UUID::generate()),
  schema_(schema), 
  columns_(new TableColumn[schema->count()]),
  row_count_(0),
  readonly_(true){
  
  for (size_t i = 0; i < schema->count(); ++i) {
    columns_[i].Init(context->allocator(), schema->Get(i), initial_rows);
  }

}

TableAtom::~TableAtom() {
  
}

void TableAtom::MakeRoomForRows(size_t rows_to_allocate) {
  for (size_t x = 0; x < schema_->count(); x++) {
    columns_[x].AllocateRows(context()->allocator(), rows_to_allocate);
  }
}

size_t TableAtom::column_count() const { 
  return schema_->count(); 
}

size_t TableAtom::row_count() const { 
   return row_count_; 
}

bool TableAtom::Encode(std::string* out){
  DataEncoder encoder;
  return encoder.EncodeTable(this, out);
}

//TableAtomBuilder::TableAtomBuilder(Schema* schema, size_t rows): table_(new TableAtom(schema, rows)) {
//}
  
// void TableAtomBuilder::AddRow(int a, int b, int c) {
//   size_t index = table_->row_count_;
//   int* icol0 = table_->column(0).offset<int>(index);
//   int* icol1 = table_->column(1).offset<int>(index);
//   int* icol2 = table_->column(2).offset<int>(index);
//   *icol0 = a;
//   *icol1 = b;
//   *icol2 = c;
//   table_->row_count_++;
// }

// TableAtom* TableAtomBuilder::Build() {
//   return table_.release();
// }


TableAtomPrinter::TableAtomPrinter(TableAtom* datum): table_(datum) {

}
  
void TableAtomPrinter::Print() {
  std::string column_head;
  std::string body;
  //base::StringPiece* first = 0;

  base::StringAppendF(&column_head, "| ");
  for (size_t i = 0; i < table_->column_count(); i++) {
    base::StringAppendF(&column_head, " %s |", table_->schema().Get(i)->name().c_str());
  }
  printf("%s\n\n", column_head.c_str());

  for (size_t rx = 0; rx < table_->row_count(); rx++) {
    for (size_t cx = 0; cx < table_->column_count(); cx++) {
      const auto& schema = table_->column(cx).schema();
      if (schema.is_integer()) {
        auto col = table_->column(cx).value<INT>(rx);
        base::StringAppendF(&body, " %d |", col);
      } else if (schema.is_floating_point()) {
        auto col = table_->column(cx).value<DOUBLE>(rx);
        base::StringAppendF(&body, " %f |", col);
      } else if (schema.is_var_length()) {
        auto col = table_->column(cx).value<STRING>(rx);
        //table_->column(cx).data<base::StringPiece>(rx);
        std::string value(col.data(), col.size());
        base::StringAppendF(&body, " %s |", value.c_str());
      }
    }
    printf("| %s\n", body.c_str());
    body.clear();
  }
}

void TableAtomPrinter::PrintTo(std::string& out) {
  std::string column_head;
  std::string body;
  //size_t col_len = 0;
  //size_t num_len = 4;
  //std::vector<size_t> space_count(table_->column_count());

  for (size_t rx = 0; rx < table_->row_count(); rx++) {
    for (size_t cx = 0; cx < table_->column_count(); cx++) {
      const auto& schema = table_->column(cx).schema();
      if (schema.is_integer()) {
        auto col = table_->column(cx).value<INT>(rx);
        //LOG(INFO) << "value: " << col; 
        base::StringAppendF(&body, "%d |", col);
        //col_len = std::max(col_len, num_len);
        //space_count[cx] = col_len;
      } else if (schema.is_floating_point()) {
        auto col = table_->column(cx).value<DOUBLE>(rx);
        //LOG(INFO) << "value: " << col;
        base::StringAppendF(&body, "%f |", col);
        //col_len = std::max(col_len, num_len);
        //space_count[cx] = col_len;
      } else if (schema.is_var_length()) {
        //auto col = table_->column(cx).data<char>(rx);
        auto col = table_->column(cx).value<STRING>(rx);
        //LOG(INFO) << "ptr: " << reinterpret_cast<const void *>(col.data()) << " +3:" << reinterpret_cast<const void *>(reinterpret_cast<const char *>(col.data()) + 3);
        size_t size = std::min(col.size(), static_cast<size_t>(255));
        std::string str(col.data(), size);//col->data(), size);
        //LOG(INFO) << "col " << cx << " row " << rx << " size(" << str.size() << ")";
        base::StringAppendF(&body, "%s |", str.c_str());
        //col_len = std::max(col_len, value.size());
        //space_count[cx] = col_len;
      }
      //LOG(INFO) << "body: " << body;
    }
    base::StringAppendF(&body, "\n");
    //base::StringAppendF(&out, "| %s\n", body.c_str());
    
    //body.clear();
  }

  base::StringAppendF(&column_head, " ");
  for (size_t i = 0; i < table_->column_count(); i++) {
    std::string colname = table_->schema().Get(i)->name();
    //std::string tabs;
    //for (size_t x = 0; x < (space_count[i] - colname.size()); x++) {
    //  tabs += " ";
    //}
    //base::StringAppendF(&column_head, "%s %s|", colname.c_str(), tabs.c_str());
    base::StringAppendF(&column_head, "%s |", colname.c_str());
  }
    
  base::StringAppendF(&out, "%s\n\n", column_head.c_str());
  base::StringAppendF(&out, "%s\n", body.c_str());  
}

}