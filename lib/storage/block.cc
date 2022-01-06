// Copyright 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "storage/block.h"

#include "base/strings/stringprintf.h"
#include "base/strings/string_util.h"
#include "base/strings/string_number_conversions.h"
#include "zetasql/public/type.h"

namespace storage {

namespace {

std::string GetSpaces(int count) {
  std::string result;
  result.reserve(count);
  for (int i = 0 ; i < count; i++) {
    result.push_back(' ');
  }
  return result;
}

std::string GetSpaces(int count, int len) {
  std::string result;
  int diff = count - len ;
  for (int i = 0 ; i < diff; i++) {
    result.push_back(' ');
  }
  return result;
}

}

Block::Block(BufferAllocator* allocator, Schema* schema, size_t initial_rows):
  allocator_(allocator),
  schema_(schema), 
  row_count_(0),
  readonly_(true){
  
  for (size_t i = 0; i < schema->count(); ++i) {
    std::unique_ptr<DataColumn> column = std::make_unique<DataColumn>();
    column->Init(allocator_, schema_->Get(i), schema_->GetName(i), initial_rows);
    columns_.push_back(std::move(column));
  }

}

Block::Block(BufferAllocator* allocator, std::unique_ptr<Schema> schema, size_t initial_rows):
  allocator_(allocator),
  owned_schema_(std::move(schema)),
  schema_(owned_schema_.get()),
  row_count_(0),
  readonly_(true){
  
  for (size_t i = 0; i < schema_->count(); ++i) {
    std::unique_ptr<DataColumn> column = std::make_unique<DataColumn>();
    column->Init(allocator_, schema_->Get(i), schema_->GetName(i), initial_rows);
    columns_.push_back(std::move(column));
  }

}

Block::Block(std::unique_ptr<BufferAllocator> allocator, std::unique_ptr<Schema> schema, size_t initial_rows):
  owned_allocator_(std::move(allocator)),
  allocator_(owned_allocator_.get()),
  owned_schema_(std::move(schema)),
  schema_(owned_schema_.get()),
  row_count_(0),
  readonly_(true){
  
  for (size_t i = 0; i < schema_->count(); ++i) {
    std::unique_ptr<DataColumn> column = std::make_unique<DataColumn>();
    column->Init(allocator_, schema_->Get(i), schema_->GetName(i), initial_rows);
    columns_.push_back(std::move(column));
  }

}

Block::~Block() {
  // forcing them to go first, because they rely on allocator
  columns_.clear();
}

void Block::MakeRoomForRows(size_t rows_to_allocate) {
  for (size_t x = 0; x < schema_->count(); x++) {
    columns_[x]->AllocateRows(allocator_, rows_to_allocate);
  }
}

size_t Block::column_count() const { 
  return schema_->count(); 
}

size_t Block::row_count() const { 
   return row_count_; 
}

size_t Block::allocated_size() const {
  size_t allocated_sz = 0;
  for (size_t i = 0; i < schema_->count(); i++) {
    allocated_sz += columns_[i]->column_data()->length();
    const auto* type = columns_[i]->GetType();
    if (type->IsString() || 
        type->IsBytes() ||
        type->IsProto() ||
        type->IsStruct() || 
        type->IsArray()) {
    //if (columns_[i].schema().is_var_length()) {
      allocated_sz += columns_[i]->arena()->memory_footprint();
    }
  }
  return allocated_sz;
}

DataColumn& Block::column(size_t index) { 
  return *columns_[index].get(); 
}

const DataColumn& Block::column(size_t index) const { 
  return *columns_[index].get(); 
}

BlockPrinter::BlockPrinter(Block* datum): block_(datum) {

}
  
void BlockPrinter::Print() {
  std::string column_head;
  std::string body;
  int space_count = 5;
  std::string space = GetSpaces(space_count);
  std::vector<int> spaces;
  //base::StringPiece* first = 0;
  //base::StringAppendF(&column_head, "|");
  for (size_t i = 0; i < block_->column_count(); i++) {
    std::string column_name = block_->column(i).Name();
    base::StringAppendF(&column_head, "%s%s", base::ToUpperASCII(column_name).c_str(), space.c_str());
    spaces.push_back(column_name.size() + space_count);
  }
  printf("%s\n\n", column_head.c_str());
  
  for (size_t rx = 0; rx < block_->row_count(); rx++) {
    for (size_t cx = 0; cx < block_->column_count(); cx++) {
      const auto* schema = block_->column(cx).GetType();
      switch (schema->kind()) {
        case zetasql::TYPE_INT32: {
          auto col = block_->column(cx).value<zetasql::TYPE_INT32>(rx);
          auto str = base::NumberToString(col);
          base::StringAppendF(&body, "%s%s", str.c_str(), GetSpaces(spaces[cx], str.size()).c_str());
          break;
        }
        case zetasql::TYPE_INT64: {
          auto col = block_->column(cx).value<zetasql::TYPE_INT64>(rx);
          auto str = base::NumberToString(col);
          base::StringAppendF(&body, "%s%s", str.c_str(), GetSpaces(spaces[cx], str.size()).c_str());
          break;
        }
        case zetasql::TYPE_UINT32: {
          auto col = block_->column(cx).value<zetasql::TYPE_UINT32>(rx);
          auto str = base::NumberToString(col);
          base::StringAppendF(&body, "%s%s", str.c_str(), GetSpaces(spaces[cx], str.size()).c_str());
          break;
        }
        case zetasql::TYPE_UINT64: {
          auto col = block_->column(cx).value<zetasql::TYPE_UINT64>(rx);
          auto str = base::NumberToString(col);
          base::StringAppendF(&body, "%s%s", str.c_str(), GetSpaces(spaces[cx], str.size()).c_str());
          break;
        }
        case zetasql::TYPE_BOOL: {
          auto col = block_->column(cx).value<zetasql::TYPE_BOOL>(rx);
          base::StringAppendF(&body, "%s%s", (col ? "true" : "false"), GetSpaces(spaces[cx], (col ? 3 : 4)).c_str());
          break;
        }
        case zetasql::TYPE_FLOAT: {
          auto col = block_->column(cx).value<zetasql::TYPE_FLOAT>(rx);
          auto str = base::NumberToString(col);
          base::StringAppendF(&body, "%s%s", str.c_str(), GetSpaces(spaces[cx], str.size()).c_str());
          break;
        }
        case zetasql::TYPE_DOUBLE: {
          auto col = block_->column(cx).value<zetasql::TYPE_DOUBLE>(rx);
          auto str = base::NumberToString(col);
          base::StringAppendF(&body, "%s%s", str.c_str(), GetSpaces(spaces[cx], str.size()).c_str());
          break;
        }  
        case zetasql::TYPE_STRING: {
          auto col = block_->column(cx).value<zetasql::TYPE_STRING>(rx);
          auto str = col.as_string();
          base::StringAppendF(&body, "%s%s", str.c_str(), GetSpaces(spaces[cx], str.size()).c_str());
          break;
        }
        case zetasql::TYPE_BYTES: {
          auto col = block_->column(cx).value<zetasql::TYPE_BYTES>(rx);
          std::string str = base::ToLowerASCII(base::HexEncode(col.data(), col.size()));
          base::StringAppendF(&body, "%s%s", str.c_str(), GetSpaces(spaces[cx], str.size()).c_str());
          break;
        }
        case zetasql::TYPE_DATE: {
          auto col = block_->column(cx).value<zetasql::TYPE_DATE>(rx);
          auto str = base::NumberToString(col);
          base::StringAppendF(&body, "%s%s", str.c_str(), GetSpaces(spaces[cx], str.size()).c_str());
          break;
        }
        case zetasql::TYPE_TIMESTAMP: {
          auto col = block_->column(cx).value<zetasql::TYPE_TIMESTAMP>(rx);
          auto str = base::NumberToString(col);
          base::StringAppendF(&body, "%s%s", str.c_str(), GetSpaces(spaces[cx], str.size()).c_str());
          break;
        }
        case zetasql::TYPE_TIME: {
          auto col = block_->column(cx).value<zetasql::TYPE_TIME>(rx);
          auto str = base::NumberToString(col);
          base::StringAppendF(&body, "%s%s", str.c_str(), GetSpaces(spaces[cx], str.size()).c_str());
          break;
        }
        case zetasql::TYPE_DATETIME: {
          auto col = block_->column(cx).value<zetasql::TYPE_DATETIME>(rx);
          auto str = base::NumberToString(col);
          base::StringAppendF(&body, "%s%s", str.c_str(), GetSpaces(spaces[cx], str.size()).c_str());
          break;
        }
        case zetasql::TYPE_NUMERIC: {
          auto col = block_->column(cx).value<zetasql::TYPE_NUMERIC>(rx);
          auto str = base::NumberToString(col);
          base::StringAppendF(&body, "%s%s", str.c_str(), GetSpaces(spaces[cx], str.size()).c_str());
          break;
        }
        case zetasql::TYPE_GEOGRAPHY: {
          base::StringAppendF(&body, "<GEOGRAPHY>%s", space.c_str());
          break;
        }  
        case zetasql::TYPE_ENUM: {
          base::StringAppendF(&body, "<ENUM>%s", space.c_str());
          break;
        }  
        case zetasql::TYPE_ARRAY: {
          base::StringAppendF(&body, "<ARRAY>%s", space.c_str());
          break;
        }  
        case zetasql::TYPE_STRUCT: {
          base::StringAppendF(&body, "<STRUCT>%s", space.c_str());
          break;
        }
        case zetasql::TYPE_PROTO: {
          base::StringAppendF(&body, "<PROTO>%s", space.c_str());
          break;
        }
        default:
          NOTREACHED();
      }
    }
    printf("%s\n", body.c_str());
    body.clear();
  }
}

void BlockPrinter::PrintTo(std::string& out) {
  std::string column_head;
  std::string body;
  //size_t col_len = 0;
  //size_t num_len = 4;
  //std::vector<size_t> space_count(block_->column_count());

  for (size_t rx = 0; rx < block_->row_count(); rx++) {
    for (size_t cx = 0; cx < block_->column_count(); cx++) {
      const auto* schema = block_->column(cx).GetType();
      switch (schema->kind()) {
        case zetasql::TYPE_INT32: { 
          auto col = block_->column(cx).value<zetasql::TYPE_INT32>(rx);
          base::StringAppendF(&body, "%d |", col);
          break;
        }
        case zetasql::TYPE_INT64: {
          auto col = block_->column(cx).value<zetasql::TYPE_INT64>(rx);
          base::StringAppendF(&body, "%ld |", col);
          break;
        }
        case zetasql::TYPE_UINT32: {
          auto col = block_->column(cx).value<zetasql::TYPE_UINT32>(rx);
          base::StringAppendF(&body, "%u |", col);
          break;
        }
        case zetasql::TYPE_UINT64: {
          auto col = block_->column(cx).value<zetasql::TYPE_UINT64>(rx);
          base::StringAppendF(&body, "%zu |", col);
          break;
        }
        case zetasql::TYPE_BOOL: {
          auto col = block_->column(cx).value<zetasql::TYPE_BOOL>(rx);
          base::StringAppendF(&body, "%s |", col ? "true" : "false");
          break;
        }
        case zetasql::TYPE_FLOAT: {
          auto col = block_->column(cx).value<zetasql::TYPE_FLOAT>(rx);
          base::StringAppendF(&body, "%f |", col);
          break;
        }
        case zetasql::TYPE_DOUBLE: {
          auto col = block_->column(cx).value<zetasql::TYPE_DOUBLE>(rx);
          base::StringAppendF(&body, "%f |", col);
          break;
        }  
        case zetasql::TYPE_STRING: {
          auto col = block_->column(cx).value<zetasql::TYPE_STRING>(rx);
          base::StringAppendF(&body, "%s |", col.as_string().c_str());
          break;
        }
        case zetasql::TYPE_BYTES: {
          auto col = block_->column(cx).value<zetasql::TYPE_BYTES>(rx);
          std::string value = base::ToLowerASCII(base::HexEncode(col.data(), col.size()));
          base::StringAppendF(&body, " %s |", value.c_str());
          break;
        }
        default:
          NOTREACHED();
      }
      
    }
    base::StringAppendF(&body, "\n");
    //base::StringAppendF(&out, "| %s\n", body.c_str());
    
    //body.clear();
  }

  base::StringAppendF(&column_head, " ");
  for (size_t i = 0; i < block_->column_count(); i++) {
    std::string colname = block_->column(i).Name();
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