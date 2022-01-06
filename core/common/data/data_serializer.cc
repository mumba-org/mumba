// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/common/data/data_serializer.h"

#include "core/common/data/data_atom.h"
#include "core/common/data/data_memory.h"
#include "core/common/data/data_table.h"
#include "core/common/data/data_stream.h"
#include "core/common/data/result_set.h"
#include "third_party/velocypack/include/velocypack/vpack.h"

using arangodb::velocypack::Builder;
using arangodb::velocypack::Value;
using arangodb::velocypack::ValueType;
using arangodb::velocypack::Slice;
using arangodb::velocypack::ArrayIterator;

namespace common {
  
namespace {

const char kHEADER_MAGIC[] = "ENCODED_DataTable";
const char kHEADER_VER[] = "0.0.1";
const int kHEADER_MAGIC_LEN = arraysize(kHEADER_MAGIC);
const int kHEADER_VER_LEN = arraysize(kHEADER_VER);

}  

DataEncoder::DataEncoder() {

}
 
bool DataEncoder::EncodeTable(const TableAtom* ds, std::string* out) {
  //LOG(INFO) << "DataTableEncoder::Encode";
  Builder b;
  std::string magic(kHEADER_MAGIC, kHEADER_MAGIC_LEN);
  std::string version(kHEADER_VER, kHEADER_VER_LEN);
  //std::string uuid_str(reinterpret_cast<const char *>(ds->uuid().data), 16);

  b.add(Value(ValueType::Object)); // root
  // magic number
  b.add("magic", Value(magic));
  // version
  b.add("version", Value(version));  
  // DataTable uuid
  //b.add("uuid", Value(uuid_str));
  // col count
  b.add("colcnt", Value(ds->column_count()));
  // row count
  b.add("rowcnt", Value(ds->row_count()));
  // readonly
  b.add("readonly", Value(ds->readonly()));
  // column schema
  b.add("schema", Value(ValueType::Array)); // schema array
  for (size_t i = 0; i < ds->column_count(); i++) {
    const auto& schema = ds->column(i).schema();
    b.add(Value(ValueType::Object));
    b.add("index", Value(i));
    b.add("type", Value(schema.type()));
    b.add("name", Value(schema.name()));
    b.close();
  }

  b.close(); // schema array end
  
  b.add("body", Value(ValueType::Object)); // body

  // column payload
  for (size_t i = 0; i < ds->column_count(); i++) {
    const auto& schema = ds->column(i).schema();
    b.add(schema.name(), Value(ValueType::Array));
    for (size_t r = 0; r < ds->row_count(); r++) {
      if (schema.is_integer()) {
        auto col = ds->column(i).value<INT>(r);
        b.add(Value(col));
      } else if (schema.is_floating_point()) {
        auto col = ds->column(i).value<DOUBLE>(r);
        b.add(Value(col));
      } else if (schema.is_var_length()) {
        auto col = ds->column(i).value<STRING>(r);
        std::string col_str = col.as_string();
        //LOG(INFO) << "setting string: " << col_str;
        b.add(Value(col_str));
      } else if (schema.type() == BOOL) {
        auto col = ds->column(i).value<BOOL>(r);
        b.add(Value(col));
      }
    }
    b.close();
  }

  b.close(); // body end
  
  b.close(); // root end

  out->assign(reinterpret_cast<const char *>(b.slice().begin()), b.slice().byteSize());

  return true;
}

bool DataEncoder::EncodeResultSet(ResultSet* cursor, std::string* out) {
  Builder b;
  //Builder array_builder;
  std::unique_ptr<TableSchema> schema;

  //base::UUID newid = base::UUID::generate();
  
  std::string magic(kHEADER_MAGIC, kHEADER_MAGIC_LEN);
  std::string version(kHEADER_VER, kHEADER_VER_LEN);
  //std::string uuid_str(reinterpret_cast<const char *>(newid.data), 16);

  b.add(Value(ValueType::Object)); // root
  // magic number
  b.add("magic", Value(magic));
  // version
  b.add("version", Value(version));  
  // DataTable uuid
  //b.add("uuid", Value(uuid_str));
  // col count
  b.add("colcnt", Value(cursor->column_count()));
  // row count
  //b.add("rowcnt", Value(0));//Value(cursor->GetRowCount()));
  // readonly
  b.add("readonly", Value(true));
  // column schema
  b.add("schema", Value(ValueType::Array)); // schema array
  
  if (cursor->column_count() > 0) {
    schema = cursor->BuildSchema(); 

    for (size_t i = 0; i < cursor->column_count(); i++) {
      const ColumnSchema* col_schema = schema->Get(i);
      b.add(Value(ValueType::Object));
      b.add("index", Value(i));
      b.add("type", Value(col_schema->type()));
      b.add("name", Value(col_schema->name()));
      b.close();
    }
  }

  b.close(); // schema array end
  
  b.add("body", Value(ValueType::Object)); // body

  int nrows = 0;
  
  for (size_t col = 0; col < cursor->column_count(); col++) {
    const ColumnSchema* col_schema = schema->Get(col);
    DataType type = cursor->GetColumnType(col);//col_schema->type();
    b.add(col_schema->name(), Value(ValueType::Array));  
    while (cursor->HasNext()) {
      //LOG(INFO) << "cursor.next";
      if (type == STRING) {
        auto str = cursor->GetString(col);
        std::string col_str = str.as_string();
        //LOG(INFO) << "str: " << col_str;        
        b.add(Value(col_str));
      } else if (type == DOUBLE) {
        b.add(Value(cursor->GetDouble(col)));
      } else if (type == INT) {
        b.add(Value(cursor->GetInt(col)));
      } else if (type == BINARY) {
        auto str = cursor->GetBlob(col);
        std::string col_str = str.as_string();
        b.add(Value(col_str));
      }
      cursor->Next();
      if (col == 0)
        nrows++;
    }
    b.close();
    cursor->First();
  }
  cursor->Done();
  
  b.close(); // body end

  //LOG(INFO) << "cursor row count: " << nrows;
  b.add("rowcnt", Value(static_cast<int>(nrows)));

  b.close(); // root end

  out->assign(reinterpret_cast<const char *>(b.slice().begin()), b.slice().byteSize());

  return true; 
}

bool DataEncoder::EncodeStream(DataStream* stream, std::string* out) {
  return false;
}

bool DataEncoder::EncodeAtom(DataAtom* atom, std::string* out) {  
  Builder b;
  
  b.add(Value(ValueType::Object)); // root
        
  b.add("type", Value(static_cast<int>(atom->type())));

  switch (atom->type()) {
    case kBOOL_ATOM:
      b.add("value", Value(static_cast<BoolAtom *>(atom)->get()));
      break;
    case kINT_ATOM:
      b.add("value", Value(static_cast<IntAtom *>(atom)->get()));
      break;
    case kUINT_ATOM:
      b.add("value", Value(static_cast<UintAtom *>(atom)->get()));
      break;
    case kFLOAT_ATOM:
      b.add("value", Value(static_cast<FloatAtom *>(atom)->get()));
      break;
    case kDOUBLE_ATOM:
      b.add("value", Value(static_cast<DoubleAtom *>(atom)->get()));
      break;
    case kUINT32_ATOM:
      b.add("value", Value(static_cast<Uint32Atom *>(atom)->get()));
      break;
    case kUINT64_ATOM:
      b.add("value", Value(static_cast<Uint64Atom *>(atom)->get()));
      break;
    case kINT32_ATOM:
      b.add("value", Value(static_cast<Int32Atom *>(atom)->get()));
      break;
    case kINT64_ATOM:
      b.add("value", Value(static_cast<Int64Atom *>(atom)->get()));
      break;
    case kDATETIME_ATOM:
      b.add("value", Value(static_cast<DatetimeAtom *>(atom)->get()));
      break;
    case kDATE_ATOM:
      b.add("value", Value(static_cast<DateAtom *>(atom)->get()));
      break;
    case kSTRING_ATOM: {
      StringAtom* str_atom = static_cast<StringAtom *>(atom);
      base::StringPiece buf = str_atom->get();
      std::string str(buf.data(), buf.size());
      b.add("value", Value(str));
      break;
    }
    case kBINARY_ATOM: {
      BinaryAtom* bin_atom = static_cast<BinaryAtom *>(atom);
      base::StringPiece buf = bin_atom->get();
      std::string str(buf.data(), buf.size());
      b.add("value", Value(str));
      break;
    }
    case kUUID_ATOM: {
      DLOG(INFO) << "uuid atom";
      UUIDAtom* uuid_atom = static_cast<UUIDAtom *>(atom);
      base::StringPiece buf = uuid_atom->get();
      std::string str(buf.data(), buf.size());
      b.add("value", Value(str));
      break;
    }
    default: {
      b.add("value", Value(0));
      b.close();
      return false;
    }
  }

  b.close();

  out->assign(reinterpret_cast<const char *>(b.slice().begin()), b.slice().byteSize());

  return true;
}

DataDecoder::DataDecoder(DataContext* context): context_(context) {
  
}
  
bool DataDecoder::DecodeTable(const std::string& data, TableAtom** out) {
  //LOG(INFO) << "DataTableDecoder::Decode";
  std::unique_ptr<TableSchema> schema(new TableSchema());
  Slice s(data.data());

  Slice smagic(s.get("magic"));
  Slice sver(s.get("version"));

  std::string magic = smagic.copyString();
  std::string version = sver.copyString();

  if (strncmp(magic.c_str(), kHEADER_MAGIC, kHEADER_MAGIC_LEN) != 0) {
    LOG(ERROR) << "decode: bad header '" << magic << "'";
    return false;
  }

  //Slice suuid(s.get("uuid"));
  Slice scolcnt(s.get("colcnt"));
  Slice srowcnt(s.get("rowcnt"));
  //Slice sreadonly(s.get("readonly"));

  Slice schema_arr(s.get("schema"));
  ArrayIterator schema_it(schema_arr);

  for (auto it = schema_it.begin(); it != schema_it.end(); ++it) {
    Slice object(*it);
    //Slice id_val(object.get("index"));
    Slice type_val(object.get("type"));
    Slice name_val(object.get("name"));
    schema->Add(new ColumnSchema(name_val.copyString(), static_cast<DataType>(type_val.getNumber<int>())));
  }

  //std::string uuid_str = suuid.copyString();
  //base::UUID ds_uuid(reinterpret_cast<const uint8_t *>(uuid_str.data()));
  //LOG(INFO) << "creating DataTable.. row count: " << srowcnt.getNumber<int>();
  //TableAtom* ds = new TableAtom(ds_uuid, context_, schema.release());
  TableAtom* ds = new TableAtom(context_, schema.release());
  Slice body(s.get("body"));

  size_t row_count = static_cast<size_t>(srowcnt.getNumber<int>());
  size_t col_count = static_cast<size_t>(scolcnt.getNumber<int>());
  if (row_count > 0) {
    for (size_t i = 0; i < col_count; i++) {
      size_t row_offset = 0;
      const ColumnSchema* col_schema = ds->schema().Get(i);
      Slice column_arr(body.get(col_schema->name()));
      ArrayIterator column_it(column_arr);
      for (auto it = column_it.begin(); it != column_it.end(); ++it) {  
        if (i == 0) {
          ds->AddRow();
        }
        Slice value(*it);
        if (col_schema->type() == INT) {
          //LOG(INFO) << "setting int";
          ds->Set<INT>(i, row_offset, value.getNumber<int>());
        } else if (col_schema->type() == DOUBLE) {
          //LOG(INFO) << "setting double";
          ds->Set<DOUBLE>(i, row_offset, value.getNumber<double>());
        } else if (col_schema->type() == STRING) {
          std::string col_str = value.copyString();
          base::StringPiece str;
          str.set(col_str.c_str(), col_str.size());
          //LOG(INFO) << "setting string: " << str.data() << " len: " << str.size();
          ds->Set<STRING>(i, row_offset, str);
        } else if (col_schema->type() == BOOL) {
          //LOG(INFO) << "setting bool";
          ds->Set<BOOL>(i, row_offset, value.getBoolean()); 
        }
        
        row_offset++;
      }
    }
  }

  *out = ds;

  return true;
}

bool DataDecoder::DecodeTable(const char* data, size_t len, TableAtom** out) {
  return false;
}

bool DataDecoder::DecodeStream(const std::string& data, DataStream** out) {
  return false; 
}

bool DataDecoder::DecodeAtom(const std::string& data, DataAtom** out) { 
  DCHECK(context_);
  DCHECK(context_->allocator());

  Slice s(data.data());
  Slice type_val(s.get("type"));  
  Slice value_val(s.get("value"));

  DataAtomType type = static_cast<DataAtomType>(type_val.getNumber<int>());

  switch (type) {
    case kBOOL_ATOM:
      *out = new BoolAtom(context_, value_val.getBool());
      break;  
    case kINT_ATOM:
      *out = new IntAtom(context_, value_val.getNumber<int>());
      break;
    case kUINT_ATOM:
      *out = new UintAtom(context_, value_val.getNumber<unsigned>());
      break;
    case kFLOAT_ATOM:
      *out = new FloatAtom(context_, value_val.getBool());
      break;
    case kDOUBLE_ATOM:
      *out = new DoubleAtom(context_, value_val.getBool());
      break;
    case kUINT32_ATOM:
      *out = new Uint32Atom(context_, value_val.getNumber<uint32_t>());
      break;
    case kUINT64_ATOM:
      *out = new Uint64Atom(context_, value_val.getNumber<uint64_t>());
      break;
    case kINT32_ATOM:
      *out = new Int32Atom(context_, value_val.getNumber<int32_t>());
      break;
    case kINT64_ATOM:
      *out = new Int64Atom(context_, value_val.getNumber<int64_t>());
      break;
    case kDATETIME_ATOM:
      *out = new DatetimeAtom(context_, value_val.getNumber<int64_t>());
      break;
    case kDATE_ATOM:
      *out = new DateAtom(context_, value_val.getNumber<int32_t>());
      break;
    case kSTRING_ATOM:
      *out = new StringAtom(context_);
      static_cast<StringAtom *>(*out)->set(value_val.copyString());
      break;
    case kBINARY_ATOM:
      *out = new BinaryAtom(context_);
      static_cast<BinaryAtom *>(*out)->set(value_val.copyString());
      break;
    case kUUID_ATOM:
      DLOG(INFO) << "uuid atom";
      *out = new UUIDAtom(context_);
      static_cast<UUIDAtom *>(*out)->set(value_val.copyString());
      break;  
    default:
      return false;
  }
  
  return true;
}

}
