// Copyright 2017 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/common/call_codec.h"

#include "base/logging.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_split.h"
#include "base/strings/string_util.h"
#include "third_party/velocypack/include/velocypack/vpack.h"

using arangodb::velocypack::Builder;
using arangodb::velocypack::Value;
using arangodb::velocypack::ValueType;
using arangodb::velocypack::Slice;
using arangodb::velocypack::HexDump;
using arangodb::velocypack::ArrayIterator;

namespace common {

CallEncoder::CallEncoder() {

}

bool CallEncoder::EncodeInfo(CallInfo* call, std::string* out) {
  Builder b;
  
  if (!EncodeCallInfo(&b, call))
    return false;

 out->assign(reinterpret_cast<const char *>(b.slice().begin()), b.slice().byteSize());

 return true;
}

bool CallEncoder::EncodeResult(CallResult* result, std::string* out) {
  Builder b;
  
  b.add(Value(ValueType::Object)); // {
  b.add("ns", Value(result->ns));
  b.add("api", Value(result->api));
  b.add("method", Value(result->method));
  b.add("error", Value(result->is_error));
  
  if (result->value.type == kBOOL_ARG) {
    b.add("type", Value("bool"));
    b.add("value", Value(result->value.entry.b));
  } else if (result->value.type == kINT_ARG) {
    b.add("type", Value("int"));
    b.add("value", Value(result->value.entry.i));  
  } else if (result->value.type == kDOUBLE_ARG) {
    b.add("type", Value("double"));
    b.add("value", Value(result->value.entry.d));
  } else if (result->value.type == kSTRING_ARG) {
    b.add("type", Value("string"));   
    b.add("value", Value(result->value.entry_string));
  } else if (result->value.type == kUNDEFINED_ARG) {
    b.add("type", Value("undefined"));   
    b.add("value", Value(result->value.entry_string));
  } else if (result->value.type == kNULL_ARG) {
    b.add("type", Value("null"));   
    b.add("value", Value(result->value.entry_string));
  } else if (result->value.type == kOBJECT_ARG) {
    b.add("type", Value("object"));   
    b.add("value", Value(result->value.entry_string));
  } 
 
  b.close();

  out->assign(reinterpret_cast<const char *>(b.slice().begin()), b.slice().byteSize());

  return true;
}

bool CallEncoder::EncodeCallInfo(arangodb::velocypack::Builder* builder, CallInfo* call) {
  builder->add(Value(ValueType::Object)); // {
  builder->add("ns", Value(call->ns));
  builder->add("api", Value(call->api));
  builder->add("method", Value(call->method));
  builder->add("args", Value(ValueType::Array)); // [
  for (auto it = call->args.begin(); it != call->args.end(); ++it) {
    auto value = (*it)->value;
    builder->add(Value(ValueType::Object)); // {
    builder->add("key", Value((*it)->key));
    builder->add("pos", Value((*it)->pos));
    if (value.type == kBOOL_ARG) {
      builder->add("type", Value("bool"));
      builder->add("value", Value(value.entry.b));
    } else if (value.type == kINT_ARG) {
      builder->add("type", Value("int"));
      builder->add("value", Value(value.entry.i));  
    } else if (value.type == kDOUBLE_ARG) {
      builder->add("type", Value("double"));
      builder->add("value", Value(value.entry.d));
    } else if (value.type == kSTRING_ARG) {
      builder->add("type", Value("string"));   
      builder->add("value", Value(value.entry_string));
    }
    builder->close(); // }
  }
  builder->close(); // ]
  // builder->add("metadata", Value(ValueType::Object)); // metadata: {
  // for (auto it = call.metadata.begin(); it != call.metadata.end(); ++it) {
  //   builder->add(it->first, Value(it->second));
  // }
  // builder->close(); // } metadata

  builder->close(); // }
  
  return true;
}

CallDecoder::CallDecoder() {

}
 
bool CallDecoder::DecodeInfo(const std::string& data, CallInfo* call) {
  return DecodeInfo(data.data(), data.size(), call);
}

bool CallDecoder::DecodeInfo(const char* data, size_t len, CallInfo* call) {
  Slice s(data);
  Slice ns(s.get("ns"));
  Slice api(s.get("api"));
  Slice method(s.get("method"));
  Slice args(s.get("args"));

  ArrayIterator args_it(args);

  for (auto it = args_it.begin(); it != args_it.end(); ++it) {
    Slice arg(*it);
    Slice key_val(arg.get("key"));
    Slice pos_val(arg.get("pos"));
    Slice type_val(arg.get("type"));
    Slice value_val(arg.get("value"));

    CallArg* call_arg = new CallArg{};
    
    call_arg->key = key_val.copyString();
    call_arg->pos = pos_val.getNumber<int>();
    
    std::string type_str = type_val.copyString();
    if (type_str == "bool") {
      call_arg->value.type = kBOOL_ARG;
      call_arg->value.entry.b = value_val.getBool();
    } else if (type_str == "int") {
      call_arg->value.type = kINT_ARG;
      call_arg->value.entry.i = value_val.getNumber<int>();
    } else if (type_str == "double") {
      call_arg->value.type = kDOUBLE_ARG;
      call_arg->value.entry.d = value_val.getDouble();
    } else if (type_str == "string") {
      call_arg->value.type = kSTRING_ARG;
      call_arg->value.entry_string = value_val.copyString();
    } else {
      DLOG(ERROR) << "error: unknow type '" << type_str << "'";
    }

    call->args.push_back(call_arg);
  }

  
  call->ns = ns.copyString();
  call->api = api.copyString();
  call->method = method.copyString();

  return true;
}

bool CallDecoder::DecodeResult(const std::string& data, CallResult* result) {
  Slice s(data.data());
  Slice ns(s.get("ns"));
  Slice api(s.get("api"));
  Slice method(s.get("method"));
  Slice error(s.get("error"));
  Slice type_val(s.get("type"));
  Slice value_val(s.get("value"));

  //LOG(INFO) << "ns";
  result->ns = ns.copyString();
  //LOG(INFO) << "api";
  result->api = api.copyString();
  //LOG(INFO) << "method";
  result->method = method.copyString();

  result->is_error = error.getBool();

  //LOG(INFO) << "type";
  std::string type_str = type_val.copyString();
  
  if (type_str == "bool") {
    //LOG(INFO) << "bool";
    result->value.type = kBOOL_ARG;
    result->value.entry.b = value_val.getBool();
    //LOG(INFO) << "bool: " << result->value.entry.b; 
  } else if (type_str == "int") {
    //LOG(INFO) << "int";
    result->value.type = kINT_ARG;
    result->value.entry.i = value_val.getNumber<int>();
    //LOG(INFO) << "int: " << result->value.entry.i; 
  } else if (type_str == "double") {
    //LOG(INFO) << "double";
    result->value.type = kDOUBLE_ARG;
    result->value.entry.d = value_val.getDouble();
    //LOG(INFO) << "double: " << result->value.entry.d; 
  } else if (type_str == "string") {
    //LOG(INFO) << "string";
    result->value.type = kSTRING_ARG;
    result->value.entry_string = value_val.copyString();
    //LOG(INFO) << "string: " << result->value.entry_string; 
  } else if (type_str == "undefined") {
    result->value.type = kUNDEFINED_ARG;
    result->value.entry_string = value_val.copyString();
  } else if (type_str == "null") {
    result->value.type = kNULL_ARG;
    result->value.entry_string = value_val.copyString();
  } else if (type_str == "object") {
    result->value.type = kOBJECT_ARG;
    result->value.entry_string = value_val.copyString();
  }

  return true;
}

}