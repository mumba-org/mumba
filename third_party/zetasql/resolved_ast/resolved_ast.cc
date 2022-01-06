//
// Copyright 2019 ZetaSQL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

// resolved_ast.cc GENERATED FROM resolved_ast.cc.template
#include "zetasql/resolved_ast/resolved_ast.h"

#include <type_traits>

#include "google/protobuf/descriptor.h"
#include "zetasql/common/errors.h"
#include "zetasql/public/catalog.h"
#include "zetasql/public/constant.h"
#include "zetasql/public/strings.h"
#include "zetasql/public/type.h"
#include "zetasql/resolved_ast/resolved_ast_visitor.h"
#include "absl/memory/memory.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_join.h"
#include "absl/strings/str_split.h"
#include "absl/types/span.h"
#include "zetasql/base/status.h"

namespace zetasql {

namespace {

// Helper for IsDefaultValue to allow template partial specialization,
// which we can do with a class but not with a function.
template <class T>
struct TestIsDefaultValue {
  static bool IsDefaultValue(const T& value) {
    static_assert(std::is_pod<T>::value,
                  "Customize IsDefaultValue for non-POD types");
    return value == T();
  }
};
template <class T>
struct TestIsDefaultValue<std::unique_ptr<T>> {
  static bool IsDefaultValue(const std::unique_ptr<T>& value) {
    return value == nullptr;
  }
};
template <class T>
struct TestIsDefaultValue<std::shared_ptr<T>> {
  static bool IsDefaultValue(const std::shared_ptr<T>& value) {
    return value == nullptr;
  }
};
template <class T>
struct TestIsDefaultValue<std::vector<T>> {
  static bool IsDefaultValue(const std::vector<T>& value) {
    return value.empty();
  }
};
template <>
struct TestIsDefaultValue<std::string> {
  static bool IsDefaultValue(const std::string& value) {
    return value.empty();
  }
};
template <>
struct TestIsDefaultValue<Value> {
  static bool IsDefaultValue(const Value& value) {
    return !value.is_valid();
  }
};
template <>
struct TestIsDefaultValue<FunctionSignature> {
  static bool IsDefaultValue(const FunctionSignature& signature) {
    return signature.NumOptionalArguments() == -1 &&
           signature.NumRepeatedArguments() == -1;
  }
};
template <>
struct TestIsDefaultValue<std::shared_ptr<ResolvedFunctionCallInfo>> {
  static bool IsDefaultValue(
      const std::shared_ptr<ResolvedFunctionCallInfo>& info) {
    return info == nullptr || info->Is<ResolvedFunctionCallInfo>();
  }
};
template <>
struct TestIsDefaultValue<ResolvedColumn> {
  static bool IsDefaultValue(const ResolvedColumn& column) {
    return !column.IsInitialized();
  }
};

// Return true if <value> is equal to the default value for its type.
// e.g. for pointers, return true if <value> is nullptr.
// TODO This provides no way to distinguish an unset value from a
// value explicitly set to its default.  Replace this with something
// smarter and more explicit.
template <class T>
static bool IsDefaultValue(const T& value) {
  return TestIsDefaultValue<T>::IsDefaultValue(value);
}

static std::string ToStringImpl(const std::string& s) {
  return ToStringLiteral(s);
}
static std::string ToStringImpl(bool b) {
  return b ? "TRUE" : "FALSE";
}
static std::string ToStringImpl(int i) {
  return absl::StrCat(i);
}
static std::string ToStringCommaSeparated(const std::vector<int>& value_vector) {
  return absl::StrCat("[", absl::StrJoin(value_vector, ", "), "]");
}
static std::string ToStringImpl(
    const std::vector<ResolvedStatement::ObjectAccess>& value_vector) {
  std::string ret;
  for (const ResolvedStatement::ObjectAccess& value : value_vector) {
    std::string name = ResolvedStatementEnums::ObjectAccess_Name(value);
    if (name.empty()) {
      LOG(DFATAL) << "Invalid ObjectAccess: " << value;
      name = absl::StrCat("INVALID_OBJECT_ACCESS(", value, ")");
    }
    if (!ret.empty()) ret += ",";
    ret += name;
  }
  return ret;
}
static std::string ToStringImpl(ResolvedJoinScan::JoinType join_type) {
  std::string name = ResolvedJoinScanEnums::JoinType_Name(join_type);
  if (!name.empty()) return name;
  LOG(DFATAL) << "Invalid JoinType: " << join_type;
  return absl::StrCat("INVALID_JOIN_TYPE(", join_type, ")");
}
static std::string ToStringImpl(ResolvedSubqueryExpr::SubqueryType type) {
  std::string name = ResolvedSubqueryExprEnums::SubqueryType_Name(type);
  if (!name.empty()) return name;
  LOG(DFATAL) << "Invalid SubqueryType: " << type;
  return absl::StrCat("INVALID_SUBQUERY_TYPE(", type, ")");
}
static std::string ToStringImpl(ResolvedSetOperationScan::SetOperationType type) {
  std::string name = ResolvedSetOperationScanEnums::SetOperationType_Name(type);
  if (!name.empty()) return name;
  LOG(DFATAL) << "Invalid SetType: " << type;
  return absl::StrCat("INVALID_SET_TYPE(", type, ")");
}
static std::string ToStringImpl(ResolvedCreateStatement::CreateScope scope) {
  std::string name = ResolvedCreateStatementEnums::CreateScope_Name(scope);
  if (!name.empty()) return name;
  LOG(DFATAL) << "Invalid CreateScope: " << scope;
  return absl::StrCat("INVALID_CREATE_SCOPE(", scope, ")");
}
static std::string ToStringImpl(ResolvedCreateStatement::CreateMode mode) {
  std::string name = ResolvedCreateStatementEnums::CreateMode_Name(mode);
  if (!name.empty()) return name;
  LOG(DFATAL) << "Invalid CreateMode: " << mode;
  return absl::StrCat("INVALID_CREATE_MODE(", mode, ")");
}
static std::string ToStringImpl(ResolvedBeginStmt::ReadWriteMode mode) {
  std::string name = ResolvedBeginStmtEnums::ReadWriteMode_Name(mode);
  if (!name.empty()) return name;
  LOG(DFATAL) << "Invalid ReadWriteMode: " << mode;
  return absl::StrCat("INVALID_READ_WRITE_MODE(", mode, ")");
}
static std::string ToStringImpl(ResolvedSampleScan::SampleUnit unit) {
  std::string name = ResolvedSampleScanEnums::SampleUnit_Name(unit);
  if (!name.empty()) return name;
  LOG(DFATAL) << "Invalid SampleUnit: " << unit;
  return absl::StrCat("INVALID_SAMPLE_UNIT(", unit, ")");
}
static std::string ToStringImpl(FieldFormat::Format format) {
  const std::string& str = FieldFormat_Format_Name(format);
  return !str.empty() ? str : absl::StrCat("INVALID_FORMAT(", format, ")");
}
static std::string ToStringImpl(ResolvedInsertStmt::InsertMode insert_mode) {
  return ResolvedInsertStmt::InsertModeToString(insert_mode);
}
static std::string ToStringImpl(
    ResolvedAggregateHavingModifier::HavingModifierKind kind) {
  return ResolvedAggregateHavingModifier::HavingModifierKindToString(kind);
}
static const std::string& ToStringImpl(
    ResolvedNonScalarFunctionCallBaseEnums::NullHandlingModifier kind) {
  return ResolvedNonScalarFunctionCallBaseEnums::NullHandlingModifier_Name(
      kind);
}
static std::string ToStringImpl(ResolvedArgumentDef::ArgumentKind kind) {
  const std::string& str = ResolvedArgumentDefEnums::ArgumentKind_Name(kind);
  return !str.empty() ? str : absl::StrCat("INVALID_ARGUMENT_KIND(", kind, ")");
}
static std::string ToStringImpl(ResolvedImportStmt::ImportKind kind) {
  return ResolvedImportStmt::ImportKindToString(kind);
}
static std::string ToStringImpl(const FunctionSignature& signature) {
  return signature.DebugString();
}
static std::string ToStringImpl(
    const std::shared_ptr<ResolvedFunctionCallInfo>& function_call_info) {
  if (function_call_info == nullptr) return "<null>";
  return function_call_info->DebugString();
}
static std::string ToStringVerbose(const FunctionSignature& signature) {
  return signature.DebugString("" /* function_name */, true /* verbose */);
}
static std::string ToStringImpl(const Table* table) {
  return table->FullName();
}
static std::string ToStringImpl(const Model* model) {
  return model->FullName();
}
static std::string ToStringImpl(const TableValuedFunction* tvf) {
  return absl::StrCat(absl::StrJoin(tvf->function_name_path(), "."), "(",
                FunctionSignature::SignaturesToString(
                    tvf->signatures(), /*verbose=*/true, /*prefix=*/"",
                    /*separator=*/"; "),
                ")");
}
static std::string ToStringImpl(const Procedure* procedure) {
  return procedure->FullName();
}
static std::string ToStringImpl(const std::shared_ptr<TVFSignature>& tvf_signature) {
  return tvf_signature->DebugString();
}
static std::string ToStringImpl(const Type* type) {
  return type->DebugString();
}
static std::string ToStringImpl(const google::protobuf::FieldDescriptor* field) {
  return field->is_extension() ?
      absl::StrCat("[", field->full_name(), "]"): field->name();
}
static std::string ToStringImpl(const ResolvedColumn& column) {
  return column.DebugString();
}
static std::string ToStringImpl(const ResolvedColumnList& column_list) {
  return ResolvedColumnListToString(column_list);
}
static std::string ToStringImpl(const Value& value) {
  return value.ShortDebugString();
}
static std::string ToStringImpl(const std::vector<std::string>& value_vector,
                           const std::string& separator) {
  std::string ret;
  for (const std::string& value : value_vector) {
    if (!ret.empty()) ret += separator;
    ret += ToIdentifierLiteral(value);
  }
  return ret;
}
static std::string ToStringImpl(const ResolvedMergeWhen::MatchType match_type) {
  std::string name = ResolvedMergeWhenEnums::MatchType_Name(match_type);
  if (!name.empty()) return name;
  LOG(DFATAL) << "Invalid MatchType: " << match_type;
  return absl::StrCat("INVALID_MATCH_TYPE(", match_type, ")");
}
static std::string ToStringImpl(const ResolvedMergeWhen::ActionType action_type) {
  std::string name = ResolvedMergeWhenEnums::ActionType_Name(action_type);
  if (!name.empty()) return name;
  LOG(DFATAL) << "Invalid ActionType: " << action_type;
  return absl::StrCat("INVALID_ACTION_TYPE(", action_type, ")");
}
static std::string ToStringImpl(ResolvedForeignKeyEnums::MatchMode match_mode) {
  std::string name = ResolvedForeignKeyEnums::MatchMode_Name(match_mode);
  if (!name.empty()) return name;
  LOG(DFATAL) << "Invalid MatchMode: " << match_mode;
  return absl::StrCat("INVALID_MATCH_MODE(", match_mode, ")");
}
static std::string ToStringImpl(
    ResolvedForeignKeyEnums::ActionOperation action_operation) {
  std::string name = ResolvedForeignKeyEnums::ActionOperation_Name(action_operation);
  if (!name.empty()) return name;
  LOG(DFATAL) << "Invalid ActionOperation: " << action_operation;
  return absl::StrCat("INVALID_ACTION_OPERATION(", action_operation, ")");
}
static std::string ToStringImpl(
    ResolvedCreateStatementEnums::SqlSecurity sql_security) {
  std::string name = ResolvedCreateStatementEnums::SqlSecurity_Name(sql_security);
  if (!name.empty()) return name;
  LOG(DFATAL) << "Invalid SqlSecurity: " << sql_security;
  return absl::StrCat("INVALID_SQL_SECURITY(", sql_security, ")");
}

// Most vector<std::string> fields are identifier paths so we format
// the value that way by default.
// For other vector<std::string> fields, we can override this with to_string_method.
static std::string ToStringImpl(const std::vector<std::string>& value_vector) {
  return ToStringImpl(value_vector, ".");
}
// This formats a list of identifiers (quoting if needed).
static std::string ToStringCommaSeparated(const std::vector<std::string>& value_vector) {
  return absl::StrCat("[", ToStringImpl(value_vector, ", "), "]");
}

// The SaveToImpl(ScalarType, FileDescriptorSetMap*, ScalarProtoType*) functions
// implement the serialization logic for scalar types. The FileDescriptorSetMap
// argument is used for serialization of zetasql::Type and data structures
// that contain zetasql::Types. For detailed usage, see comments above
// Type::SerializeToProtoAndDistinctFileDescriptors().
static zetasql_base::Status SaveToImpl(
    const Table* table,
    FileDescriptorSetMap* file_descriptor_set_map,
    TableRefProto* proto) {
  proto->set_name(table->Name());
  proto->set_serialization_id(table->GetSerializationId());
  proto->set_full_name(table->FullName());
  return ::zetasql_base::OkStatus();
}

// The RestoreFrom functions reverse the effect of the SaveTo functions.
static zetasql_base::StatusOr<const Table*> RestoreFromImpl(
    const TableRefProto& proto,
    const ResolvedNode::RestoreParams& params) {
  const Table* table;
  const std::vector<std::string> path = absl::StrSplit(proto.full_name(), '.');
  ZETASQL_RETURN_IF_ERROR(params.catalog->FindTable(path, &table));
  return table;
}

static zetasql_base::Status SaveToImpl(
    const Model* model,
    FileDescriptorSetMap* file_descriptor_set_map,
    ModelRefProto* proto) {
  proto->set_name(model->Name());
  proto->set_serialization_id(model->GetSerializationId());
  proto->set_full_name(model->FullName());
  return ::zetasql_base::OkStatus();
}

// The RestoreFrom functions reverse the effect of the SaveTo functions.
static zetasql_base::StatusOr<const Model*> RestoreFromImpl(
    const ModelRefProto& proto,
    const ResolvedNode::RestoreParams& params) {
  const Model* model;
  const std::vector<std::string> path = absl::StrSplit(proto.full_name(), '.');
  ZETASQL_RETURN_IF_ERROR(params.catalog->FindModel(path, &model));
  return model;
}

static zetasql_base::Status SaveToImpl(
    const Constant* constant,
    FileDescriptorSetMap* file_descriptor_set_map,
    ConstantRefProto* proto) {
  proto->set_name(constant->FullName());
  return ::zetasql_base::OkStatus();
}

static zetasql_base::StatusOr<const Constant*> RestoreFromImpl(
    const ConstantRefProto& proto, const ResolvedNode::RestoreParams& params) {
  if (proto.name().empty()) {
    return zetasql_base::InvalidArgumentErrorBuilder(ZETASQL_LOC)
           << "Tried to parse function with blank name: "
           << proto.DebugString();
  }

  const Constant* constant;
  const std::vector<std::string> path = absl::StrSplit(proto.name(), '.');
  ZETASQL_RETURN_IF_ERROR(params.catalog->FindConstant(path, &constant));
  return constant;
}

static zetasql_base::Status SaveToImpl(
    const Function* func,
    FileDescriptorSetMap* file_descriptor_set_map,
    FunctionRefProto* proto) {
  proto->set_name(func->FullName(true  /* include_group */));
  return ::zetasql_base::OkStatus();
}

static zetasql_base::StatusOr<const Function*> RestoreFromImpl(
    const FunctionRefProto& proto,
    const ResolvedNode::RestoreParams& params) {
  // Serialized function names include the group. We do not need this to look
  // up a function in the catalog.
  const std::vector<absl::string_view> group_and_name =
      absl::StrSplit(proto.name(), ":");
  if (group_and_name.empty()) {
    return zetasql_base::InvalidArgumentErrorBuilder(ZETASQL_LOC)
        << "Tried to parse function with blank name: " << proto.DebugString();
  }

  const Function* func;
  const std::vector<std::string> path = absl::StrSplit(group_and_name.back(), '.');
  ZETASQL_RETURN_IF_ERROR(params.catalog->FindFunction(path, &func));
  return func;
}

static zetasql_base::Status SaveToImpl(
    const TableValuedFunction* func,
    FileDescriptorSetMap* file_descriptor_set_map,
    TableValuedFunctionRefProto* proto) {
  proto->set_name(func->FullName());
  return ::zetasql_base::OkStatus();
}

static zetasql_base::StatusOr<const TableValuedFunction*> RestoreFromImpl(
    const TableValuedFunctionRefProto& proto,
    const ResolvedNode::RestoreParams& params) {
  const TableValuedFunction* func;
  const std::vector<std::string> path = absl::StrSplit(proto.name(), '.');
  ZETASQL_RETURN_IF_ERROR(params.catalog->FindTableValuedFunction(path, &func));
  return func;
}

static zetasql_base::Status SaveToImpl(
    const Procedure* procedure,
    FileDescriptorSetMap* file_descriptor_set_map,
    ProcedureRefProto* proto) {
  proto->set_name(procedure->FullName());
  return ::zetasql_base::OkStatus();
}

static zetasql_base::StatusOr<const Procedure*> RestoreFromImpl(
    const ProcedureRefProto& proto,
    const ResolvedNode::RestoreParams& params) {
  const Procedure* procedure;
  const std::vector<std::string> path = absl::StrSplit(proto.name(), '.');
  ZETASQL_RETURN_IF_ERROR(params.catalog->FindProcedure(path, &procedure));
  return procedure;
}

static zetasql_base::Status SaveToImpl(
    const FunctionSignature& sig,
    FileDescriptorSetMap* file_descriptor_set_map,
    FunctionSignatureProto* proto) {
  return sig.Serialize(file_descriptor_set_map, proto);
}

static zetasql_base::StatusOr<FunctionSignature> RestoreFromImpl(
    const FunctionSignatureProto& proto,
    const ResolvedNode::RestoreParams& params) {
  // Some fields demand being set as FunctionSignature, not
  // std::unique_ptr<FunctionSignature>. It's fine if we just copy the returned
  // one though.
  std::unique_ptr<FunctionSignature> sig;
  ZETASQL_RETURN_IF_ERROR(FunctionSignature::Deserialize(
      proto, params.pools, params.type_factory, &sig));
  return *sig;
}

static zetasql_base::Status SaveToImpl(
    const Type* type,
    FileDescriptorSetMap* file_descriptor_set_map,
    TypeProto* proto) {
  return type->SerializeToProtoAndDistinctFileDescriptors(
      proto, file_descriptor_set_map);
}

static zetasql_base::StatusOr<const Type*> RestoreFromImpl(
    const TypeProto& proto,
    const ResolvedNode::RestoreParams& params) {
  const Type* type;
  ZETASQL_RETURN_IF_ERROR(params.type_factory->DeserializeFromProtoUsingExistingPools(
      proto, params.pools, &type));
  return type;
}

static zetasql_base::Status SaveToImpl(
    const google::protobuf::FieldDescriptor* desc,
    FileDescriptorSetMap* file_descriptor_set_map,
    FieldDescriptorRefProto* proto) {
  TypeFactory factory;
  const ProtoType* proto_type;
  ZETASQL_RETURN_IF_ERROR(factory.MakeProtoType(desc->containing_type(), &proto_type));
  TypeProto type_proto;
  ZETASQL_RETURN_IF_ERROR(proto_type->SerializeToProtoAndDistinctFileDescriptors(
      &type_proto, file_descriptor_set_map));
  *proto->mutable_containing_proto() = type_proto.proto_type();
  proto->set_number(desc->number());
  return ::zetasql_base::OkStatus();
}

static zetasql_base::StatusOr<const google::protobuf::FieldDescriptor*> RestoreFromImpl(
    const FieldDescriptorRefProto& proto,
    const ResolvedNode::RestoreParams& params) {
  TypeProto type_proto;
  type_proto.set_type_kind(TypeKind::TYPE_PROTO);
  *type_proto.mutable_proto_type() = proto.containing_proto();
  const Type* containing_type;
  ZETASQL_RETURN_IF_ERROR(params.type_factory->DeserializeFromProtoUsingExistingPools(
      type_proto, params.pools, &containing_type));
  const ProtoType* proto_type = containing_type->AsProto();
  if (!proto_type) {
    return zetasql_base::InvalidArgumentErrorBuilder(ZETASQL_LOC)
        << "Expected ProtoType, got: " << containing_type->DebugString();
  }
  const google::protobuf::FieldDescriptor* field_descriptor =
      proto_type->descriptor()->FindFieldByNumber(proto.number());
  if (field_descriptor) return field_descriptor;

  // Otherwise, let's look through the extensions and see if one of those match.
  for (const auto* pool : params.pools) {
    field_descriptor = pool->FindExtensionByNumber(proto_type->descriptor(),
                                                   proto.number());
    if (field_descriptor) return field_descriptor;
  }

  return zetasql_base::InvalidArgumentErrorBuilder(ZETASQL_LOC)
      << "Field number " << proto.number() << " is neither a field or a known "
      << "extension of " << proto_type->DebugString();
}

static zetasql_base::Status SaveToImpl(
    const ResolvedColumn& column,
    FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedColumnProto* proto) {
  return column.SaveTo(file_descriptor_set_map, proto);
}

static zetasql_base::StatusOr<ResolvedColumn> RestoreFromImpl(
    const ResolvedColumnProto& proto,
    const ResolvedNode::RestoreParams& params) {
  return ResolvedColumn::RestoreFrom(proto, params);
}

static zetasql_base::Status SaveToImpl(
    const Value& value,
    FileDescriptorSetMap* file_descriptor_set_map,
    ValueWithTypeProto* proto) {
  if (!value.is_valid()) {
    return ::zetasql_base::OkStatus();
  }
  ZETASQL_RETURN_IF_ERROR(value.Serialize(proto->mutable_value()));
  return SaveToImpl(
      value.type(), file_descriptor_set_map, proto->mutable_type());
}

static zetasql_base::StatusOr<Value> RestoreFromImpl(
    const ValueWithTypeProto& proto,
    const ResolvedNode::RestoreParams& params) {
  if (!proto.has_value()) {
    // The only way you get a blank value field is by serializing an invalid
    // value. So that's what we return if we see !has_value.
    return Value();
  }
  ZETASQL_ASSIGN_OR_RETURN(const Type* type, RestoreFromImpl(proto.type(), params));
  return Value::Deserialize(proto.value(), type);
}

static zetasql_base::Status SaveToImpl(
    const std::shared_ptr<TVFSignature>& tvf_signature,
    FileDescriptorSetMap* file_descriptor_set_map,
    TVFSignatureProto* proto) {
  for (const TVFInputArgumentType& arg : tvf_signature->input_arguments()) {
    TVFArgumentProto* arg_proto = proto->add_argument();
    if (arg.is_relation()) {
      for (const TVFRelation::Column& col : arg.relation().columns()) {
        TVFRelationColumnProto* col_proto =
            arg_proto->mutable_relation_argument()->add_column();
        col_proto->set_name(col.name);
        ZETASQL_RETURN_IF_ERROR(SaveToImpl(
            col.type, file_descriptor_set_map, col_proto->mutable_type()));
      }
      arg_proto->mutable_relation_argument()->set_is_value_table(
          arg.relation().is_value_table());
    } else if (arg.is_model()) {
      TVFModelProto* model_proto = arg_proto->mutable_model_argument();
      model_proto->set_name(arg.model().model()->Name());
      model_proto->set_full_name(arg.model().model()->FullName());
    } else {
      ZETASQL_ASSIGN_OR_RETURN(const InputArgumentType& arg_type,
                       arg.GetScalarArgType());
      ZETASQL_RETURN_IF_ERROR(SaveToImpl(
          arg_type.type(), file_descriptor_set_map,
          arg_proto->mutable_scalar_argument()->mutable_type()));
      if (arg_type.literal_value() != nullptr) {
        ZETASQL_RETURN_IF_ERROR(SaveToImpl(
            *arg_type.literal_value(), file_descriptor_set_map,
            arg_proto->mutable_scalar_argument()));
      }
    }
  }
  TVFRelationProto* output_schema_proto = proto->mutable_output_schema();
  for (const TVFRelation::Column& col :
           tvf_signature->result_schema().columns()) {
    TVFRelationColumnProto* col_proto = output_schema_proto->add_column();
    col_proto->set_name(col.name);
    col_proto->set_is_pseudo_column(col.is_pseudo_column);
    ZETASQL_RETURN_IF_ERROR(SaveToImpl(
        col.type, file_descriptor_set_map, col_proto->mutable_type()));
  }
  output_schema_proto->set_is_value_table(
      tvf_signature->result_schema().is_value_table());

  for (const FreestandingDeprecationWarning& warning :
           tvf_signature->options().additional_deprecation_warnings) {
    *proto->mutable_options()->add_additional_deprecation_warning() =
        warning;
  }

  return ::zetasql_base::OkStatus();
}

static zetasql_base::StatusOr<std::shared_ptr<TVFSignature>> RestoreFromImpl(
    const TVFSignatureProto& proto,
    const ResolvedNode::RestoreParams& params) {
  std::vector<TVFInputArgumentType> input_args;
  input_args.reserve(proto.argument_size());
  for (const TVFArgumentProto& argument : proto.argument()) {
    if (argument.has_relation_argument()) {
      const TVFRelationProto& relation_arg = argument.relation_argument();
      std::vector<TVFRelation::Column> cols;
      cols.reserve(relation_arg.column_size());
      const Type* type = nullptr;
      for (const TVFRelationColumnProto& col_proto : relation_arg.column()) {
        ZETASQL_ASSIGN_OR_RETURN(type, RestoreFromImpl(col_proto.type(), params));
        cols.emplace_back(TVFRelation::Column(col_proto.name(), type));
      }
      if (relation_arg.is_value_table()) {
        input_args.push_back(TVFInputArgumentType(
            TVFRelation::ValueTable(type)));
      } else {
        input_args.push_back(TVFInputArgumentType(TVFRelation(cols)));
      }
    } else if (argument.has_model_argument()) {
      const Model* model;
      const std::vector<std::string> path = absl::StrSplit(
        argument.model_argument().full_name(), '.');
      ZETASQL_RETURN_IF_ERROR(params.catalog->FindModel(path, &model));
      input_args.push_back(TVFInputArgumentType(TVFModelArgument(
        model)));
    } else {
      const ValueWithTypeProto& scalar_arg = argument.scalar_argument();
      if (scalar_arg.has_value()) {
        ZETASQL_ASSIGN_OR_RETURN(const Value value,
                         RestoreFromImpl(scalar_arg, params));
        input_args.push_back(TVFInputArgumentType(InputArgumentType(value)));
      } else {
        ZETASQL_ASSIGN_OR_RETURN(const Type* type,
                         RestoreFromImpl(scalar_arg.type(), params));
        input_args.push_back(TVFInputArgumentType(InputArgumentType(type)));
      }
    }
  }
  std::vector<TVFRelation::Column> cols;
  cols.reserve(proto.output_schema().column_size());
  const Type* type = nullptr;
  for (const TVFRelationColumnProto& col_proto :
       proto.output_schema().column()) {
    ZETASQL_ASSIGN_OR_RETURN(type, RestoreFromImpl(col_proto.type(), params));
    cols.emplace_back(TVFRelation::Column(col_proto.name(), type,
                                          col_proto.is_pseudo_column()));
  }

  TVFSignatureOptions options;
  for (const FreestandingDeprecationWarning& warning :
           proto.options().additional_deprecation_warning()) {
    options.additional_deprecation_warnings.push_back(warning);
  }

  if (proto.output_schema().is_value_table()) {
    const Type* type = cols[0].type;
    cols.erase(cols.begin());
    ZETASQL_ASSIGN_OR_RETURN(TVFRelation table_schema,
                     TVFRelation::ValueTable(type, cols));
    return std::shared_ptr<TVFSignature>(
        new TVFSignature(input_args, std::move(table_schema), options));
  } else {
    return std::shared_ptr<TVFSignature>(
        new TVFSignature(input_args, TVFRelation(cols), options));
  }
}

static zetasql_base::Status SaveToImpl(
    const std::shared_ptr<ResolvedFunctionCallInfo>& context,
    FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedFunctionCallInfoProto* proto) {
  // TODO: Implement this for ResolvedFunctionCallInfo subclasses.
  return ::zetasql_base::OkStatus();
}

static zetasql_base::StatusOr<std::shared_ptr<ResolvedFunctionCallInfo>>
    RestoreFromImpl(
        const ResolvedFunctionCallInfoProto& proto,
        const ResolvedNode::RestoreParams& params) {
  // TODO: Implement this for ResolvedFunctionCallInfo subclasses.
  return std::shared_ptr<ResolvedFunctionCallInfo>(
      new ResolvedFunctionCallInfo());
}

}  // anonymous namespace

// This is defined separately from the rest of the RestoreFrom implementations
// because the root node does not have a proper entry in the tree generated in
// gen_resolved_ast.py, so we have to iterate the nodes in a different way.
zetasql_base::StatusOr<std::unique_ptr<ResolvedNode>> ResolvedNode::RestoreFrom(
    const AnyResolvedNodeProto& proto, const RestoreParams& params) {
  switch (proto.node_case()) {
    case AnyResolvedNodeProto::kResolvedArgumentNode:
      return ResolvedArgument::RestoreFrom(
          proto.resolved_argument_node(), params);
    case AnyResolvedNodeProto::kResolvedExprNode:
      return ResolvedExpr::RestoreFrom(
          proto.resolved_expr_node(), params);
    case AnyResolvedNodeProto::kResolvedScanNode:
      return ResolvedScan::RestoreFrom(
          proto.resolved_scan_node(), params);
    case AnyResolvedNodeProto::kResolvedStatementNode:
      return ResolvedStatement::RestoreFrom(
          proto.resolved_statement_node(), params);
    case AnyResolvedNodeProto::NODE_NOT_SET:
      return ::zetasql_base::InvalidArgumentErrorBuilder(ZETASQL_LOC)
          << "No subnode types set in AnyResolvedNodeProto";
  }
}

std::string ResolvedNodeKindToString(ResolvedNodeKind kind) {
  switch (kind) {
    case RESOLVED_LITERAL: return "Literal";
    case RESOLVED_PARAMETER: return "Parameter";
    case RESOLVED_EXPRESSION_COLUMN: return "ExpressionColumn";
    case RESOLVED_COLUMN_REF: return "ColumnRef";
    case RESOLVED_CONSTANT: return "Constant";
    case RESOLVED_FUNCTION_CALL: return "FunctionCall";
    case RESOLVED_AGGREGATE_FUNCTION_CALL: return "AggregateFunctionCall";
    case RESOLVED_ANALYTIC_FUNCTION_CALL: return "AnalyticFunctionCall";
    case RESOLVED_CAST: return "Cast";
    case RESOLVED_MAKE_STRUCT: return "MakeStruct";
    case RESOLVED_MAKE_PROTO: return "MakeProto";
    case RESOLVED_MAKE_PROTO_FIELD: return "MakeProtoField";
    case RESOLVED_GET_STRUCT_FIELD: return "GetStructField";
    case RESOLVED_GET_PROTO_FIELD: return "GetProtoField";
    case RESOLVED_SUBQUERY_EXPR: return "SubqueryExpr";
    case RESOLVED_MODEL: return "Model";
    case RESOLVED_SINGLE_ROW_SCAN: return "SingleRowScan";
    case RESOLVED_TABLE_SCAN: return "TableScan";
    case RESOLVED_JOIN_SCAN: return "JoinScan";
    case RESOLVED_ARRAY_SCAN: return "ArrayScan";
    case RESOLVED_COLUMN_HOLDER: return "ColumnHolder";
    case RESOLVED_FILTER_SCAN: return "FilterScan";
    case RESOLVED_GROUPING_SET: return "GroupingSet";
    case RESOLVED_AGGREGATE_SCAN: return "AggregateScan";
    case RESOLVED_SET_OPERATION_ITEM: return "SetOperationItem";
    case RESOLVED_SET_OPERATION_SCAN: return "SetOperationScan";
    case RESOLVED_ORDER_BY_SCAN: return "OrderByScan";
    case RESOLVED_LIMIT_OFFSET_SCAN: return "LimitOffsetScan";
    case RESOLVED_WITH_REF_SCAN: return "WithRefScan";
    case RESOLVED_ANALYTIC_SCAN: return "AnalyticScan";
    case RESOLVED_SAMPLE_SCAN: return "SampleScan";
    case RESOLVED_COMPUTED_COLUMN: return "ComputedColumn";
    case RESOLVED_ORDER_BY_ITEM: return "OrderByItem";
    case RESOLVED_COLUMN_ANNOTATIONS: return "ColumnAnnotations";
    case RESOLVED_GENERATED_COLUMN_INFO: return "GeneratedColumnInfo";
    case RESOLVED_COLUMN_DEFINITION: return "ColumnDefinition";
    case RESOLVED_PRIMARY_KEY: return "PrimaryKey";
    case RESOLVED_FOREIGN_KEY: return "ForeignKey";
    case RESOLVED_CHECK_CONSTRAINT: return "CheckConstraint";
    case RESOLVED_OUTPUT_COLUMN: return "OutputColumn";
    case RESOLVED_PROJECT_SCAN: return "ProjectScan";
    case RESOLVED_TVFSCAN: return "TVFScan";
    case RESOLVED_TVFARGUMENT: return "TVFArgument";
    case RESOLVED_EXPLAIN_STMT: return "ExplainStmt";
    case RESOLVED_QUERY_STMT: return "QueryStmt";
    case RESOLVED_CREATE_DATABASE_STMT: return "CreateDatabaseStmt";
    case RESOLVED_INDEX_ITEM: return "IndexItem";
    case RESOLVED_UNNEST_ITEM: return "UnnestItem";
    case RESOLVED_CREATE_INDEX_STMT: return "CreateIndexStmt";
    case RESOLVED_CREATE_TABLE_STMT: return "CreateTableStmt";
    case RESOLVED_CREATE_TABLE_AS_SELECT_STMT: return "CreateTableAsSelectStmt";
    case RESOLVED_CREATE_MODEL_STMT: return "CreateModelStmt";
    case RESOLVED_CREATE_VIEW_STMT: return "CreateViewStmt";
    case RESOLVED_CREATE_EXTERNAL_TABLE_STMT: return "CreateExternalTableStmt";
    case RESOLVED_EXPORT_DATA_STMT: return "ExportDataStmt";
    case RESOLVED_DEFINE_TABLE_STMT: return "DefineTableStmt";
    case RESOLVED_DESCRIBE_STMT: return "DescribeStmt";
    case RESOLVED_SHOW_STMT: return "ShowStmt";
    case RESOLVED_BEGIN_STMT: return "BeginStmt";
    case RESOLVED_SET_TRANSACTION_STMT: return "SetTransactionStmt";
    case RESOLVED_COMMIT_STMT: return "CommitStmt";
    case RESOLVED_ROLLBACK_STMT: return "RollbackStmt";
    case RESOLVED_START_BATCH_STMT: return "StartBatchStmt";
    case RESOLVED_RUN_BATCH_STMT: return "RunBatchStmt";
    case RESOLVED_ABORT_BATCH_STMT: return "AbortBatchStmt";
    case RESOLVED_DROP_STMT: return "DropStmt";
    case RESOLVED_DROP_MATERIALIZED_VIEW_STMT: return "DropMaterializedViewStmt";
    case RESOLVED_WITH_SCAN: return "WithScan";
    case RESOLVED_WITH_ENTRY: return "WithEntry";
    case RESOLVED_OPTION: return "Option";
    case RESOLVED_WINDOW_PARTITIONING: return "WindowPartitioning";
    case RESOLVED_WINDOW_ORDERING: return "WindowOrdering";
    case RESOLVED_WINDOW_FRAME: return "WindowFrame";
    case RESOLVED_ANALYTIC_FUNCTION_GROUP: return "AnalyticFunctionGroup";
    case RESOLVED_WINDOW_FRAME_EXPR: return "WindowFrameExpr";
    case RESOLVED_DMLVALUE: return "DMLValue";
    case RESOLVED_DMLDEFAULT: return "DMLDefault";
    case RESOLVED_ASSERT_STMT: return "AssertStmt";
    case RESOLVED_ASSERT_ROWS_MODIFIED: return "AssertRowsModified";
    case RESOLVED_INSERT_ROW: return "InsertRow";
    case RESOLVED_INSERT_STMT: return "InsertStmt";
    case RESOLVED_DELETE_STMT: return "DeleteStmt";
    case RESOLVED_UPDATE_ITEM: return "UpdateItem";
    case RESOLVED_UPDATE_ARRAY_ITEM: return "UpdateArrayItem";
    case RESOLVED_UPDATE_STMT: return "UpdateStmt";
    case RESOLVED_MERGE_WHEN: return "MergeWhen";
    case RESOLVED_MERGE_STMT: return "MergeStmt";
    case RESOLVED_PRIVILEGE: return "Privilege";
    case RESOLVED_GRANT_STMT: return "GrantStmt";
    case RESOLVED_REVOKE_STMT: return "RevokeStmt";
    case RESOLVED_ALTER_MATERIALIZED_VIEW_STMT: return "AlterMaterializedViewStmt";
    case RESOLVED_ALTER_TABLE_STMT: return "AlterTableStmt";
    case RESOLVED_ALTER_VIEW_STMT: return "AlterViewStmt";
    case RESOLVED_SET_OPTIONS_ACTION: return "SetOptionsAction";
    case RESOLVED_ALTER_TABLE_SET_OPTIONS_STMT: return "AlterTableSetOptionsStmt";
    case RESOLVED_RENAME_STMT: return "RenameStmt";
    case RESOLVED_CREATE_ROW_POLICY_STMT: return "CreateRowPolicyStmt";
    case RESOLVED_DROP_ROW_POLICY_STMT: return "DropRowPolicyStmt";
    case RESOLVED_ALTER_ROW_POLICY_STMT: return "AlterRowPolicyStmt";
    case RESOLVED_CREATE_CONSTANT_STMT: return "CreateConstantStmt";
    case RESOLVED_CREATE_FUNCTION_STMT: return "CreateFunctionStmt";
    case RESOLVED_ARGUMENT_DEF: return "ArgumentDef";
    case RESOLVED_ARGUMENT_REF: return "ArgumentRef";
    case RESOLVED_CREATE_TABLE_FUNCTION_STMT: return "CreateTableFunctionStmt";
    case RESOLVED_RELATION_ARGUMENT_SCAN: return "RelationArgumentScan";
    case RESOLVED_ARGUMENT_LIST: return "ArgumentList";
    case RESOLVED_FUNCTION_SIGNATURE_HOLDER: return "FunctionSignatureHolder";
    case RESOLVED_DROP_FUNCTION_STMT: return "DropFunctionStmt";
    case RESOLVED_CALL_STMT: return "CallStmt";
    case RESOLVED_IMPORT_STMT: return "ImportStmt";
    case RESOLVED_MODULE_STMT: return "ModuleStmt";
    case RESOLVED_AGGREGATE_HAVING_MODIFIER: return "AggregateHavingModifier";
    case RESOLVED_CREATE_MATERIALIZED_VIEW_STMT: return "CreateMaterializedViewStmt";
    case RESOLVED_CREATE_PROCEDURE_STMT: return "CreateProcedureStmt";
    default:
      return absl::StrCat("INVALID_RESOLVED_NODE_KIND(", kind, ")");
  }
}

ResolvedArgument::~ResolvedArgument() {
}

zetasql_base::Status ResolvedArgument::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedNodeProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_argument_node());
}

zetasql_base::Status ResolvedArgument::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedArgumentProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedArgument>> ResolvedArgument::RestoreFrom(
    const AnyResolvedArgumentProto& proto,
    const ResolvedNode::RestoreParams& params) {
  switch (proto.node_case()) {
    case AnyResolvedArgumentProto::kResolvedMakeProtoFieldNode:
      return ResolvedMakeProtoField::RestoreFrom(
          proto.resolved_make_proto_field_node(), params);
    case AnyResolvedArgumentProto::kResolvedColumnHolderNode:
      return ResolvedColumnHolder::RestoreFrom(
          proto.resolved_column_holder_node(), params);
    case AnyResolvedArgumentProto::kResolvedComputedColumnNode:
      return ResolvedComputedColumn::RestoreFrom(
          proto.resolved_computed_column_node(), params);
    case AnyResolvedArgumentProto::kResolvedOrderByItemNode:
      return ResolvedOrderByItem::RestoreFrom(
          proto.resolved_order_by_item_node(), params);
    case AnyResolvedArgumentProto::kResolvedOutputColumnNode:
      return ResolvedOutputColumn::RestoreFrom(
          proto.resolved_output_column_node(), params);
    case AnyResolvedArgumentProto::kResolvedWithEntryNode:
      return ResolvedWithEntry::RestoreFrom(
          proto.resolved_with_entry_node(), params);
    case AnyResolvedArgumentProto::kResolvedOptionNode:
      return ResolvedOption::RestoreFrom(
          proto.resolved_option_node(), params);
    case AnyResolvedArgumentProto::kResolvedWindowPartitioningNode:
      return ResolvedWindowPartitioning::RestoreFrom(
          proto.resolved_window_partitioning_node(), params);
    case AnyResolvedArgumentProto::kResolvedWindowOrderingNode:
      return ResolvedWindowOrdering::RestoreFrom(
          proto.resolved_window_ordering_node(), params);
    case AnyResolvedArgumentProto::kResolvedWindowFrameNode:
      return ResolvedWindowFrame::RestoreFrom(
          proto.resolved_window_frame_node(), params);
    case AnyResolvedArgumentProto::kResolvedAnalyticFunctionGroupNode:
      return ResolvedAnalyticFunctionGroup::RestoreFrom(
          proto.resolved_analytic_function_group_node(), params);
    case AnyResolvedArgumentProto::kResolvedWindowFrameExprNode:
      return ResolvedWindowFrameExpr::RestoreFrom(
          proto.resolved_window_frame_expr_node(), params);
    case AnyResolvedArgumentProto::kResolvedDmlvalueNode:
      return ResolvedDMLValue::RestoreFrom(
          proto.resolved_dmlvalue_node(), params);
    case AnyResolvedArgumentProto::kResolvedAssertRowsModifiedNode:
      return ResolvedAssertRowsModified::RestoreFrom(
          proto.resolved_assert_rows_modified_node(), params);
    case AnyResolvedArgumentProto::kResolvedInsertRowNode:
      return ResolvedInsertRow::RestoreFrom(
          proto.resolved_insert_row_node(), params);
    case AnyResolvedArgumentProto::kResolvedUpdateItemNode:
      return ResolvedUpdateItem::RestoreFrom(
          proto.resolved_update_item_node(), params);
    case AnyResolvedArgumentProto::kResolvedPrivilegeNode:
      return ResolvedPrivilege::RestoreFrom(
          proto.resolved_privilege_node(), params);
    case AnyResolvedArgumentProto::kResolvedArgumentDefNode:
      return ResolvedArgumentDef::RestoreFrom(
          proto.resolved_argument_def_node(), params);
    case AnyResolvedArgumentProto::kResolvedArgumentListNode:
      return ResolvedArgumentList::RestoreFrom(
          proto.resolved_argument_list_node(), params);
    case AnyResolvedArgumentProto::kResolvedTvfargumentNode:
      return ResolvedTVFArgument::RestoreFrom(
          proto.resolved_tvfargument_node(), params);
    case AnyResolvedArgumentProto::kResolvedFunctionSignatureHolderNode:
      return ResolvedFunctionSignatureHolder::RestoreFrom(
          proto.resolved_function_signature_holder_node(), params);
    case AnyResolvedArgumentProto::kResolvedAggregateHavingModifierNode:
      return ResolvedAggregateHavingModifier::RestoreFrom(
          proto.resolved_aggregate_having_modifier_node(), params);
    case AnyResolvedArgumentProto::kResolvedColumnDefinitionNode:
      return ResolvedColumnDefinition::RestoreFrom(
          proto.resolved_column_definition_node(), params);
    case AnyResolvedArgumentProto::kResolvedPrimaryKeyNode:
      return ResolvedPrimaryKey::RestoreFrom(
          proto.resolved_primary_key_node(), params);
    case AnyResolvedArgumentProto::kResolvedGroupingSetNode:
      return ResolvedGroupingSet::RestoreFrom(
          proto.resolved_grouping_set_node(), params);
    case AnyResolvedArgumentProto::kResolvedSetOperationItemNode:
      return ResolvedSetOperationItem::RestoreFrom(
          proto.resolved_set_operation_item_node(), params);
    case AnyResolvedArgumentProto::kResolvedIndexItemNode:
      return ResolvedIndexItem::RestoreFrom(
          proto.resolved_index_item_node(), params);
    case AnyResolvedArgumentProto::kResolvedMergeWhenNode:
      return ResolvedMergeWhen::RestoreFrom(
          proto.resolved_merge_when_node(), params);
    case AnyResolvedArgumentProto::kResolvedUpdateArrayItemNode:
      return ResolvedUpdateArrayItem::RestoreFrom(
          proto.resolved_update_array_item_node(), params);
    case AnyResolvedArgumentProto::kResolvedColumnAnnotationsNode:
      return ResolvedColumnAnnotations::RestoreFrom(
          proto.resolved_column_annotations_node(), params);
    case AnyResolvedArgumentProto::kResolvedGeneratedColumnInfoNode:
      return ResolvedGeneratedColumnInfo::RestoreFrom(
          proto.resolved_generated_column_info_node(), params);
    case AnyResolvedArgumentProto::kResolvedModelNode:
      return ResolvedModel::RestoreFrom(
          proto.resolved_model_node(), params);
    case AnyResolvedArgumentProto::kResolvedForeignKeyNode:
      return ResolvedForeignKey::RestoreFrom(
          proto.resolved_foreign_key_node(), params);
    case AnyResolvedArgumentProto::kResolvedCheckConstraintNode:
      return ResolvedCheckConstraint::RestoreFrom(
          proto.resolved_check_constraint_node(), params);
    case AnyResolvedArgumentProto::kResolvedAlterActionNode:
      return ResolvedAlterAction::RestoreFrom(
          proto.resolved_alter_action_node(), params);
    case AnyResolvedArgumentProto::kResolvedUnnestItemNode:
      return ResolvedUnnestItem::RestoreFrom(
          proto.resolved_unnest_item_node(), params);
  case AnyResolvedArgumentProto::NODE_NOT_SET:
    return ::zetasql_base::InvalidArgumentErrorBuilder(ZETASQL_LOC)
        << "No subnode types set in ResolvedArgumentProto";
  }
}

zetasql_base::Status ResolvedArgument::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedArgument(this);
}

zetasql_base::Status ResolvedArgument::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  return ::zetasql_base::OkStatus();
}

ResolvedExpr::~ResolvedExpr() {
}

zetasql_base::Status ResolvedExpr::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedNodeProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_expr_node());
}

zetasql_base::Status ResolvedExpr::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedExprProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  ZETASQL_RETURN_IF_ERROR(SaveToImpl(
      type_, file_descriptor_set_map,
      proto->mutable_type()));
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedExpr>> ResolvedExpr::RestoreFrom(
    const AnyResolvedExprProto& proto,
    const ResolvedNode::RestoreParams& params) {
  switch (proto.node_case()) {
    case AnyResolvedExprProto::kResolvedLiteralNode:
      return ResolvedLiteral::RestoreFrom(
          proto.resolved_literal_node(), params);
    case AnyResolvedExprProto::kResolvedParameterNode:
      return ResolvedParameter::RestoreFrom(
          proto.resolved_parameter_node(), params);
    case AnyResolvedExprProto::kResolvedExpressionColumnNode:
      return ResolvedExpressionColumn::RestoreFrom(
          proto.resolved_expression_column_node(), params);
    case AnyResolvedExprProto::kResolvedColumnRefNode:
      return ResolvedColumnRef::RestoreFrom(
          proto.resolved_column_ref_node(), params);
    case AnyResolvedExprProto::kResolvedFunctionCallBaseNode:
      return ResolvedFunctionCallBase::RestoreFrom(
          proto.resolved_function_call_base_node(), params);
    case AnyResolvedExprProto::kResolvedCastNode:
      return ResolvedCast::RestoreFrom(
          proto.resolved_cast_node(), params);
    case AnyResolvedExprProto::kResolvedMakeStructNode:
      return ResolvedMakeStruct::RestoreFrom(
          proto.resolved_make_struct_node(), params);
    case AnyResolvedExprProto::kResolvedMakeProtoNode:
      return ResolvedMakeProto::RestoreFrom(
          proto.resolved_make_proto_node(), params);
    case AnyResolvedExprProto::kResolvedGetStructFieldNode:
      return ResolvedGetStructField::RestoreFrom(
          proto.resolved_get_struct_field_node(), params);
    case AnyResolvedExprProto::kResolvedGetProtoFieldNode:
      return ResolvedGetProtoField::RestoreFrom(
          proto.resolved_get_proto_field_node(), params);
    case AnyResolvedExprProto::kResolvedSubqueryExprNode:
      return ResolvedSubqueryExpr::RestoreFrom(
          proto.resolved_subquery_expr_node(), params);
    case AnyResolvedExprProto::kResolvedDmldefaultNode:
      return ResolvedDMLDefault::RestoreFrom(
          proto.resolved_dmldefault_node(), params);
    case AnyResolvedExprProto::kResolvedArgumentRefNode:
      return ResolvedArgumentRef::RestoreFrom(
          proto.resolved_argument_ref_node(), params);
    case AnyResolvedExprProto::kResolvedConstantNode:
      return ResolvedConstant::RestoreFrom(
          proto.resolved_constant_node(), params);
  case AnyResolvedExprProto::NODE_NOT_SET:
    return ::zetasql_base::InvalidArgumentErrorBuilder(ZETASQL_LOC)
        << "No subnode types set in ResolvedExprProto";
  }
}

void ResolvedExpr::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
}

void ResolvedExpr::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
}

zetasql_base::Status ResolvedExpr::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedExpr(this);
}

zetasql_base::Status ResolvedExpr::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  return ::zetasql_base::OkStatus();
}

void ResolvedExpr::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  if (!IsDefaultValue(type_)) {
    fields->emplace_back("type", ToStringImpl(type_));
  }
}

zetasql_base::Status ResolvedExpr::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  return ::zetasql_base::OkStatus();
}

void ResolvedExpr::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
}

const ResolvedNodeKind ResolvedLiteral::TYPE;

ResolvedLiteral::~ResolvedLiteral() {
}

zetasql_base::Status ResolvedLiteral::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedExprProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_literal_node());
}

zetasql_base::Status ResolvedLiteral::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedLiteralProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  ZETASQL_RETURN_IF_ERROR(SaveToImpl(
      value_, file_descriptor_set_map,
      proto->mutable_value()));
  proto->set_has_explicit_type(has_explicit_type_);
  proto->set_float_literal_id(float_literal_id_);
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedLiteral>> ResolvedLiteral::RestoreFrom(
    const ResolvedLiteralProto& proto,
    const ResolvedNode::RestoreParams& params) {
  ZETASQL_ASSIGN_OR_RETURN(Value value,
                   RestoreFromImpl(proto.value(),
                                   params));
  bool has_explicit_type =
      proto.has_explicit_type();
  int float_literal_id =
      proto.float_literal_id();
  ZETASQL_ASSIGN_OR_RETURN(const Type* type,
                   RestoreFromImpl(proto.parent().type(),
                                   params));
  auto node = MakeResolvedLiteral(
      std::move(type),
      std::move(value),
      std::move(has_explicit_type),
      std::move(float_literal_id));

  return std::move(node);
}

void ResolvedLiteral::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
}

void ResolvedLiteral::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
}

zetasql_base::Status ResolvedLiteral::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedLiteral(this);
}

zetasql_base::Status ResolvedLiteral::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  return ::zetasql_base::OkStatus();
}

void ResolvedLiteral::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  {
    fields->emplace_back("value", ToStringImpl(value_));
  }
  if (!IsDefaultValue(has_explicit_type_)) {
    fields->emplace_back("has_explicit_type", ToStringImpl(has_explicit_type_));
  }
  if (!IsDefaultValue(float_literal_id_)) {
    fields->emplace_back("float_literal_id", ToStringImpl(float_literal_id_));
  }
}

zetasql_base::Status ResolvedLiteral::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedLiteral::value not accessed)";
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedLiteral::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
}

const ResolvedNodeKind ResolvedParameter::TYPE;

ResolvedParameter::~ResolvedParameter() {
}

zetasql_base::Status ResolvedParameter::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedExprProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_parameter_node());
}

zetasql_base::Status ResolvedParameter::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedParameterProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  proto->set_name(name_);
  proto->set_position(position_);
  proto->set_is_untyped(is_untyped_);
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedParameter>> ResolvedParameter::RestoreFrom(
    const ResolvedParameterProto& proto,
    const ResolvedNode::RestoreParams& params) {
  std::string name =
      proto.name();
  int position =
      proto.position();
  bool is_untyped =
      proto.is_untyped();
  ZETASQL_ASSIGN_OR_RETURN(const Type* type,
                   RestoreFromImpl(proto.parent().type(),
                                   params));
  auto node = MakeResolvedParameter(
      std::move(type),
      std::move(name),
      std::move(position),
      std::move(is_untyped));

  return std::move(node);
}

void ResolvedParameter::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
}

void ResolvedParameter::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
}

zetasql_base::Status ResolvedParameter::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedParameter(this);
}

zetasql_base::Status ResolvedParameter::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  return ::zetasql_base::OkStatus();
}

void ResolvedParameter::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  if (!IsDefaultValue(name_)) {
    fields->emplace_back("name", ToStringImpl(name_));
  }
  if (!IsDefaultValue(position_)) {
    fields->emplace_back("position", ToStringImpl(position_));
  }
  if (!IsDefaultValue(is_untyped_)) {
    fields->emplace_back("is_untyped", ToStringImpl(is_untyped_));
  }
}

zetasql_base::Status ResolvedParameter::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0 &&
      !IsDefaultValue(name_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedParameter::name not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<1)) == 0 &&
      !IsDefaultValue(position_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedParameter::position not accessed "
           "and has non-default value)";
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedParameter::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
}

const ResolvedNodeKind ResolvedExpressionColumn::TYPE;

ResolvedExpressionColumn::~ResolvedExpressionColumn() {
}

zetasql_base::Status ResolvedExpressionColumn::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedExprProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_expression_column_node());
}

zetasql_base::Status ResolvedExpressionColumn::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedExpressionColumnProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  proto->set_name(name_);
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedExpressionColumn>> ResolvedExpressionColumn::RestoreFrom(
    const ResolvedExpressionColumnProto& proto,
    const ResolvedNode::RestoreParams& params) {
  std::string name =
      proto.name();
  ZETASQL_ASSIGN_OR_RETURN(const Type* type,
                   RestoreFromImpl(proto.parent().type(),
                                   params));
  auto node = MakeResolvedExpressionColumn(
      std::move(type),
      std::move(name));

  return std::move(node);
}

void ResolvedExpressionColumn::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
}

void ResolvedExpressionColumn::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
}

zetasql_base::Status ResolvedExpressionColumn::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedExpressionColumn(this);
}

zetasql_base::Status ResolvedExpressionColumn::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  return ::zetasql_base::OkStatus();
}

void ResolvedExpressionColumn::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  {
    fields->emplace_back("name", ToStringImpl(name_));
  }
}

zetasql_base::Status ResolvedExpressionColumn::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedExpressionColumn::name not accessed)";
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedExpressionColumn::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
}

const ResolvedNodeKind ResolvedColumnRef::TYPE;

ResolvedColumnRef::~ResolvedColumnRef() {
}

zetasql_base::Status ResolvedColumnRef::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedExprProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_column_ref_node());
}

zetasql_base::Status ResolvedColumnRef::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedColumnRefProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  ZETASQL_RETURN_IF_ERROR(SaveToImpl(
      column_, file_descriptor_set_map,
      proto->mutable_column()));
  proto->set_is_correlated(is_correlated_);
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedColumnRef>> ResolvedColumnRef::RestoreFrom(
    const ResolvedColumnRefProto& proto,
    const ResolvedNode::RestoreParams& params) {
  ZETASQL_ASSIGN_OR_RETURN(ResolvedColumn column,
                   RestoreFromImpl(proto.column(),
                                   params));
  bool is_correlated =
      proto.is_correlated();
  ZETASQL_ASSIGN_OR_RETURN(const Type* type,
                   RestoreFromImpl(proto.parent().type(),
                                   params));
  auto node = MakeResolvedColumnRef(
      std::move(type),
      std::move(column),
      std::move(is_correlated));

  return std::move(node);
}

void ResolvedColumnRef::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
}

void ResolvedColumnRef::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
}

zetasql_base::Status ResolvedColumnRef::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedColumnRef(this);
}

zetasql_base::Status ResolvedColumnRef::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  return ::zetasql_base::OkStatus();
}

void ResolvedColumnRef::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  {
    fields->emplace_back("column", ToStringImpl(column_));
  }
  if (!IsDefaultValue(is_correlated_)) {
    fields->emplace_back("is_correlated", ToStringImpl(is_correlated_));
  }
}

zetasql_base::Status ResolvedColumnRef::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedColumnRef::column not accessed)";
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedColumnRef::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
}

const ResolvedNodeKind ResolvedConstant::TYPE;

ResolvedConstant::~ResolvedConstant() {
}

zetasql_base::Status ResolvedConstant::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedExprProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_constant_node());
}

zetasql_base::Status ResolvedConstant::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedConstantProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  ZETASQL_RETURN_IF_ERROR(SaveToImpl(
      constant_, file_descriptor_set_map,
      proto->mutable_constant()));
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedConstant>> ResolvedConstant::RestoreFrom(
    const ResolvedConstantProto& proto,
    const ResolvedNode::RestoreParams& params) {
  ZETASQL_ASSIGN_OR_RETURN(const Constant* constant,
                   RestoreFromImpl(proto.constant(),
                                   params));
  ZETASQL_ASSIGN_OR_RETURN(const Type* type,
                   RestoreFromImpl(proto.parent().type(),
                                   params));
  auto node = MakeResolvedConstant(
      std::move(type),
      std::move(constant));

  return std::move(node);
}

void ResolvedConstant::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
}

void ResolvedConstant::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
}

zetasql_base::Status ResolvedConstant::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedConstant(this);
}

zetasql_base::Status ResolvedConstant::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  return ::zetasql_base::OkStatus();
}

zetasql_base::Status ResolvedConstant::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedConstant::constant not accessed)";
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedConstant::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
}

const ResolvedFunctionCallBase::ErrorMode ResolvedFunctionCallBase::DEFAULT_ERROR_MODE;
const ResolvedFunctionCallBase::ErrorMode ResolvedFunctionCallBase::SAFE_ERROR_MODE;

ResolvedFunctionCallBase::~ResolvedFunctionCallBase() {
}

zetasql_base::Status ResolvedFunctionCallBase::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedExprProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_function_call_base_node());
}

zetasql_base::Status ResolvedFunctionCallBase::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedFunctionCallBaseProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  ZETASQL_RETURN_IF_ERROR(SaveToImpl(
      function_, file_descriptor_set_map,
      proto->mutable_function()));
  ZETASQL_RETURN_IF_ERROR(SaveToImpl(
      signature_, file_descriptor_set_map,
      proto->mutable_signature()));
  for (const auto& elem : argument_list_) {
    ZETASQL_RETURN_IF_ERROR(elem->SaveTo(
      file_descriptor_set_map, proto->add_argument_list()));
  }
  proto->set_error_mode(error_mode_);
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedFunctionCallBase>> ResolvedFunctionCallBase::RestoreFrom(
    const AnyResolvedFunctionCallBaseProto& proto,
    const ResolvedNode::RestoreParams& params) {
  switch (proto.node_case()) {
    case AnyResolvedFunctionCallBaseProto::kResolvedFunctionCallNode:
      return ResolvedFunctionCall::RestoreFrom(
          proto.resolved_function_call_node(), params);
    case AnyResolvedFunctionCallBaseProto::kResolvedNonScalarFunctionCallBaseNode:
      return ResolvedNonScalarFunctionCallBase::RestoreFrom(
          proto.resolved_non_scalar_function_call_base_node(), params);
  case AnyResolvedFunctionCallBaseProto::NODE_NOT_SET:
    return ::zetasql_base::InvalidArgumentErrorBuilder(ZETASQL_LOC)
        << "No subnode types set in ResolvedFunctionCallBaseProto";
  }
}

void ResolvedFunctionCallBase::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
  for (const auto& elem : argument_list_) {
    child_nodes->emplace_back(elem.get());
  }
}

void ResolvedFunctionCallBase::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
  for (auto& elem : argument_list_) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(&elem));
  }
}

zetasql_base::Status ResolvedFunctionCallBase::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedFunctionCallBase(this);
}

zetasql_base::Status ResolvedFunctionCallBase::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  for (const auto& elem : argument_list_) {
    ZETASQL_RETURN_IF_ERROR(elem.get()->Accept(visitor));
  }
  return ::zetasql_base::OkStatus();
}

zetasql_base::Status ResolvedFunctionCallBase::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedFunctionCallBase::function not accessed)";
  }
  if ((accessed_ & (1<<2)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedFunctionCallBase::argument_list not accessed)";
  }
  if ((accessed_ & (1<<3)) == 0 &&
      !IsDefaultValue(error_mode_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedFunctionCallBase::error_mode not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<2)) != 0) {
    for (const auto& it : argument_list_) ZETASQL_RETURN_IF_ERROR(it->CheckFieldsAccessed());
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedFunctionCallBase::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
  for (const auto& it : argument_list_) it->ClearFieldsAccessed();
}

const ResolvedNodeKind ResolvedFunctionCall::TYPE;

ResolvedFunctionCall::~ResolvedFunctionCall() {
}

zetasql_base::Status ResolvedFunctionCall::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedFunctionCallBaseProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_function_call_node());
}

zetasql_base::Status ResolvedFunctionCall::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedFunctionCallProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  ZETASQL_RETURN_IF_ERROR(SaveToImpl(
      function_call_info_, file_descriptor_set_map,
      proto->mutable_function_call_info()));
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedFunctionCall>> ResolvedFunctionCall::RestoreFrom(
    const ResolvedFunctionCallProto& proto,
    const ResolvedNode::RestoreParams& params) {
  ZETASQL_ASSIGN_OR_RETURN(std::shared_ptr<ResolvedFunctionCallInfo> function_call_info,
                   RestoreFromImpl(proto.function_call_info(),
                                   params));
  ZETASQL_ASSIGN_OR_RETURN(const Type* type,
                   RestoreFromImpl(proto.parent().parent().type(),
                                   params));
  ZETASQL_ASSIGN_OR_RETURN(const Function* function,
                   RestoreFromImpl(proto.parent().function(),
                                   params));
  ZETASQL_ASSIGN_OR_RETURN(FunctionSignature signature,
                   RestoreFromImpl(proto.parent().signature(),
                                   params));
  std::vector<std::unique_ptr<const ResolvedExpr>> argument_list;
  for (const auto& elem : proto.parent().argument_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedExpr> elem_restored,
                     ResolvedExpr::RestoreFrom(elem, params));
    argument_list.push_back(std::move(elem_restored));
  }
  ErrorMode error_mode =
      proto.parent().error_mode();
  auto node = MakeResolvedFunctionCall(
      std::move(type),
      std::move(function),
      std::move(signature),
      std::move(argument_list),
      std::move(error_mode),
      std::move(function_call_info));

  return std::move(node);
}

void ResolvedFunctionCall::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
}

void ResolvedFunctionCall::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
}

zetasql_base::Status ResolvedFunctionCall::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedFunctionCall(this);
}

zetasql_base::Status ResolvedFunctionCall::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  return ::zetasql_base::OkStatus();
}

void ResolvedFunctionCall::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  if (!IsDefaultValue(function_call_info_)) {
    fields->emplace_back("function_call_info", ToStringImpl(function_call_info_));
  }
}

zetasql_base::Status ResolvedFunctionCall::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  return ::zetasql_base::OkStatus();
}

void ResolvedFunctionCall::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
}

const ResolvedNonScalarFunctionCallBase::NullHandlingModifier ResolvedNonScalarFunctionCallBase::DEFAULT_NULL_HANDLING;
const ResolvedNonScalarFunctionCallBase::NullHandlingModifier ResolvedNonScalarFunctionCallBase::IGNORE_NULLS;
const ResolvedNonScalarFunctionCallBase::NullHandlingModifier ResolvedNonScalarFunctionCallBase::RESPECT_NULLS;

ResolvedNonScalarFunctionCallBase::~ResolvedNonScalarFunctionCallBase() {
}

zetasql_base::Status ResolvedNonScalarFunctionCallBase::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedFunctionCallBaseProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_non_scalar_function_call_base_node());
}

zetasql_base::Status ResolvedNonScalarFunctionCallBase::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedNonScalarFunctionCallBaseProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  proto->set_distinct(distinct_);
  proto->set_null_handling_modifier(null_handling_modifier_);
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedNonScalarFunctionCallBase>> ResolvedNonScalarFunctionCallBase::RestoreFrom(
    const AnyResolvedNonScalarFunctionCallBaseProto& proto,
    const ResolvedNode::RestoreParams& params) {
  switch (proto.node_case()) {
    case AnyResolvedNonScalarFunctionCallBaseProto::kResolvedAggregateFunctionCallNode:
      return ResolvedAggregateFunctionCall::RestoreFrom(
          proto.resolved_aggregate_function_call_node(), params);
    case AnyResolvedNonScalarFunctionCallBaseProto::kResolvedAnalyticFunctionCallNode:
      return ResolvedAnalyticFunctionCall::RestoreFrom(
          proto.resolved_analytic_function_call_node(), params);
  case AnyResolvedNonScalarFunctionCallBaseProto::NODE_NOT_SET:
    return ::zetasql_base::InvalidArgumentErrorBuilder(ZETASQL_LOC)
        << "No subnode types set in ResolvedNonScalarFunctionCallBaseProto";
  }
}

void ResolvedNonScalarFunctionCallBase::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
}

void ResolvedNonScalarFunctionCallBase::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
}

zetasql_base::Status ResolvedNonScalarFunctionCallBase::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedNonScalarFunctionCallBase(this);
}

zetasql_base::Status ResolvedNonScalarFunctionCallBase::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  return ::zetasql_base::OkStatus();
}

void ResolvedNonScalarFunctionCallBase::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  if (!IsDefaultValue(distinct_)) {
    fields->emplace_back("distinct", ToStringImpl(distinct_));
  }
  if (!IsDefaultValue(null_handling_modifier_)) {
    fields->emplace_back("null_handling_modifier", ToStringImpl(null_handling_modifier_));
  }
}

zetasql_base::Status ResolvedNonScalarFunctionCallBase::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0 &&
      !IsDefaultValue(distinct_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedNonScalarFunctionCallBase::distinct not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<1)) == 0 &&
      !IsDefaultValue(null_handling_modifier_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedNonScalarFunctionCallBase::null_handling_modifier not accessed "
           "and has non-default value)";
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedNonScalarFunctionCallBase::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
}

const ResolvedNodeKind ResolvedAggregateFunctionCall::TYPE;

ResolvedAggregateFunctionCall::~ResolvedAggregateFunctionCall() {
}

zetasql_base::Status ResolvedAggregateFunctionCall::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedNonScalarFunctionCallBaseProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_aggregate_function_call_node());
}

zetasql_base::Status ResolvedAggregateFunctionCall::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedAggregateFunctionCallProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  if (having_modifier_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(having_modifier_->SaveTo(
        file_descriptor_set_map, proto->mutable_having_modifier()));
  }
  for (const auto& elem : order_by_item_list_) {
    ZETASQL_RETURN_IF_ERROR(elem->SaveTo(
      file_descriptor_set_map, proto->add_order_by_item_list()));
  }
  if (limit_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(limit_->SaveTo(
        file_descriptor_set_map, proto->mutable_limit()));
  }
  ZETASQL_RETURN_IF_ERROR(SaveToImpl(
      function_call_info_, file_descriptor_set_map,
      proto->mutable_function_call_info()));
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedAggregateFunctionCall>> ResolvedAggregateFunctionCall::RestoreFrom(
    const ResolvedAggregateFunctionCallProto& proto,
    const ResolvedNode::RestoreParams& params) {
  std::unique_ptr<const ResolvedAggregateHavingModifier> having_modifier;
  if (proto.
  has_having_modifier()) {
    ZETASQL_ASSIGN_OR_RETURN(having_modifier,
                     ResolvedAggregateHavingModifier::RestoreFrom(
                         proto.having_modifier(), params));
  }
  std::vector<std::unique_ptr<const ResolvedOrderByItem>> order_by_item_list;
  for (const auto& elem : proto.order_by_item_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedOrderByItem> elem_restored,
                     ResolvedOrderByItem::RestoreFrom(elem, params));
    order_by_item_list.push_back(std::move(elem_restored));
  }
  std::unique_ptr<const ResolvedExpr> limit;
  if (proto.
  has_limit()) {
    ZETASQL_ASSIGN_OR_RETURN(limit,
                     ResolvedExpr::RestoreFrom(
                         proto.limit(), params));
  }
  ZETASQL_ASSIGN_OR_RETURN(std::shared_ptr<ResolvedFunctionCallInfo> function_call_info,
                   RestoreFromImpl(proto.function_call_info(),
                                   params));
  ZETASQL_ASSIGN_OR_RETURN(const Type* type,
                   RestoreFromImpl(proto.parent().parent().parent().type(),
                                   params));
  ZETASQL_ASSIGN_OR_RETURN(const Function* function,
                   RestoreFromImpl(proto.parent().parent().function(),
                                   params));
  ZETASQL_ASSIGN_OR_RETURN(FunctionSignature signature,
                   RestoreFromImpl(proto.parent().parent().signature(),
                                   params));
  std::vector<std::unique_ptr<const ResolvedExpr>> argument_list;
  for (const auto& elem : proto.parent().parent().argument_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedExpr> elem_restored,
                     ResolvedExpr::RestoreFrom(elem, params));
    argument_list.push_back(std::move(elem_restored));
  }
  ErrorMode error_mode =
      proto.parent().parent().error_mode();
  bool distinct =
      proto.parent().distinct();
  NullHandlingModifier null_handling_modifier =
      proto.parent().null_handling_modifier();
  auto node = MakeResolvedAggregateFunctionCall(
      std::move(type),
      std::move(function),
      std::move(signature),
      std::move(argument_list),
      std::move(error_mode),
      std::move(distinct),
      std::move(null_handling_modifier),
      std::move(having_modifier),
      std::move(order_by_item_list),
      std::move(limit),
      std::move(function_call_info));

  return std::move(node);
}

void ResolvedAggregateFunctionCall::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
  if (having_modifier_ != nullptr) {
    child_nodes->emplace_back(having_modifier_.get());
  }
  for (const auto& elem : order_by_item_list_) {
    child_nodes->emplace_back(elem.get());
  }
  if (limit_ != nullptr) {
    child_nodes->emplace_back(limit_.get());
  }
}

void ResolvedAggregateFunctionCall::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
  if (having_modifier_ != nullptr) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(
            &having_modifier_));
    static_assert(sizeof(having_modifier_) ==
                  sizeof(*(mutable_child_node_ptrs->back())),
                  "Incorrect casting of mutable child node");
  }
  for (auto& elem : order_by_item_list_) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(&elem));
  }
  if (limit_ != nullptr) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(
            &limit_));
    static_assert(sizeof(limit_) ==
                  sizeof(*(mutable_child_node_ptrs->back())),
                  "Incorrect casting of mutable child node");
  }
}

zetasql_base::Status ResolvedAggregateFunctionCall::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedAggregateFunctionCall(this);
}

zetasql_base::Status ResolvedAggregateFunctionCall::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  if (having_modifier_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(having_modifier_.get()->Accept(visitor));
  }
  for (const auto& elem : order_by_item_list_) {
    ZETASQL_RETURN_IF_ERROR(elem.get()->Accept(visitor));
  }
  if (limit_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(limit_.get()->Accept(visitor));
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedAggregateFunctionCall::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  if (having_modifier_ != nullptr) {
    fields->emplace_back("having_modifier", having_modifier_.get());
  }
  if (!order_by_item_list_.empty()) {
    fields->emplace_back("order_by_item_list", order_by_item_list_);
  }
  if (limit_ != nullptr) {
    fields->emplace_back("limit", limit_.get());
  }
  if (!IsDefaultValue(function_call_info_)) {
    fields->emplace_back("function_call_info", ToStringImpl(function_call_info_));
  }
}

zetasql_base::Status ResolvedAggregateFunctionCall::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0 &&
      !IsDefaultValue(having_modifier_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedAggregateFunctionCall::having_modifier not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<1)) == 0 &&
      !IsDefaultValue(order_by_item_list_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedAggregateFunctionCall::order_by_item_list not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<2)) == 0 &&
      !IsDefaultValue(limit_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedAggregateFunctionCall::limit not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<0)) != 0) {
    if (having_modifier_ != nullptr) {
      ZETASQL_RETURN_IF_ERROR(having_modifier_->CheckFieldsAccessed());
    }
  }
  if ((accessed_ & (1<<1)) != 0) {
    for (const auto& it : order_by_item_list_) ZETASQL_RETURN_IF_ERROR(it->CheckFieldsAccessed());
  }
  if ((accessed_ & (1<<2)) != 0) {
    if (limit_ != nullptr) {
      ZETASQL_RETURN_IF_ERROR(limit_->CheckFieldsAccessed());
    }
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedAggregateFunctionCall::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
  if (having_modifier_ != nullptr) having_modifier_->ClearFieldsAccessed();
  for (const auto& it : order_by_item_list_) it->ClearFieldsAccessed();
  if (limit_ != nullptr) limit_->ClearFieldsAccessed();
}

const ResolvedNodeKind ResolvedAnalyticFunctionCall::TYPE;

ResolvedAnalyticFunctionCall::~ResolvedAnalyticFunctionCall() {
}

zetasql_base::Status ResolvedAnalyticFunctionCall::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedNonScalarFunctionCallBaseProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_analytic_function_call_node());
}

zetasql_base::Status ResolvedAnalyticFunctionCall::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedAnalyticFunctionCallProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  if (window_frame_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(window_frame_->SaveTo(
        file_descriptor_set_map, proto->mutable_window_frame()));
  }
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedAnalyticFunctionCall>> ResolvedAnalyticFunctionCall::RestoreFrom(
    const ResolvedAnalyticFunctionCallProto& proto,
    const ResolvedNode::RestoreParams& params) {
  std::unique_ptr<const ResolvedWindowFrame> window_frame;
  if (proto.
  has_window_frame()) {
    ZETASQL_ASSIGN_OR_RETURN(window_frame,
                     ResolvedWindowFrame::RestoreFrom(
                         proto.window_frame(), params));
  }
  ZETASQL_ASSIGN_OR_RETURN(const Type* type,
                   RestoreFromImpl(proto.parent().parent().parent().type(),
                                   params));
  ZETASQL_ASSIGN_OR_RETURN(const Function* function,
                   RestoreFromImpl(proto.parent().parent().function(),
                                   params));
  ZETASQL_ASSIGN_OR_RETURN(FunctionSignature signature,
                   RestoreFromImpl(proto.parent().parent().signature(),
                                   params));
  std::vector<std::unique_ptr<const ResolvedExpr>> argument_list;
  for (const auto& elem : proto.parent().parent().argument_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedExpr> elem_restored,
                     ResolvedExpr::RestoreFrom(elem, params));
    argument_list.push_back(std::move(elem_restored));
  }
  ErrorMode error_mode =
      proto.parent().parent().error_mode();
  bool distinct =
      proto.parent().distinct();
  NullHandlingModifier null_handling_modifier =
      proto.parent().null_handling_modifier();
  auto node = MakeResolvedAnalyticFunctionCall(
      std::move(type),
      std::move(function),
      std::move(signature),
      std::move(argument_list),
      std::move(error_mode),
      std::move(distinct),
      std::move(null_handling_modifier),
      std::move(window_frame));

  return std::move(node);
}

void ResolvedAnalyticFunctionCall::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
  if (window_frame_ != nullptr) {
    child_nodes->emplace_back(window_frame_.get());
  }
}

void ResolvedAnalyticFunctionCall::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
  if (window_frame_ != nullptr) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(
            &window_frame_));
    static_assert(sizeof(window_frame_) ==
                  sizeof(*(mutable_child_node_ptrs->back())),
                  "Incorrect casting of mutable child node");
  }
}

zetasql_base::Status ResolvedAnalyticFunctionCall::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedAnalyticFunctionCall(this);
}

zetasql_base::Status ResolvedAnalyticFunctionCall::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  if (window_frame_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(window_frame_.get()->Accept(visitor));
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedAnalyticFunctionCall::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  if (window_frame_ != nullptr) {
    fields->emplace_back("window_frame", window_frame_.get());
  }
}

zetasql_base::Status ResolvedAnalyticFunctionCall::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedAnalyticFunctionCall::window_frame not accessed)";
  }
  if ((accessed_ & (1<<0)) != 0) {
    if (window_frame_ != nullptr) {
      ZETASQL_RETURN_IF_ERROR(window_frame_->CheckFieldsAccessed());
    }
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedAnalyticFunctionCall::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
  if (window_frame_ != nullptr) window_frame_->ClearFieldsAccessed();
}

const ResolvedNodeKind ResolvedCast::TYPE;

ResolvedCast::~ResolvedCast() {
}

zetasql_base::Status ResolvedCast::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedExprProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_cast_node());
}

zetasql_base::Status ResolvedCast::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedCastProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  if (expr_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(expr_->SaveTo(
        file_descriptor_set_map, proto->mutable_expr()));
  }
  proto->set_return_null_on_error(return_null_on_error_);
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedCast>> ResolvedCast::RestoreFrom(
    const ResolvedCastProto& proto,
    const ResolvedNode::RestoreParams& params) {
  std::unique_ptr<const ResolvedExpr> expr;
  if (proto.
  has_expr()) {
    ZETASQL_ASSIGN_OR_RETURN(expr,
                     ResolvedExpr::RestoreFrom(
                         proto.expr(), params));
  }
  bool return_null_on_error =
      proto.return_null_on_error();
  ZETASQL_ASSIGN_OR_RETURN(const Type* type,
                   RestoreFromImpl(proto.parent().type(),
                                   params));
  auto node = MakeResolvedCast(
      std::move(type),
      std::move(expr),
      std::move(return_null_on_error));

  return std::move(node);
}

void ResolvedCast::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
  if (expr_ != nullptr) {
    child_nodes->emplace_back(expr_.get());
  }
}

void ResolvedCast::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
  if (expr_ != nullptr) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(
            &expr_));
    static_assert(sizeof(expr_) ==
                  sizeof(*(mutable_child_node_ptrs->back())),
                  "Incorrect casting of mutable child node");
  }
}

zetasql_base::Status ResolvedCast::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedCast(this);
}

zetasql_base::Status ResolvedCast::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  if (expr_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(expr_.get()->Accept(visitor));
  }
  return ::zetasql_base::OkStatus();
}

zetasql_base::Status ResolvedCast::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedCast::expr not accessed)";
  }
  if ((accessed_ & (1<<1)) == 0 &&
      !IsDefaultValue(return_null_on_error_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedCast::return_null_on_error not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<0)) != 0) {
    if (expr_ != nullptr) {
      ZETASQL_RETURN_IF_ERROR(expr_->CheckFieldsAccessed());
    }
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedCast::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
  if (expr_ != nullptr) expr_->ClearFieldsAccessed();
}

const ResolvedNodeKind ResolvedMakeStruct::TYPE;

ResolvedMakeStruct::~ResolvedMakeStruct() {
}

zetasql_base::Status ResolvedMakeStruct::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedExprProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_make_struct_node());
}

zetasql_base::Status ResolvedMakeStruct::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedMakeStructProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  for (const auto& elem : field_list_) {
    ZETASQL_RETURN_IF_ERROR(elem->SaveTo(
      file_descriptor_set_map, proto->add_field_list()));
  }
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedMakeStruct>> ResolvedMakeStruct::RestoreFrom(
    const ResolvedMakeStructProto& proto,
    const ResolvedNode::RestoreParams& params) {
  std::vector<std::unique_ptr<const ResolvedExpr>> field_list;
  for (const auto& elem : proto.field_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedExpr> elem_restored,
                     ResolvedExpr::RestoreFrom(elem, params));
    field_list.push_back(std::move(elem_restored));
  }
  ZETASQL_ASSIGN_OR_RETURN(const Type* type,
                   RestoreFromImpl(proto.parent().type(),
                                   params));
  auto node = MakeResolvedMakeStruct(
      std::move(type),
      std::move(field_list));

  return std::move(node);
}

void ResolvedMakeStruct::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
  for (const auto& elem : field_list_) {
    child_nodes->emplace_back(elem.get());
  }
}

void ResolvedMakeStruct::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
  for (auto& elem : field_list_) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(&elem));
  }
}

zetasql_base::Status ResolvedMakeStruct::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedMakeStruct(this);
}

zetasql_base::Status ResolvedMakeStruct::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  for (const auto& elem : field_list_) {
    ZETASQL_RETURN_IF_ERROR(elem.get()->Accept(visitor));
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedMakeStruct::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  if (!field_list_.empty()) {
    fields->emplace_back("field_list", field_list_);
  }
}

zetasql_base::Status ResolvedMakeStruct::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedMakeStruct::field_list not accessed)";
  }
  if ((accessed_ & (1<<0)) != 0) {
    for (const auto& it : field_list_) ZETASQL_RETURN_IF_ERROR(it->CheckFieldsAccessed());
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedMakeStruct::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
  for (const auto& it : field_list_) it->ClearFieldsAccessed();
}

const ResolvedNodeKind ResolvedMakeProto::TYPE;

ResolvedMakeProto::~ResolvedMakeProto() {
}

zetasql_base::Status ResolvedMakeProto::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedExprProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_make_proto_node());
}

zetasql_base::Status ResolvedMakeProto::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedMakeProtoProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  for (const auto& elem : field_list_) {
    ZETASQL_RETURN_IF_ERROR(elem->SaveTo(
      file_descriptor_set_map, proto->add_field_list()));
  }
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedMakeProto>> ResolvedMakeProto::RestoreFrom(
    const ResolvedMakeProtoProto& proto,
    const ResolvedNode::RestoreParams& params) {
  std::vector<std::unique_ptr<const ResolvedMakeProtoField>> field_list;
  for (const auto& elem : proto.field_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedMakeProtoField> elem_restored,
                     ResolvedMakeProtoField::RestoreFrom(elem, params));
    field_list.push_back(std::move(elem_restored));
  }
  ZETASQL_ASSIGN_OR_RETURN(const Type* type,
                   RestoreFromImpl(proto.parent().type(),
                                   params));
  auto node = MakeResolvedMakeProto(
      std::move(type),
      std::move(field_list));

  return std::move(node);
}

void ResolvedMakeProto::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
  for (const auto& elem : field_list_) {
    child_nodes->emplace_back(elem.get());
  }
}

void ResolvedMakeProto::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
  for (auto& elem : field_list_) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(&elem));
  }
}

zetasql_base::Status ResolvedMakeProto::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedMakeProto(this);
}

zetasql_base::Status ResolvedMakeProto::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  for (const auto& elem : field_list_) {
    ZETASQL_RETURN_IF_ERROR(elem.get()->Accept(visitor));
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedMakeProto::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  if (!field_list_.empty()) {
    fields->emplace_back("field_list", field_list_);
  }
}

zetasql_base::Status ResolvedMakeProto::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedMakeProto::field_list not accessed)";
  }
  if ((accessed_ & (1<<0)) != 0) {
    for (const auto& it : field_list_) ZETASQL_RETURN_IF_ERROR(it->CheckFieldsAccessed());
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedMakeProto::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
  for (const auto& it : field_list_) it->ClearFieldsAccessed();
}

const ResolvedNodeKind ResolvedMakeProtoField::TYPE;

ResolvedMakeProtoField::~ResolvedMakeProtoField() {
}

zetasql_base::Status ResolvedMakeProtoField::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedArgumentProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_make_proto_field_node());
}

zetasql_base::Status ResolvedMakeProtoField::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedMakeProtoFieldProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  ZETASQL_RETURN_IF_ERROR(SaveToImpl(
      field_descriptor_, file_descriptor_set_map,
      proto->mutable_field_descriptor()));
  proto->set_format(format_);
  if (expr_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(expr_->SaveTo(
        file_descriptor_set_map, proto->mutable_expr()));
  }
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedMakeProtoField>> ResolvedMakeProtoField::RestoreFrom(
    const ResolvedMakeProtoFieldProto& proto,
    const ResolvedNode::RestoreParams& params) {
  ZETASQL_ASSIGN_OR_RETURN(const google::protobuf::FieldDescriptor* field_descriptor,
                   RestoreFromImpl(proto.field_descriptor(),
                                   params));
  FieldFormat::Format format =
      proto.format();
  std::unique_ptr<const ResolvedExpr> expr;
  if (proto.
  has_expr()) {
    ZETASQL_ASSIGN_OR_RETURN(expr,
                     ResolvedExpr::RestoreFrom(
                         proto.expr(), params));
  }
  auto node = MakeResolvedMakeProtoField(
      std::move(field_descriptor),
      std::move(format),
      std::move(expr));

  return std::move(node);
}

void ResolvedMakeProtoField::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
  if (expr_ != nullptr) {
    child_nodes->emplace_back(expr_.get());
  }
}

void ResolvedMakeProtoField::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
  if (expr_ != nullptr) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(
            &expr_));
    static_assert(sizeof(expr_) ==
                  sizeof(*(mutable_child_node_ptrs->back())),
                  "Incorrect casting of mutable child node");
  }
}

zetasql_base::Status ResolvedMakeProtoField::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedMakeProtoField(this);
}

zetasql_base::Status ResolvedMakeProtoField::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  if (expr_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(expr_.get()->Accept(visitor));
  }
  return ::zetasql_base::OkStatus();
}

zetasql_base::Status ResolvedMakeProtoField::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedMakeProtoField::field_descriptor not accessed)";
  }
  if ((accessed_ & (1<<1)) == 0 &&
      !IsDefaultValue(format_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedMakeProtoField::format not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<2)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedMakeProtoField::expr not accessed)";
  }
  if ((accessed_ & (1<<2)) != 0) {
    if (expr_ != nullptr) {
      ZETASQL_RETURN_IF_ERROR(expr_->CheckFieldsAccessed());
    }
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedMakeProtoField::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
  if (expr_ != nullptr) expr_->ClearFieldsAccessed();
}

const ResolvedNodeKind ResolvedGetStructField::TYPE;

ResolvedGetStructField::~ResolvedGetStructField() {
}

zetasql_base::Status ResolvedGetStructField::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedExprProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_get_struct_field_node());
}

zetasql_base::Status ResolvedGetStructField::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedGetStructFieldProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  if (expr_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(expr_->SaveTo(
        file_descriptor_set_map, proto->mutable_expr()));
  }
  proto->set_field_idx(field_idx_);
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedGetStructField>> ResolvedGetStructField::RestoreFrom(
    const ResolvedGetStructFieldProto& proto,
    const ResolvedNode::RestoreParams& params) {
  std::unique_ptr<const ResolvedExpr> expr;
  if (proto.
  has_expr()) {
    ZETASQL_ASSIGN_OR_RETURN(expr,
                     ResolvedExpr::RestoreFrom(
                         proto.expr(), params));
  }
  int field_idx =
      proto.field_idx();
  ZETASQL_ASSIGN_OR_RETURN(const Type* type,
                   RestoreFromImpl(proto.parent().type(),
                                   params));
  auto node = MakeResolvedGetStructField(
      std::move(type),
      std::move(expr),
      std::move(field_idx));

  return std::move(node);
}

void ResolvedGetStructField::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
  if (expr_ != nullptr) {
    child_nodes->emplace_back(expr_.get());
  }
}

void ResolvedGetStructField::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
  if (expr_ != nullptr) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(
            &expr_));
    static_assert(sizeof(expr_) ==
                  sizeof(*(mutable_child_node_ptrs->back())),
                  "Incorrect casting of mutable child node");
  }
}

zetasql_base::Status ResolvedGetStructField::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedGetStructField(this);
}

zetasql_base::Status ResolvedGetStructField::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  if (expr_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(expr_.get()->Accept(visitor));
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedGetStructField::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  if (expr_ != nullptr) {
    fields->emplace_back("expr", expr_.get());
  }
  {
    fields->emplace_back("field_idx", ToStringImpl(field_idx_));
  }
}

zetasql_base::Status ResolvedGetStructField::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedGetStructField::expr not accessed)";
  }
  if ((accessed_ & (1<<1)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedGetStructField::field_idx not accessed)";
  }
  if ((accessed_ & (1<<0)) != 0) {
    if (expr_ != nullptr) {
      ZETASQL_RETURN_IF_ERROR(expr_->CheckFieldsAccessed());
    }
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedGetStructField::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
  if (expr_ != nullptr) expr_->ClearFieldsAccessed();
}

const ResolvedNodeKind ResolvedGetProtoField::TYPE;

ResolvedGetProtoField::~ResolvedGetProtoField() {
}

zetasql_base::Status ResolvedGetProtoField::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedExprProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_get_proto_field_node());
}

zetasql_base::Status ResolvedGetProtoField::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedGetProtoFieldProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  if (expr_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(expr_->SaveTo(
        file_descriptor_set_map, proto->mutable_expr()));
  }
  ZETASQL_RETURN_IF_ERROR(SaveToImpl(
      field_descriptor_, file_descriptor_set_map,
      proto->mutable_field_descriptor()));
  ZETASQL_RETURN_IF_ERROR(SaveToImpl(
      default_value_, file_descriptor_set_map,
      proto->mutable_default_value()));
  proto->set_get_has_bit(get_has_bit_);
  proto->set_format(format_);
  proto->set_return_default_value_when_unset(return_default_value_when_unset_);
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedGetProtoField>> ResolvedGetProtoField::RestoreFrom(
    const ResolvedGetProtoFieldProto& proto,
    const ResolvedNode::RestoreParams& params) {
  std::unique_ptr<const ResolvedExpr> expr;
  if (proto.
  has_expr()) {
    ZETASQL_ASSIGN_OR_RETURN(expr,
                     ResolvedExpr::RestoreFrom(
                         proto.expr(), params));
  }
  ZETASQL_ASSIGN_OR_RETURN(const google::protobuf::FieldDescriptor* field_descriptor,
                   RestoreFromImpl(proto.field_descriptor(),
                                   params));
  ZETASQL_ASSIGN_OR_RETURN(Value default_value,
                   RestoreFromImpl(proto.default_value(),
                                   params));
  bool get_has_bit =
      proto.get_has_bit();
  FieldFormat::Format format =
      proto.format();
  bool return_default_value_when_unset =
      proto.return_default_value_when_unset();
  ZETASQL_ASSIGN_OR_RETURN(const Type* type,
                   RestoreFromImpl(proto.parent().type(),
                                   params));
  auto node = MakeResolvedGetProtoField(
      std::move(type),
      std::move(expr),
      std::move(field_descriptor),
      std::move(default_value),
      std::move(get_has_bit),
      std::move(format),
      std::move(return_default_value_when_unset));

  return std::move(node);
}

void ResolvedGetProtoField::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
  if (expr_ != nullptr) {
    child_nodes->emplace_back(expr_.get());
  }
}

void ResolvedGetProtoField::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
  if (expr_ != nullptr) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(
            &expr_));
    static_assert(sizeof(expr_) ==
                  sizeof(*(mutable_child_node_ptrs->back())),
                  "Incorrect casting of mutable child node");
  }
}

zetasql_base::Status ResolvedGetProtoField::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedGetProtoField(this);
}

zetasql_base::Status ResolvedGetProtoField::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  if (expr_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(expr_.get()->Accept(visitor));
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedGetProtoField::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  if (expr_ != nullptr) {
    fields->emplace_back("expr", expr_.get());
  }
  {
    fields->emplace_back("field_descriptor", ToStringImpl(field_descriptor_));
  }
  if (!IsDefaultValue(default_value_)) {
    fields->emplace_back("default_value", ToStringImpl(default_value_));
  }
  if (!IsDefaultValue(get_has_bit_)) {
    fields->emplace_back("get_has_bit", ToStringImpl(get_has_bit_));
  }
  if (!IsDefaultValue(format_)) {
    fields->emplace_back("format", ToStringImpl(format_));
  }
  if (!IsDefaultValue(return_default_value_when_unset_)) {
    fields->emplace_back("return_default_value_when_unset", ToStringImpl(return_default_value_when_unset_));
  }
}

zetasql_base::Status ResolvedGetProtoField::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedGetProtoField::expr not accessed)";
  }
  if ((accessed_ & (1<<1)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedGetProtoField::field_descriptor not accessed)";
  }
  if ((accessed_ & (1<<3)) == 0 &&
      !IsDefaultValue(get_has_bit_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedGetProtoField::get_has_bit not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<4)) == 0 &&
      !IsDefaultValue(format_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedGetProtoField::format not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<5)) == 0 &&
      !IsDefaultValue(return_default_value_when_unset_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedGetProtoField::return_default_value_when_unset not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<0)) != 0) {
    if (expr_ != nullptr) {
      ZETASQL_RETURN_IF_ERROR(expr_->CheckFieldsAccessed());
    }
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedGetProtoField::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
  if (expr_ != nullptr) expr_->ClearFieldsAccessed();
}

const ResolvedNodeKind ResolvedSubqueryExpr::TYPE;

const ResolvedSubqueryExpr::SubqueryType ResolvedSubqueryExpr::SCALAR;
const ResolvedSubqueryExpr::SubqueryType ResolvedSubqueryExpr::ARRAY;
const ResolvedSubqueryExpr::SubqueryType ResolvedSubqueryExpr::EXISTS;
const ResolvedSubqueryExpr::SubqueryType ResolvedSubqueryExpr::IN;

ResolvedSubqueryExpr::~ResolvedSubqueryExpr() {
}

zetasql_base::Status ResolvedSubqueryExpr::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedExprProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_subquery_expr_node());
}

zetasql_base::Status ResolvedSubqueryExpr::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedSubqueryExprProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  proto->set_subquery_type(subquery_type_);
  for (const auto& elem : parameter_list_) {
    ZETASQL_RETURN_IF_ERROR(elem->SaveTo(
      file_descriptor_set_map, proto->add_parameter_list()));
  }
  if (in_expr_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(in_expr_->SaveTo(
        file_descriptor_set_map, proto->mutable_in_expr()));
  }
  if (subquery_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(subquery_->SaveTo(
        file_descriptor_set_map, proto->mutable_subquery()));
  }
  for (const auto& elem : hint_list_) {
    ZETASQL_RETURN_IF_ERROR(elem->SaveTo(
      file_descriptor_set_map, proto->add_hint_list()));
  }
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedSubqueryExpr>> ResolvedSubqueryExpr::RestoreFrom(
    const ResolvedSubqueryExprProto& proto,
    const ResolvedNode::RestoreParams& params) {
  SubqueryType subquery_type =
      proto.subquery_type();
  std::vector<std::unique_ptr<const ResolvedColumnRef>> parameter_list;
  for (const auto& elem : proto.parameter_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedColumnRef> elem_restored,
                     ResolvedColumnRef::RestoreFrom(elem, params));
    parameter_list.push_back(std::move(elem_restored));
  }
  std::unique_ptr<const ResolvedExpr> in_expr;
  if (proto.
  has_in_expr()) {
    ZETASQL_ASSIGN_OR_RETURN(in_expr,
                     ResolvedExpr::RestoreFrom(
                         proto.in_expr(), params));
  }
  std::unique_ptr<const ResolvedScan> subquery;
  if (proto.
  has_subquery()) {
    ZETASQL_ASSIGN_OR_RETURN(subquery,
                     ResolvedScan::RestoreFrom(
                         proto.subquery(), params));
  }
  std::vector<std::unique_ptr<const ResolvedOption>> hint_list;
  for (const auto& elem : proto.hint_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedOption> elem_restored,
                     ResolvedOption::RestoreFrom(elem, params));
    hint_list.push_back(std::move(elem_restored));
  }
  ZETASQL_ASSIGN_OR_RETURN(const Type* type,
                   RestoreFromImpl(proto.parent().type(),
                                   params));
  auto node = MakeResolvedSubqueryExpr(
      std::move(type),
      std::move(subquery_type),
      std::move(parameter_list),
      std::move(in_expr),
      std::move(subquery));

  node->set_hint_list(std::move(hint_list));
  return std::move(node);
}

void ResolvedSubqueryExpr::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
  for (const auto& elem : parameter_list_) {
    child_nodes->emplace_back(elem.get());
  }
  if (in_expr_ != nullptr) {
    child_nodes->emplace_back(in_expr_.get());
  }
  if (subquery_ != nullptr) {
    child_nodes->emplace_back(subquery_.get());
  }
  for (const auto& elem : hint_list_) {
    child_nodes->emplace_back(elem.get());
  }
}

void ResolvedSubqueryExpr::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
  for (auto& elem : parameter_list_) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(&elem));
  }
  if (in_expr_ != nullptr) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(
            &in_expr_));
    static_assert(sizeof(in_expr_) ==
                  sizeof(*(mutable_child_node_ptrs->back())),
                  "Incorrect casting of mutable child node");
  }
  if (subquery_ != nullptr) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(
            &subquery_));
    static_assert(sizeof(subquery_) ==
                  sizeof(*(mutable_child_node_ptrs->back())),
                  "Incorrect casting of mutable child node");
  }
  for (auto& elem : hint_list_) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(&elem));
  }
}

zetasql_base::Status ResolvedSubqueryExpr::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedSubqueryExpr(this);
}

zetasql_base::Status ResolvedSubqueryExpr::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  for (const auto& elem : parameter_list_) {
    ZETASQL_RETURN_IF_ERROR(elem.get()->Accept(visitor));
  }
  if (in_expr_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(in_expr_.get()->Accept(visitor));
  }
  if (subquery_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(subquery_.get()->Accept(visitor));
  }
  for (const auto& elem : hint_list_) {
    ZETASQL_RETURN_IF_ERROR(elem.get()->Accept(visitor));
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedSubqueryExpr::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  {
    fields->emplace_back("subquery_type", ToStringImpl(subquery_type_));
  }
  if (!parameter_list_.empty()) {
    fields->emplace_back("parameter_list", parameter_list_);
  }
  if (in_expr_ != nullptr) {
    fields->emplace_back("in_expr", in_expr_.get());
  }
  if (subquery_ != nullptr) {
    fields->emplace_back("subquery", subquery_.get());
  }
  if (!hint_list_.empty()) {
    fields->emplace_back("hint_list", hint_list_);
  }
}

zetasql_base::Status ResolvedSubqueryExpr::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedSubqueryExpr::subquery_type not accessed)";
  }
  if ((accessed_ & (1<<1)) == 0 &&
      !IsDefaultValue(parameter_list_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedSubqueryExpr::parameter_list not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<2)) == 0 &&
      !IsDefaultValue(in_expr_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedSubqueryExpr::in_expr not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<3)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedSubqueryExpr::subquery not accessed)";
  }
  if ((accessed_ & (1<<1)) != 0) {
    for (const auto& it : parameter_list_) ZETASQL_RETURN_IF_ERROR(it->CheckFieldsAccessed());
  }
  if ((accessed_ & (1<<2)) != 0) {
    if (in_expr_ != nullptr) {
      ZETASQL_RETURN_IF_ERROR(in_expr_->CheckFieldsAccessed());
    }
  }
  if ((accessed_ & (1<<3)) != 0) {
    if (subquery_ != nullptr) {
      ZETASQL_RETURN_IF_ERROR(subquery_->CheckFieldsAccessed());
    }
  }
  if ((accessed_ & (1<<4)) != 0) {
    for (const auto& it : hint_list_) ZETASQL_RETURN_IF_ERROR(it->CheckFieldsAccessed());
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedSubqueryExpr::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
  for (const auto& it : parameter_list_) it->ClearFieldsAccessed();
  if (in_expr_ != nullptr) in_expr_->ClearFieldsAccessed();
  if (subquery_ != nullptr) subquery_->ClearFieldsAccessed();
  for (const auto& it : hint_list_) it->ClearFieldsAccessed();
}

ResolvedScan::~ResolvedScan() {
}

zetasql_base::Status ResolvedScan::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedNodeProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_scan_node());
}

zetasql_base::Status ResolvedScan::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedScanProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  for (const auto& elem : column_list_) {
    ZETASQL_RETURN_IF_ERROR(SaveToImpl(
        elem, file_descriptor_set_map, proto->add_column_list()));
  }
  for (const auto& elem : hint_list_) {
    ZETASQL_RETURN_IF_ERROR(elem->SaveTo(
      file_descriptor_set_map, proto->add_hint_list()));
  }
  proto->set_is_ordered(is_ordered_);
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedScan>> ResolvedScan::RestoreFrom(
    const AnyResolvedScanProto& proto,
    const ResolvedNode::RestoreParams& params) {
  switch (proto.node_case()) {
    case AnyResolvedScanProto::kResolvedSingleRowScanNode:
      return ResolvedSingleRowScan::RestoreFrom(
          proto.resolved_single_row_scan_node(), params);
    case AnyResolvedScanProto::kResolvedTableScanNode:
      return ResolvedTableScan::RestoreFrom(
          proto.resolved_table_scan_node(), params);
    case AnyResolvedScanProto::kResolvedJoinScanNode:
      return ResolvedJoinScan::RestoreFrom(
          proto.resolved_join_scan_node(), params);
    case AnyResolvedScanProto::kResolvedArrayScanNode:
      return ResolvedArrayScan::RestoreFrom(
          proto.resolved_array_scan_node(), params);
    case AnyResolvedScanProto::kResolvedFilterScanNode:
      return ResolvedFilterScan::RestoreFrom(
          proto.resolved_filter_scan_node(), params);
    case AnyResolvedScanProto::kResolvedSetOperationScanNode:
      return ResolvedSetOperationScan::RestoreFrom(
          proto.resolved_set_operation_scan_node(), params);
    case AnyResolvedScanProto::kResolvedOrderByScanNode:
      return ResolvedOrderByScan::RestoreFrom(
          proto.resolved_order_by_scan_node(), params);
    case AnyResolvedScanProto::kResolvedLimitOffsetScanNode:
      return ResolvedLimitOffsetScan::RestoreFrom(
          proto.resolved_limit_offset_scan_node(), params);
    case AnyResolvedScanProto::kResolvedWithRefScanNode:
      return ResolvedWithRefScan::RestoreFrom(
          proto.resolved_with_ref_scan_node(), params);
    case AnyResolvedScanProto::kResolvedAnalyticScanNode:
      return ResolvedAnalyticScan::RestoreFrom(
          proto.resolved_analytic_scan_node(), params);
    case AnyResolvedScanProto::kResolvedSampleScanNode:
      return ResolvedSampleScan::RestoreFrom(
          proto.resolved_sample_scan_node(), params);
    case AnyResolvedScanProto::kResolvedProjectScanNode:
      return ResolvedProjectScan::RestoreFrom(
          proto.resolved_project_scan_node(), params);
    case AnyResolvedScanProto::kResolvedWithScanNode:
      return ResolvedWithScan::RestoreFrom(
          proto.resolved_with_scan_node(), params);
    case AnyResolvedScanProto::kResolvedTvfscanNode:
      return ResolvedTVFScan::RestoreFrom(
          proto.resolved_tvfscan_node(), params);
    case AnyResolvedScanProto::kResolvedRelationArgumentScanNode:
      return ResolvedRelationArgumentScan::RestoreFrom(
          proto.resolved_relation_argument_scan_node(), params);
    case AnyResolvedScanProto::kResolvedAggregateScanBaseNode:
      return ResolvedAggregateScanBase::RestoreFrom(
          proto.resolved_aggregate_scan_base_node(), params);
  case AnyResolvedScanProto::NODE_NOT_SET:
    return ::zetasql_base::InvalidArgumentErrorBuilder(ZETASQL_LOC)
        << "No subnode types set in ResolvedScanProto";
  }
}

void ResolvedScan::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
  for (const auto& elem : hint_list_) {
    child_nodes->emplace_back(elem.get());
  }
}

void ResolvedScan::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
  for (auto& elem : hint_list_) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(&elem));
  }
}

zetasql_base::Status ResolvedScan::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedScan(this);
}

zetasql_base::Status ResolvedScan::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  for (const auto& elem : hint_list_) {
    ZETASQL_RETURN_IF_ERROR(elem.get()->Accept(visitor));
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedScan::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  if (!IsDefaultValue(column_list_)) {
    fields->emplace_back("column_list", ToStringImpl(column_list_));
  }
  if (!hint_list_.empty()) {
    fields->emplace_back("hint_list", hint_list_);
  }
  if (!IsDefaultValue(is_ordered_)) {
    fields->emplace_back("is_ordered", ToStringImpl(is_ordered_));
  }
}

zetasql_base::Status ResolvedScan::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<1)) != 0) {
    for (const auto& it : hint_list_) ZETASQL_RETURN_IF_ERROR(it->CheckFieldsAccessed());
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedScan::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
  for (const auto& it : hint_list_) it->ClearFieldsAccessed();
}

const ResolvedNodeKind ResolvedModel::TYPE;

ResolvedModel::~ResolvedModel() {
}

zetasql_base::Status ResolvedModel::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedArgumentProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_model_node());
}

zetasql_base::Status ResolvedModel::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedModelProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  ZETASQL_RETURN_IF_ERROR(SaveToImpl(
      model_, file_descriptor_set_map,
      proto->mutable_model()));
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedModel>> ResolvedModel::RestoreFrom(
    const ResolvedModelProto& proto,
    const ResolvedNode::RestoreParams& params) {
  ZETASQL_ASSIGN_OR_RETURN(const Model* model,
                   RestoreFromImpl(proto.model(),
                                   params));
  auto node = MakeResolvedModel(
      std::move(model));

  return std::move(node);
}

void ResolvedModel::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
}

void ResolvedModel::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
}

zetasql_base::Status ResolvedModel::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedModel(this);
}

zetasql_base::Status ResolvedModel::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  return ::zetasql_base::OkStatus();
}

void ResolvedModel::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  {
    fields->emplace_back("model", ToStringImpl(model_));
  }
}

zetasql_base::Status ResolvedModel::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedModel::model not accessed)";
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedModel::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
}

const ResolvedNodeKind ResolvedSingleRowScan::TYPE;

ResolvedSingleRowScan::~ResolvedSingleRowScan() {
}

zetasql_base::Status ResolvedSingleRowScan::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedScanProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_single_row_scan_node());
}

zetasql_base::Status ResolvedSingleRowScan::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedSingleRowScanProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedSingleRowScan>> ResolvedSingleRowScan::RestoreFrom(
    const ResolvedSingleRowScanProto& proto,
    const ResolvedNode::RestoreParams& params) {
  std::vector<ResolvedColumn> column_list;
  for (const auto& elem : proto.parent().column_list()) {
    ZETASQL_ASSIGN_OR_RETURN(auto elem_restored, RestoreFromImpl(elem, params));
    column_list.push_back(std::move(elem_restored));
  }
  std::vector<std::unique_ptr<const ResolvedOption>> hint_list;
  for (const auto& elem : proto.parent().hint_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedOption> elem_restored,
                     ResolvedOption::RestoreFrom(elem, params));
    hint_list.push_back(std::move(elem_restored));
  }
  bool is_ordered =
      proto.parent().is_ordered();
  auto node = MakeResolvedSingleRowScan(
      std::move(column_list));

  node->set_hint_list(std::move(hint_list));
  node->set_is_ordered(std::move(is_ordered));
  return std::move(node);
}

zetasql_base::Status ResolvedSingleRowScan::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedSingleRowScan(this);
}

zetasql_base::Status ResolvedSingleRowScan::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  return ::zetasql_base::OkStatus();
}

const ResolvedNodeKind ResolvedTableScan::TYPE;

ResolvedTableScan::~ResolvedTableScan() {
}

zetasql_base::Status ResolvedTableScan::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedScanProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_table_scan_node());
}

zetasql_base::Status ResolvedTableScan::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedTableScanProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  ZETASQL_RETURN_IF_ERROR(SaveToImpl(
      table_, file_descriptor_set_map,
      proto->mutable_table()));
  if (for_system_time_expr_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(for_system_time_expr_->SaveTo(
        file_descriptor_set_map, proto->mutable_for_system_time_expr()));
  }
  for (const auto& elem : column_index_list_) {
    proto->add_column_index_list(elem);
  }
  proto->set_alias(alias_);
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedTableScan>> ResolvedTableScan::RestoreFrom(
    const ResolvedTableScanProto& proto,
    const ResolvedNode::RestoreParams& params) {
  ZETASQL_ASSIGN_OR_RETURN(const Table* table,
                   RestoreFromImpl(proto.table(),
                                   params));
  std::unique_ptr<const ResolvedExpr> for_system_time_expr;
  if (proto.
  has_for_system_time_expr()) {
    ZETASQL_ASSIGN_OR_RETURN(for_system_time_expr,
                     ResolvedExpr::RestoreFrom(
                         proto.for_system_time_expr(), params));
  }
  std::vector<int> column_index_list;
  for (const auto& elem : proto.column_index_list()) {
    column_index_list.push_back(elem);
  }
  std::string alias =
      proto.alias();
  std::vector<ResolvedColumn> column_list;
  for (const auto& elem : proto.parent().column_list()) {
    ZETASQL_ASSIGN_OR_RETURN(auto elem_restored, RestoreFromImpl(elem, params));
    column_list.push_back(std::move(elem_restored));
  }
  std::vector<std::unique_ptr<const ResolvedOption>> hint_list;
  for (const auto& elem : proto.parent().hint_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedOption> elem_restored,
                     ResolvedOption::RestoreFrom(elem, params));
    hint_list.push_back(std::move(elem_restored));
  }
  bool is_ordered =
      proto.parent().is_ordered();
  auto node = MakeResolvedTableScan(
      std::move(column_list),
      std::move(table),
      std::move(for_system_time_expr),
      std::move(alias));

  node->set_hint_list(std::move(hint_list));
  node->set_is_ordered(std::move(is_ordered));
  node->set_column_index_list(std::move(column_index_list));
  return std::move(node);
}

void ResolvedTableScan::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
  if (for_system_time_expr_ != nullptr) {
    child_nodes->emplace_back(for_system_time_expr_.get());
  }
}

void ResolvedTableScan::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
  if (for_system_time_expr_ != nullptr) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(
            &for_system_time_expr_));
    static_assert(sizeof(for_system_time_expr_) ==
                  sizeof(*(mutable_child_node_ptrs->back())),
                  "Incorrect casting of mutable child node");
  }
}

zetasql_base::Status ResolvedTableScan::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedTableScan(this);
}

zetasql_base::Status ResolvedTableScan::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  if (for_system_time_expr_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(for_system_time_expr_.get()->Accept(visitor));
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedTableScan::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  {
    fields->emplace_back("table", ToStringImpl(table_));
  }
  if (for_system_time_expr_ != nullptr) {
    fields->emplace_back("for_system_time_expr", for_system_time_expr_.get());
  }
  if (!IsDefaultValue(column_index_list_)) {
    fields->emplace_back("column_index_list", ToStringCommaSeparated(column_index_list_));
  }
  if (!IsDefaultValue(alias_)) {
    fields->emplace_back("alias", ToStringImpl(alias_));
  }
}

zetasql_base::Status ResolvedTableScan::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedTableScan::table not accessed)";
  }
  if ((accessed_ & (1<<1)) == 0 &&
      !IsDefaultValue(for_system_time_expr_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedTableScan::for_system_time_expr not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<1)) != 0) {
    if (for_system_time_expr_ != nullptr) {
      ZETASQL_RETURN_IF_ERROR(for_system_time_expr_->CheckFieldsAccessed());
    }
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedTableScan::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
  if (for_system_time_expr_ != nullptr) for_system_time_expr_->ClearFieldsAccessed();
}

const ResolvedNodeKind ResolvedJoinScan::TYPE;

const ResolvedJoinScan::JoinType ResolvedJoinScan::INNER;
const ResolvedJoinScan::JoinType ResolvedJoinScan::LEFT;
const ResolvedJoinScan::JoinType ResolvedJoinScan::RIGHT;
const ResolvedJoinScan::JoinType ResolvedJoinScan::FULL;

ResolvedJoinScan::~ResolvedJoinScan() {
}

zetasql_base::Status ResolvedJoinScan::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedScanProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_join_scan_node());
}

zetasql_base::Status ResolvedJoinScan::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedJoinScanProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  proto->set_join_type(join_type_);
  if (left_scan_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(left_scan_->SaveTo(
        file_descriptor_set_map, proto->mutable_left_scan()));
  }
  if (right_scan_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(right_scan_->SaveTo(
        file_descriptor_set_map, proto->mutable_right_scan()));
  }
  if (join_expr_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(join_expr_->SaveTo(
        file_descriptor_set_map, proto->mutable_join_expr()));
  }
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedJoinScan>> ResolvedJoinScan::RestoreFrom(
    const ResolvedJoinScanProto& proto,
    const ResolvedNode::RestoreParams& params) {
  JoinType join_type =
      proto.join_type();
  std::unique_ptr<const ResolvedScan> left_scan;
  if (proto.
  has_left_scan()) {
    ZETASQL_ASSIGN_OR_RETURN(left_scan,
                     ResolvedScan::RestoreFrom(
                         proto.left_scan(), params));
  }
  std::unique_ptr<const ResolvedScan> right_scan;
  if (proto.
  has_right_scan()) {
    ZETASQL_ASSIGN_OR_RETURN(right_scan,
                     ResolvedScan::RestoreFrom(
                         proto.right_scan(), params));
  }
  std::unique_ptr<const ResolvedExpr> join_expr;
  if (proto.
  has_join_expr()) {
    ZETASQL_ASSIGN_OR_RETURN(join_expr,
                     ResolvedExpr::RestoreFrom(
                         proto.join_expr(), params));
  }
  std::vector<ResolvedColumn> column_list;
  for (const auto& elem : proto.parent().column_list()) {
    ZETASQL_ASSIGN_OR_RETURN(auto elem_restored, RestoreFromImpl(elem, params));
    column_list.push_back(std::move(elem_restored));
  }
  std::vector<std::unique_ptr<const ResolvedOption>> hint_list;
  for (const auto& elem : proto.parent().hint_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedOption> elem_restored,
                     ResolvedOption::RestoreFrom(elem, params));
    hint_list.push_back(std::move(elem_restored));
  }
  bool is_ordered =
      proto.parent().is_ordered();
  auto node = MakeResolvedJoinScan(
      std::move(column_list),
      std::move(join_type),
      std::move(left_scan),
      std::move(right_scan),
      std::move(join_expr));

  node->set_hint_list(std::move(hint_list));
  node->set_is_ordered(std::move(is_ordered));
  return std::move(node);
}

void ResolvedJoinScan::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
  if (left_scan_ != nullptr) {
    child_nodes->emplace_back(left_scan_.get());
  }
  if (right_scan_ != nullptr) {
    child_nodes->emplace_back(right_scan_.get());
  }
  if (join_expr_ != nullptr) {
    child_nodes->emplace_back(join_expr_.get());
  }
}

void ResolvedJoinScan::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
  if (left_scan_ != nullptr) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(
            &left_scan_));
    static_assert(sizeof(left_scan_) ==
                  sizeof(*(mutable_child_node_ptrs->back())),
                  "Incorrect casting of mutable child node");
  }
  if (right_scan_ != nullptr) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(
            &right_scan_));
    static_assert(sizeof(right_scan_) ==
                  sizeof(*(mutable_child_node_ptrs->back())),
                  "Incorrect casting of mutable child node");
  }
  if (join_expr_ != nullptr) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(
            &join_expr_));
    static_assert(sizeof(join_expr_) ==
                  sizeof(*(mutable_child_node_ptrs->back())),
                  "Incorrect casting of mutable child node");
  }
}

zetasql_base::Status ResolvedJoinScan::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedJoinScan(this);
}

zetasql_base::Status ResolvedJoinScan::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  if (left_scan_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(left_scan_.get()->Accept(visitor));
  }
  if (right_scan_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(right_scan_.get()->Accept(visitor));
  }
  if (join_expr_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(join_expr_.get()->Accept(visitor));
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedJoinScan::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  if (!IsDefaultValue(join_type_)) {
    fields->emplace_back("join_type", ToStringImpl(join_type_));
  }
  if (left_scan_ != nullptr) {
    fields->emplace_back("left_scan", left_scan_.get());
  }
  if (right_scan_ != nullptr) {
    fields->emplace_back("right_scan", right_scan_.get());
  }
  if (join_expr_ != nullptr) {
    fields->emplace_back("join_expr", join_expr_.get());
  }
}

zetasql_base::Status ResolvedJoinScan::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0 &&
      !IsDefaultValue(join_type_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedJoinScan::join_type not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<1)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedJoinScan::left_scan not accessed)";
  }
  if ((accessed_ & (1<<2)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedJoinScan::right_scan not accessed)";
  }
  if ((accessed_ & (1<<3)) == 0 &&
      !IsDefaultValue(join_expr_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedJoinScan::join_expr not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<1)) != 0) {
    if (left_scan_ != nullptr) {
      ZETASQL_RETURN_IF_ERROR(left_scan_->CheckFieldsAccessed());
    }
  }
  if ((accessed_ & (1<<2)) != 0) {
    if (right_scan_ != nullptr) {
      ZETASQL_RETURN_IF_ERROR(right_scan_->CheckFieldsAccessed());
    }
  }
  if ((accessed_ & (1<<3)) != 0) {
    if (join_expr_ != nullptr) {
      ZETASQL_RETURN_IF_ERROR(join_expr_->CheckFieldsAccessed());
    }
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedJoinScan::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
  if (left_scan_ != nullptr) left_scan_->ClearFieldsAccessed();
  if (right_scan_ != nullptr) right_scan_->ClearFieldsAccessed();
  if (join_expr_ != nullptr) join_expr_->ClearFieldsAccessed();
}

const ResolvedNodeKind ResolvedArrayScan::TYPE;

ResolvedArrayScan::~ResolvedArrayScan() {
}

zetasql_base::Status ResolvedArrayScan::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedScanProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_array_scan_node());
}

zetasql_base::Status ResolvedArrayScan::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedArrayScanProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  if (input_scan_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(input_scan_->SaveTo(
        file_descriptor_set_map, proto->mutable_input_scan()));
  }
  if (array_expr_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(array_expr_->SaveTo(
        file_descriptor_set_map, proto->mutable_array_expr()));
  }
  ZETASQL_RETURN_IF_ERROR(SaveToImpl(
      element_column_, file_descriptor_set_map,
      proto->mutable_element_column()));
  if (array_offset_column_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(array_offset_column_->SaveTo(
        file_descriptor_set_map, proto->mutable_array_offset_column()));
  }
  if (join_expr_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(join_expr_->SaveTo(
        file_descriptor_set_map, proto->mutable_join_expr()));
  }
  proto->set_is_outer(is_outer_);
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedArrayScan>> ResolvedArrayScan::RestoreFrom(
    const ResolvedArrayScanProto& proto,
    const ResolvedNode::RestoreParams& params) {
  std::unique_ptr<const ResolvedScan> input_scan;
  if (proto.
  has_input_scan()) {
    ZETASQL_ASSIGN_OR_RETURN(input_scan,
                     ResolvedScan::RestoreFrom(
                         proto.input_scan(), params));
  }
  std::unique_ptr<const ResolvedExpr> array_expr;
  if (proto.
  has_array_expr()) {
    ZETASQL_ASSIGN_OR_RETURN(array_expr,
                     ResolvedExpr::RestoreFrom(
                         proto.array_expr(), params));
  }
  ZETASQL_ASSIGN_OR_RETURN(ResolvedColumn element_column,
                   RestoreFromImpl(proto.element_column(),
                                   params));
  std::unique_ptr<const ResolvedColumnHolder> array_offset_column;
  if (proto.
  has_array_offset_column()) {
    ZETASQL_ASSIGN_OR_RETURN(array_offset_column,
                     ResolvedColumnHolder::RestoreFrom(
                         proto.array_offset_column(), params));
  }
  std::unique_ptr<const ResolvedExpr> join_expr;
  if (proto.
  has_join_expr()) {
    ZETASQL_ASSIGN_OR_RETURN(join_expr,
                     ResolvedExpr::RestoreFrom(
                         proto.join_expr(), params));
  }
  bool is_outer =
      proto.is_outer();
  std::vector<ResolvedColumn> column_list;
  for (const auto& elem : proto.parent().column_list()) {
    ZETASQL_ASSIGN_OR_RETURN(auto elem_restored, RestoreFromImpl(elem, params));
    column_list.push_back(std::move(elem_restored));
  }
  std::vector<std::unique_ptr<const ResolvedOption>> hint_list;
  for (const auto& elem : proto.parent().hint_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedOption> elem_restored,
                     ResolvedOption::RestoreFrom(elem, params));
    hint_list.push_back(std::move(elem_restored));
  }
  bool is_ordered =
      proto.parent().is_ordered();
  auto node = MakeResolvedArrayScan(
      std::move(column_list),
      std::move(input_scan),
      std::move(array_expr),
      std::move(element_column),
      std::move(array_offset_column),
      std::move(join_expr),
      std::move(is_outer));

  node->set_hint_list(std::move(hint_list));
  node->set_is_ordered(std::move(is_ordered));
  return std::move(node);
}

void ResolvedArrayScan::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
  if (input_scan_ != nullptr) {
    child_nodes->emplace_back(input_scan_.get());
  }
  if (array_expr_ != nullptr) {
    child_nodes->emplace_back(array_expr_.get());
  }
  if (array_offset_column_ != nullptr) {
    child_nodes->emplace_back(array_offset_column_.get());
  }
  if (join_expr_ != nullptr) {
    child_nodes->emplace_back(join_expr_.get());
  }
}

void ResolvedArrayScan::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
  if (input_scan_ != nullptr) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(
            &input_scan_));
    static_assert(sizeof(input_scan_) ==
                  sizeof(*(mutable_child_node_ptrs->back())),
                  "Incorrect casting of mutable child node");
  }
  if (array_expr_ != nullptr) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(
            &array_expr_));
    static_assert(sizeof(array_expr_) ==
                  sizeof(*(mutable_child_node_ptrs->back())),
                  "Incorrect casting of mutable child node");
  }
  if (array_offset_column_ != nullptr) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(
            &array_offset_column_));
    static_assert(sizeof(array_offset_column_) ==
                  sizeof(*(mutable_child_node_ptrs->back())),
                  "Incorrect casting of mutable child node");
  }
  if (join_expr_ != nullptr) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(
            &join_expr_));
    static_assert(sizeof(join_expr_) ==
                  sizeof(*(mutable_child_node_ptrs->back())),
                  "Incorrect casting of mutable child node");
  }
}

zetasql_base::Status ResolvedArrayScan::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedArrayScan(this);
}

zetasql_base::Status ResolvedArrayScan::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  if (input_scan_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(input_scan_.get()->Accept(visitor));
  }
  if (array_expr_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(array_expr_.get()->Accept(visitor));
  }
  if (array_offset_column_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(array_offset_column_.get()->Accept(visitor));
  }
  if (join_expr_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(join_expr_.get()->Accept(visitor));
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedArrayScan::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  if (input_scan_ != nullptr) {
    fields->emplace_back("input_scan", input_scan_.get());
  }
  if (array_expr_ != nullptr) {
    fields->emplace_back("array_expr", array_expr_.get());
  }
  {
    fields->emplace_back("element_column", ToStringImpl(element_column_));
  }
  if (array_offset_column_ != nullptr) {
    fields->emplace_back("array_offset_column", array_offset_column_.get());
  }
  if (join_expr_ != nullptr) {
    fields->emplace_back("join_expr", join_expr_.get());
  }
  if (!IsDefaultValue(is_outer_)) {
    fields->emplace_back("is_outer", ToStringImpl(is_outer_));
  }
}

zetasql_base::Status ResolvedArrayScan::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedArrayScan::input_scan not accessed)";
  }
  if ((accessed_ & (1<<1)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedArrayScan::array_expr not accessed)";
  }
  if ((accessed_ & (1<<2)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedArrayScan::element_column not accessed)";
  }
  if ((accessed_ & (1<<3)) == 0 &&
      !IsDefaultValue(array_offset_column_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedArrayScan::array_offset_column not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<4)) == 0 &&
      !IsDefaultValue(join_expr_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedArrayScan::join_expr not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<5)) == 0 &&
      !IsDefaultValue(is_outer_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedArrayScan::is_outer not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<0)) != 0) {
    if (input_scan_ != nullptr) {
      ZETASQL_RETURN_IF_ERROR(input_scan_->CheckFieldsAccessed());
    }
  }
  if ((accessed_ & (1<<1)) != 0) {
    if (array_expr_ != nullptr) {
      ZETASQL_RETURN_IF_ERROR(array_expr_->CheckFieldsAccessed());
    }
  }
  if ((accessed_ & (1<<3)) != 0) {
    if (array_offset_column_ != nullptr) {
      ZETASQL_RETURN_IF_ERROR(array_offset_column_->CheckFieldsAccessed());
    }
  }
  if ((accessed_ & (1<<4)) != 0) {
    if (join_expr_ != nullptr) {
      ZETASQL_RETURN_IF_ERROR(join_expr_->CheckFieldsAccessed());
    }
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedArrayScan::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
  if (input_scan_ != nullptr) input_scan_->ClearFieldsAccessed();
  if (array_expr_ != nullptr) array_expr_->ClearFieldsAccessed();
  if (array_offset_column_ != nullptr) array_offset_column_->ClearFieldsAccessed();
  if (join_expr_ != nullptr) join_expr_->ClearFieldsAccessed();
}

const ResolvedNodeKind ResolvedColumnHolder::TYPE;

ResolvedColumnHolder::~ResolvedColumnHolder() {
}

zetasql_base::Status ResolvedColumnHolder::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedArgumentProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_column_holder_node());
}

zetasql_base::Status ResolvedColumnHolder::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedColumnHolderProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  ZETASQL_RETURN_IF_ERROR(SaveToImpl(
      column_, file_descriptor_set_map,
      proto->mutable_column()));
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedColumnHolder>> ResolvedColumnHolder::RestoreFrom(
    const ResolvedColumnHolderProto& proto,
    const ResolvedNode::RestoreParams& params) {
  ZETASQL_ASSIGN_OR_RETURN(ResolvedColumn column,
                   RestoreFromImpl(proto.column(),
                                   params));
  auto node = MakeResolvedColumnHolder(
      std::move(column));

  return std::move(node);
}

void ResolvedColumnHolder::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
}

void ResolvedColumnHolder::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
}

zetasql_base::Status ResolvedColumnHolder::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedColumnHolder(this);
}

zetasql_base::Status ResolvedColumnHolder::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  return ::zetasql_base::OkStatus();
}

void ResolvedColumnHolder::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  {
    fields->emplace_back("column", ToStringImpl(column_));
  }
}

zetasql_base::Status ResolvedColumnHolder::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedColumnHolder::column not accessed)";
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedColumnHolder::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
}

const ResolvedNodeKind ResolvedFilterScan::TYPE;

ResolvedFilterScan::~ResolvedFilterScan() {
}

zetasql_base::Status ResolvedFilterScan::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedScanProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_filter_scan_node());
}

zetasql_base::Status ResolvedFilterScan::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedFilterScanProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  if (input_scan_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(input_scan_->SaveTo(
        file_descriptor_set_map, proto->mutable_input_scan()));
  }
  if (filter_expr_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(filter_expr_->SaveTo(
        file_descriptor_set_map, proto->mutable_filter_expr()));
  }
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedFilterScan>> ResolvedFilterScan::RestoreFrom(
    const ResolvedFilterScanProto& proto,
    const ResolvedNode::RestoreParams& params) {
  std::unique_ptr<const ResolvedScan> input_scan;
  if (proto.
  has_input_scan()) {
    ZETASQL_ASSIGN_OR_RETURN(input_scan,
                     ResolvedScan::RestoreFrom(
                         proto.input_scan(), params));
  }
  std::unique_ptr<const ResolvedExpr> filter_expr;
  if (proto.
  has_filter_expr()) {
    ZETASQL_ASSIGN_OR_RETURN(filter_expr,
                     ResolvedExpr::RestoreFrom(
                         proto.filter_expr(), params));
  }
  std::vector<ResolvedColumn> column_list;
  for (const auto& elem : proto.parent().column_list()) {
    ZETASQL_ASSIGN_OR_RETURN(auto elem_restored, RestoreFromImpl(elem, params));
    column_list.push_back(std::move(elem_restored));
  }
  std::vector<std::unique_ptr<const ResolvedOption>> hint_list;
  for (const auto& elem : proto.parent().hint_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedOption> elem_restored,
                     ResolvedOption::RestoreFrom(elem, params));
    hint_list.push_back(std::move(elem_restored));
  }
  bool is_ordered =
      proto.parent().is_ordered();
  auto node = MakeResolvedFilterScan(
      std::move(column_list),
      std::move(input_scan),
      std::move(filter_expr));

  node->set_hint_list(std::move(hint_list));
  node->set_is_ordered(std::move(is_ordered));
  return std::move(node);
}

void ResolvedFilterScan::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
  if (input_scan_ != nullptr) {
    child_nodes->emplace_back(input_scan_.get());
  }
  if (filter_expr_ != nullptr) {
    child_nodes->emplace_back(filter_expr_.get());
  }
}

void ResolvedFilterScan::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
  if (input_scan_ != nullptr) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(
            &input_scan_));
    static_assert(sizeof(input_scan_) ==
                  sizeof(*(mutable_child_node_ptrs->back())),
                  "Incorrect casting of mutable child node");
  }
  if (filter_expr_ != nullptr) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(
            &filter_expr_));
    static_assert(sizeof(filter_expr_) ==
                  sizeof(*(mutable_child_node_ptrs->back())),
                  "Incorrect casting of mutable child node");
  }
}

zetasql_base::Status ResolvedFilterScan::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedFilterScan(this);
}

zetasql_base::Status ResolvedFilterScan::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  if (input_scan_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(input_scan_.get()->Accept(visitor));
  }
  if (filter_expr_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(filter_expr_.get()->Accept(visitor));
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedFilterScan::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  if (input_scan_ != nullptr) {
    fields->emplace_back("input_scan", input_scan_.get());
  }
  if (filter_expr_ != nullptr) {
    fields->emplace_back("filter_expr", filter_expr_.get());
  }
}

zetasql_base::Status ResolvedFilterScan::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedFilterScan::input_scan not accessed)";
  }
  if ((accessed_ & (1<<1)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedFilterScan::filter_expr not accessed)";
  }
  if ((accessed_ & (1<<0)) != 0) {
    if (input_scan_ != nullptr) {
      ZETASQL_RETURN_IF_ERROR(input_scan_->CheckFieldsAccessed());
    }
  }
  if ((accessed_ & (1<<1)) != 0) {
    if (filter_expr_ != nullptr) {
      ZETASQL_RETURN_IF_ERROR(filter_expr_->CheckFieldsAccessed());
    }
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedFilterScan::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
  if (input_scan_ != nullptr) input_scan_->ClearFieldsAccessed();
  if (filter_expr_ != nullptr) filter_expr_->ClearFieldsAccessed();
}

const ResolvedNodeKind ResolvedGroupingSet::TYPE;

ResolvedGroupingSet::~ResolvedGroupingSet() {
}

zetasql_base::Status ResolvedGroupingSet::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedArgumentProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_grouping_set_node());
}

zetasql_base::Status ResolvedGroupingSet::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedGroupingSetProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  for (const auto& elem : group_by_column_list_) {
    ZETASQL_RETURN_IF_ERROR(elem->SaveTo(
      file_descriptor_set_map, proto->add_group_by_column_list()));
  }
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedGroupingSet>> ResolvedGroupingSet::RestoreFrom(
    const ResolvedGroupingSetProto& proto,
    const ResolvedNode::RestoreParams& params) {
  std::vector<std::unique_ptr<const ResolvedColumnRef>> group_by_column_list;
  for (const auto& elem : proto.group_by_column_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedColumnRef> elem_restored,
                     ResolvedColumnRef::RestoreFrom(elem, params));
    group_by_column_list.push_back(std::move(elem_restored));
  }
  auto node = MakeResolvedGroupingSet(
      std::move(group_by_column_list));

  return std::move(node);
}

void ResolvedGroupingSet::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
  for (const auto& elem : group_by_column_list_) {
    child_nodes->emplace_back(elem.get());
  }
}

void ResolvedGroupingSet::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
  for (auto& elem : group_by_column_list_) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(&elem));
  }
}

zetasql_base::Status ResolvedGroupingSet::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedGroupingSet(this);
}

zetasql_base::Status ResolvedGroupingSet::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  for (const auto& elem : group_by_column_list_) {
    ZETASQL_RETURN_IF_ERROR(elem.get()->Accept(visitor));
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedGroupingSet::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  if (!group_by_column_list_.empty()) {
    fields->emplace_back("group_by_column_list", group_by_column_list_);
  }
}

zetasql_base::Status ResolvedGroupingSet::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedGroupingSet::group_by_column_list not accessed)";
  }
  if ((accessed_ & (1<<0)) != 0) {
    for (const auto& it : group_by_column_list_) ZETASQL_RETURN_IF_ERROR(it->CheckFieldsAccessed());
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedGroupingSet::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
  for (const auto& it : group_by_column_list_) it->ClearFieldsAccessed();
}

ResolvedAggregateScanBase::~ResolvedAggregateScanBase() {
}

zetasql_base::Status ResolvedAggregateScanBase::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedScanProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_aggregate_scan_base_node());
}

zetasql_base::Status ResolvedAggregateScanBase::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedAggregateScanBaseProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  if (input_scan_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(input_scan_->SaveTo(
        file_descriptor_set_map, proto->mutable_input_scan()));
  }
  for (const auto& elem : group_by_list_) {
    ZETASQL_RETURN_IF_ERROR(elem->SaveTo(
      file_descriptor_set_map, proto->add_group_by_list()));
  }
  for (const auto& elem : aggregate_list_) {
    ZETASQL_RETURN_IF_ERROR(elem->SaveTo(
      file_descriptor_set_map, proto->add_aggregate_list()));
  }
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedAggregateScanBase>> ResolvedAggregateScanBase::RestoreFrom(
    const AnyResolvedAggregateScanBaseProto& proto,
    const ResolvedNode::RestoreParams& params) {
  switch (proto.node_case()) {
    case AnyResolvedAggregateScanBaseProto::kResolvedAggregateScanNode:
      return ResolvedAggregateScan::RestoreFrom(
          proto.resolved_aggregate_scan_node(), params);
  case AnyResolvedAggregateScanBaseProto::NODE_NOT_SET:
    return ::zetasql_base::InvalidArgumentErrorBuilder(ZETASQL_LOC)
        << "No subnode types set in ResolvedAggregateScanBaseProto";
  }
}

void ResolvedAggregateScanBase::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
  if (input_scan_ != nullptr) {
    child_nodes->emplace_back(input_scan_.get());
  }
  for (const auto& elem : group_by_list_) {
    child_nodes->emplace_back(elem.get());
  }
  for (const auto& elem : aggregate_list_) {
    child_nodes->emplace_back(elem.get());
  }
}

void ResolvedAggregateScanBase::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
  if (input_scan_ != nullptr) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(
            &input_scan_));
    static_assert(sizeof(input_scan_) ==
                  sizeof(*(mutable_child_node_ptrs->back())),
                  "Incorrect casting of mutable child node");
  }
  for (auto& elem : group_by_list_) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(&elem));
  }
  for (auto& elem : aggregate_list_) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(&elem));
  }
}

zetasql_base::Status ResolvedAggregateScanBase::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedAggregateScanBase(this);
}

zetasql_base::Status ResolvedAggregateScanBase::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  if (input_scan_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(input_scan_.get()->Accept(visitor));
  }
  for (const auto& elem : group_by_list_) {
    ZETASQL_RETURN_IF_ERROR(elem.get()->Accept(visitor));
  }
  for (const auto& elem : aggregate_list_) {
    ZETASQL_RETURN_IF_ERROR(elem.get()->Accept(visitor));
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedAggregateScanBase::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  if (input_scan_ != nullptr) {
    fields->emplace_back("input_scan", input_scan_.get());
  }
  if (!group_by_list_.empty()) {
    fields->emplace_back("group_by_list", group_by_list_);
  }
  if (!aggregate_list_.empty()) {
    fields->emplace_back("aggregate_list", aggregate_list_);
  }
}

zetasql_base::Status ResolvedAggregateScanBase::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedAggregateScanBase::input_scan not accessed)";
  }
  if ((accessed_ & (1<<1)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedAggregateScanBase::group_by_list not accessed)";
  }
  if ((accessed_ & (1<<2)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedAggregateScanBase::aggregate_list not accessed)";
  }
  if ((accessed_ & (1<<0)) != 0) {
    if (input_scan_ != nullptr) {
      ZETASQL_RETURN_IF_ERROR(input_scan_->CheckFieldsAccessed());
    }
  }
  if ((accessed_ & (1<<1)) != 0) {
    for (const auto& it : group_by_list_) ZETASQL_RETURN_IF_ERROR(it->CheckFieldsAccessed());
  }
  if ((accessed_ & (1<<2)) != 0) {
    for (const auto& it : aggregate_list_) ZETASQL_RETURN_IF_ERROR(it->CheckFieldsAccessed());
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedAggregateScanBase::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
  if (input_scan_ != nullptr) input_scan_->ClearFieldsAccessed();
  for (const auto& it : group_by_list_) it->ClearFieldsAccessed();
  for (const auto& it : aggregate_list_) it->ClearFieldsAccessed();
}

const ResolvedNodeKind ResolvedAggregateScan::TYPE;

ResolvedAggregateScan::~ResolvedAggregateScan() {
}

zetasql_base::Status ResolvedAggregateScan::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedAggregateScanBaseProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_aggregate_scan_node());
}

zetasql_base::Status ResolvedAggregateScan::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedAggregateScanProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  for (const auto& elem : grouping_set_list_) {
    ZETASQL_RETURN_IF_ERROR(elem->SaveTo(
      file_descriptor_set_map, proto->add_grouping_set_list()));
  }
  for (const auto& elem : rollup_column_list_) {
    ZETASQL_RETURN_IF_ERROR(elem->SaveTo(
      file_descriptor_set_map, proto->add_rollup_column_list()));
  }
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedAggregateScan>> ResolvedAggregateScan::RestoreFrom(
    const ResolvedAggregateScanProto& proto,
    const ResolvedNode::RestoreParams& params) {
  std::vector<std::unique_ptr<const ResolvedGroupingSet>> grouping_set_list;
  for (const auto& elem : proto.grouping_set_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedGroupingSet> elem_restored,
                     ResolvedGroupingSet::RestoreFrom(elem, params));
    grouping_set_list.push_back(std::move(elem_restored));
  }
  std::vector<std::unique_ptr<const ResolvedColumnRef>> rollup_column_list;
  for (const auto& elem : proto.rollup_column_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedColumnRef> elem_restored,
                     ResolvedColumnRef::RestoreFrom(elem, params));
    rollup_column_list.push_back(std::move(elem_restored));
  }
  std::vector<ResolvedColumn> column_list;
  for (const auto& elem : proto.parent().parent().column_list()) {
    ZETASQL_ASSIGN_OR_RETURN(auto elem_restored, RestoreFromImpl(elem, params));
    column_list.push_back(std::move(elem_restored));
  }
  std::vector<std::unique_ptr<const ResolvedOption>> hint_list;
  for (const auto& elem : proto.parent().parent().hint_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedOption> elem_restored,
                     ResolvedOption::RestoreFrom(elem, params));
    hint_list.push_back(std::move(elem_restored));
  }
  bool is_ordered =
      proto.parent().parent().is_ordered();
  std::unique_ptr<const ResolvedScan> input_scan;
  if (proto.parent().
  has_input_scan()) {
    ZETASQL_ASSIGN_OR_RETURN(input_scan,
                     ResolvedScan::RestoreFrom(
                         proto.parent().input_scan(), params));
  }
  std::vector<std::unique_ptr<const ResolvedComputedColumn>> group_by_list;
  for (const auto& elem : proto.parent().group_by_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedComputedColumn> elem_restored,
                     ResolvedComputedColumn::RestoreFrom(elem, params));
    group_by_list.push_back(std::move(elem_restored));
  }
  std::vector<std::unique_ptr<const ResolvedComputedColumn>> aggregate_list;
  for (const auto& elem : proto.parent().aggregate_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedComputedColumn> elem_restored,
                     ResolvedComputedColumn::RestoreFrom(elem, params));
    aggregate_list.push_back(std::move(elem_restored));
  }
  auto node = MakeResolvedAggregateScan(
      std::move(column_list),
      std::move(input_scan),
      std::move(group_by_list),
      std::move(aggregate_list),
      std::move(grouping_set_list),
      std::move(rollup_column_list));

  node->set_hint_list(std::move(hint_list));
  node->set_is_ordered(std::move(is_ordered));
  return std::move(node);
}

void ResolvedAggregateScan::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
  for (const auto& elem : grouping_set_list_) {
    child_nodes->emplace_back(elem.get());
  }
  for (const auto& elem : rollup_column_list_) {
    child_nodes->emplace_back(elem.get());
  }
}

void ResolvedAggregateScan::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
  for (auto& elem : grouping_set_list_) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(&elem));
  }
  for (auto& elem : rollup_column_list_) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(&elem));
  }
}

zetasql_base::Status ResolvedAggregateScan::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedAggregateScan(this);
}

zetasql_base::Status ResolvedAggregateScan::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  for (const auto& elem : grouping_set_list_) {
    ZETASQL_RETURN_IF_ERROR(elem.get()->Accept(visitor));
  }
  for (const auto& elem : rollup_column_list_) {
    ZETASQL_RETURN_IF_ERROR(elem.get()->Accept(visitor));
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedAggregateScan::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  if (!grouping_set_list_.empty()) {
    fields->emplace_back("grouping_set_list", grouping_set_list_);
  }
  if (!rollup_column_list_.empty()) {
    fields->emplace_back("rollup_column_list", rollup_column_list_);
  }
}

zetasql_base::Status ResolvedAggregateScan::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0 &&
      !IsDefaultValue(grouping_set_list_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedAggregateScan::grouping_set_list not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<1)) == 0 &&
      !IsDefaultValue(rollup_column_list_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedAggregateScan::rollup_column_list not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<0)) != 0) {
    for (const auto& it : grouping_set_list_) ZETASQL_RETURN_IF_ERROR(it->CheckFieldsAccessed());
  }
  if ((accessed_ & (1<<1)) != 0) {
    for (const auto& it : rollup_column_list_) ZETASQL_RETURN_IF_ERROR(it->CheckFieldsAccessed());
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedAggregateScan::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
  for (const auto& it : grouping_set_list_) it->ClearFieldsAccessed();
  for (const auto& it : rollup_column_list_) it->ClearFieldsAccessed();
}

const ResolvedNodeKind ResolvedSetOperationItem::TYPE;

ResolvedSetOperationItem::~ResolvedSetOperationItem() {
}

zetasql_base::Status ResolvedSetOperationItem::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedArgumentProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_set_operation_item_node());
}

zetasql_base::Status ResolvedSetOperationItem::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedSetOperationItemProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  if (scan_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(scan_->SaveTo(
        file_descriptor_set_map, proto->mutable_scan()));
  }
  for (const auto& elem : output_column_list_) {
    ZETASQL_RETURN_IF_ERROR(SaveToImpl(
        elem, file_descriptor_set_map, proto->add_output_column_list()));
  }
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedSetOperationItem>> ResolvedSetOperationItem::RestoreFrom(
    const ResolvedSetOperationItemProto& proto,
    const ResolvedNode::RestoreParams& params) {
  std::unique_ptr<const ResolvedScan> scan;
  if (proto.
  has_scan()) {
    ZETASQL_ASSIGN_OR_RETURN(scan,
                     ResolvedScan::RestoreFrom(
                         proto.scan(), params));
  }
  std::vector<ResolvedColumn> output_column_list;
  for (const auto& elem : proto.output_column_list()) {
    ZETASQL_ASSIGN_OR_RETURN(auto elem_restored, RestoreFromImpl(elem, params));
    output_column_list.push_back(std::move(elem_restored));
  }
  auto node = MakeResolvedSetOperationItem(
      std::move(scan),
      std::move(output_column_list));

  return std::move(node);
}

void ResolvedSetOperationItem::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
  if (scan_ != nullptr) {
    child_nodes->emplace_back(scan_.get());
  }
}

void ResolvedSetOperationItem::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
  if (scan_ != nullptr) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(
            &scan_));
    static_assert(sizeof(scan_) ==
                  sizeof(*(mutable_child_node_ptrs->back())),
                  "Incorrect casting of mutable child node");
  }
}

zetasql_base::Status ResolvedSetOperationItem::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedSetOperationItem(this);
}

zetasql_base::Status ResolvedSetOperationItem::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  if (scan_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(scan_.get()->Accept(visitor));
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedSetOperationItem::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  if (scan_ != nullptr) {
    fields->emplace_back("scan", scan_.get());
  }
  {
    fields->emplace_back("output_column_list", ToStringImpl(output_column_list_));
  }
}

zetasql_base::Status ResolvedSetOperationItem::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedSetOperationItem::scan not accessed)";
  }
  if ((accessed_ & (1<<1)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedSetOperationItem::output_column_list not accessed)";
  }
  if ((accessed_ & (1<<0)) != 0) {
    if (scan_ != nullptr) {
      ZETASQL_RETURN_IF_ERROR(scan_->CheckFieldsAccessed());
    }
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedSetOperationItem::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
  if (scan_ != nullptr) scan_->ClearFieldsAccessed();
}

const ResolvedNodeKind ResolvedSetOperationScan::TYPE;

const ResolvedSetOperationScan::SetOperationType ResolvedSetOperationScan::UNION_ALL;
const ResolvedSetOperationScan::SetOperationType ResolvedSetOperationScan::UNION_DISTINCT;
const ResolvedSetOperationScan::SetOperationType ResolvedSetOperationScan::INTERSECT_ALL;
const ResolvedSetOperationScan::SetOperationType ResolvedSetOperationScan::INTERSECT_DISTINCT;
const ResolvedSetOperationScan::SetOperationType ResolvedSetOperationScan::EXCEPT_ALL;
const ResolvedSetOperationScan::SetOperationType ResolvedSetOperationScan::EXCEPT_DISTINCT;

ResolvedSetOperationScan::~ResolvedSetOperationScan() {
}

zetasql_base::Status ResolvedSetOperationScan::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedScanProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_set_operation_scan_node());
}

zetasql_base::Status ResolvedSetOperationScan::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedSetOperationScanProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  proto->set_op_type(op_type_);
  for (const auto& elem : input_item_list_) {
    ZETASQL_RETURN_IF_ERROR(elem->SaveTo(
      file_descriptor_set_map, proto->add_input_item_list()));
  }
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedSetOperationScan>> ResolvedSetOperationScan::RestoreFrom(
    const ResolvedSetOperationScanProto& proto,
    const ResolvedNode::RestoreParams& params) {
  SetOperationType op_type =
      proto.op_type();
  std::vector<std::unique_ptr<const ResolvedSetOperationItem>> input_item_list;
  for (const auto& elem : proto.input_item_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedSetOperationItem> elem_restored,
                     ResolvedSetOperationItem::RestoreFrom(elem, params));
    input_item_list.push_back(std::move(elem_restored));
  }
  std::vector<ResolvedColumn> column_list;
  for (const auto& elem : proto.parent().column_list()) {
    ZETASQL_ASSIGN_OR_RETURN(auto elem_restored, RestoreFromImpl(elem, params));
    column_list.push_back(std::move(elem_restored));
  }
  std::vector<std::unique_ptr<const ResolvedOption>> hint_list;
  for (const auto& elem : proto.parent().hint_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedOption> elem_restored,
                     ResolvedOption::RestoreFrom(elem, params));
    hint_list.push_back(std::move(elem_restored));
  }
  bool is_ordered =
      proto.parent().is_ordered();
  auto node = MakeResolvedSetOperationScan(
      std::move(column_list),
      std::move(op_type),
      std::move(input_item_list));

  node->set_hint_list(std::move(hint_list));
  node->set_is_ordered(std::move(is_ordered));
  return std::move(node);
}

void ResolvedSetOperationScan::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
  for (const auto& elem : input_item_list_) {
    child_nodes->emplace_back(elem.get());
  }
}

void ResolvedSetOperationScan::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
  for (auto& elem : input_item_list_) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(&elem));
  }
}

zetasql_base::Status ResolvedSetOperationScan::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedSetOperationScan(this);
}

zetasql_base::Status ResolvedSetOperationScan::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  for (const auto& elem : input_item_list_) {
    ZETASQL_RETURN_IF_ERROR(elem.get()->Accept(visitor));
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedSetOperationScan::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  {
    fields->emplace_back("op_type", ToStringImpl(op_type_));
  }
  if (!input_item_list_.empty()) {
    fields->emplace_back("input_item_list", input_item_list_);
  }
}

zetasql_base::Status ResolvedSetOperationScan::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedSetOperationScan::op_type not accessed)";
  }
  if ((accessed_ & (1<<1)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedSetOperationScan::input_item_list not accessed)";
  }
  if ((accessed_ & (1<<1)) != 0) {
    for (const auto& it : input_item_list_) ZETASQL_RETURN_IF_ERROR(it->CheckFieldsAccessed());
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedSetOperationScan::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
  for (const auto& it : input_item_list_) it->ClearFieldsAccessed();
}

const ResolvedNodeKind ResolvedOrderByScan::TYPE;

ResolvedOrderByScan::~ResolvedOrderByScan() {
}

zetasql_base::Status ResolvedOrderByScan::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedScanProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_order_by_scan_node());
}

zetasql_base::Status ResolvedOrderByScan::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedOrderByScanProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  if (input_scan_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(input_scan_->SaveTo(
        file_descriptor_set_map, proto->mutable_input_scan()));
  }
  for (const auto& elem : order_by_item_list_) {
    ZETASQL_RETURN_IF_ERROR(elem->SaveTo(
      file_descriptor_set_map, proto->add_order_by_item_list()));
  }
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedOrderByScan>> ResolvedOrderByScan::RestoreFrom(
    const ResolvedOrderByScanProto& proto,
    const ResolvedNode::RestoreParams& params) {
  std::unique_ptr<const ResolvedScan> input_scan;
  if (proto.
  has_input_scan()) {
    ZETASQL_ASSIGN_OR_RETURN(input_scan,
                     ResolvedScan::RestoreFrom(
                         proto.input_scan(), params));
  }
  std::vector<std::unique_ptr<const ResolvedOrderByItem>> order_by_item_list;
  for (const auto& elem : proto.order_by_item_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedOrderByItem> elem_restored,
                     ResolvedOrderByItem::RestoreFrom(elem, params));
    order_by_item_list.push_back(std::move(elem_restored));
  }
  std::vector<ResolvedColumn> column_list;
  for (const auto& elem : proto.parent().column_list()) {
    ZETASQL_ASSIGN_OR_RETURN(auto elem_restored, RestoreFromImpl(elem, params));
    column_list.push_back(std::move(elem_restored));
  }
  std::vector<std::unique_ptr<const ResolvedOption>> hint_list;
  for (const auto& elem : proto.parent().hint_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedOption> elem_restored,
                     ResolvedOption::RestoreFrom(elem, params));
    hint_list.push_back(std::move(elem_restored));
  }
  bool is_ordered =
      proto.parent().is_ordered();
  auto node = MakeResolvedOrderByScan(
      std::move(column_list),
      std::move(input_scan),
      std::move(order_by_item_list));

  node->set_hint_list(std::move(hint_list));
  node->set_is_ordered(std::move(is_ordered));
  return std::move(node);
}

void ResolvedOrderByScan::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
  if (input_scan_ != nullptr) {
    child_nodes->emplace_back(input_scan_.get());
  }
  for (const auto& elem : order_by_item_list_) {
    child_nodes->emplace_back(elem.get());
  }
}

void ResolvedOrderByScan::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
  if (input_scan_ != nullptr) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(
            &input_scan_));
    static_assert(sizeof(input_scan_) ==
                  sizeof(*(mutable_child_node_ptrs->back())),
                  "Incorrect casting of mutable child node");
  }
  for (auto& elem : order_by_item_list_) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(&elem));
  }
}

zetasql_base::Status ResolvedOrderByScan::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedOrderByScan(this);
}

zetasql_base::Status ResolvedOrderByScan::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  if (input_scan_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(input_scan_.get()->Accept(visitor));
  }
  for (const auto& elem : order_by_item_list_) {
    ZETASQL_RETURN_IF_ERROR(elem.get()->Accept(visitor));
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedOrderByScan::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  if (input_scan_ != nullptr) {
    fields->emplace_back("input_scan", input_scan_.get());
  }
  if (!order_by_item_list_.empty()) {
    fields->emplace_back("order_by_item_list", order_by_item_list_);
  }
}

zetasql_base::Status ResolvedOrderByScan::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedOrderByScan::input_scan not accessed)";
  }
  if ((accessed_ & (1<<1)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedOrderByScan::order_by_item_list not accessed)";
  }
  if ((accessed_ & (1<<0)) != 0) {
    if (input_scan_ != nullptr) {
      ZETASQL_RETURN_IF_ERROR(input_scan_->CheckFieldsAccessed());
    }
  }
  if ((accessed_ & (1<<1)) != 0) {
    for (const auto& it : order_by_item_list_) ZETASQL_RETURN_IF_ERROR(it->CheckFieldsAccessed());
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedOrderByScan::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
  if (input_scan_ != nullptr) input_scan_->ClearFieldsAccessed();
  for (const auto& it : order_by_item_list_) it->ClearFieldsAccessed();
}

const ResolvedNodeKind ResolvedLimitOffsetScan::TYPE;

ResolvedLimitOffsetScan::~ResolvedLimitOffsetScan() {
}

zetasql_base::Status ResolvedLimitOffsetScan::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedScanProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_limit_offset_scan_node());
}

zetasql_base::Status ResolvedLimitOffsetScan::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedLimitOffsetScanProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  if (input_scan_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(input_scan_->SaveTo(
        file_descriptor_set_map, proto->mutable_input_scan()));
  }
  if (limit_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(limit_->SaveTo(
        file_descriptor_set_map, proto->mutable_limit()));
  }
  if (offset_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(offset_->SaveTo(
        file_descriptor_set_map, proto->mutable_offset()));
  }
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedLimitOffsetScan>> ResolvedLimitOffsetScan::RestoreFrom(
    const ResolvedLimitOffsetScanProto& proto,
    const ResolvedNode::RestoreParams& params) {
  std::unique_ptr<const ResolvedScan> input_scan;
  if (proto.
  has_input_scan()) {
    ZETASQL_ASSIGN_OR_RETURN(input_scan,
                     ResolvedScan::RestoreFrom(
                         proto.input_scan(), params));
  }
  std::unique_ptr<const ResolvedExpr> limit;
  if (proto.
  has_limit()) {
    ZETASQL_ASSIGN_OR_RETURN(limit,
                     ResolvedExpr::RestoreFrom(
                         proto.limit(), params));
  }
  std::unique_ptr<const ResolvedExpr> offset;
  if (proto.
  has_offset()) {
    ZETASQL_ASSIGN_OR_RETURN(offset,
                     ResolvedExpr::RestoreFrom(
                         proto.offset(), params));
  }
  std::vector<ResolvedColumn> column_list;
  for (const auto& elem : proto.parent().column_list()) {
    ZETASQL_ASSIGN_OR_RETURN(auto elem_restored, RestoreFromImpl(elem, params));
    column_list.push_back(std::move(elem_restored));
  }
  std::vector<std::unique_ptr<const ResolvedOption>> hint_list;
  for (const auto& elem : proto.parent().hint_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedOption> elem_restored,
                     ResolvedOption::RestoreFrom(elem, params));
    hint_list.push_back(std::move(elem_restored));
  }
  bool is_ordered =
      proto.parent().is_ordered();
  auto node = MakeResolvedLimitOffsetScan(
      std::move(column_list),
      std::move(input_scan),
      std::move(limit),
      std::move(offset));

  node->set_hint_list(std::move(hint_list));
  node->set_is_ordered(std::move(is_ordered));
  return std::move(node);
}

void ResolvedLimitOffsetScan::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
  if (input_scan_ != nullptr) {
    child_nodes->emplace_back(input_scan_.get());
  }
  if (limit_ != nullptr) {
    child_nodes->emplace_back(limit_.get());
  }
  if (offset_ != nullptr) {
    child_nodes->emplace_back(offset_.get());
  }
}

void ResolvedLimitOffsetScan::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
  if (input_scan_ != nullptr) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(
            &input_scan_));
    static_assert(sizeof(input_scan_) ==
                  sizeof(*(mutable_child_node_ptrs->back())),
                  "Incorrect casting of mutable child node");
  }
  if (limit_ != nullptr) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(
            &limit_));
    static_assert(sizeof(limit_) ==
                  sizeof(*(mutable_child_node_ptrs->back())),
                  "Incorrect casting of mutable child node");
  }
  if (offset_ != nullptr) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(
            &offset_));
    static_assert(sizeof(offset_) ==
                  sizeof(*(mutable_child_node_ptrs->back())),
                  "Incorrect casting of mutable child node");
  }
}

zetasql_base::Status ResolvedLimitOffsetScan::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedLimitOffsetScan(this);
}

zetasql_base::Status ResolvedLimitOffsetScan::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  if (input_scan_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(input_scan_.get()->Accept(visitor));
  }
  if (limit_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(limit_.get()->Accept(visitor));
  }
  if (offset_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(offset_.get()->Accept(visitor));
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedLimitOffsetScan::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  if (input_scan_ != nullptr) {
    fields->emplace_back("input_scan", input_scan_.get());
  }
  if (limit_ != nullptr) {
    fields->emplace_back("limit", limit_.get());
  }
  if (offset_ != nullptr) {
    fields->emplace_back("offset", offset_.get());
  }
}

zetasql_base::Status ResolvedLimitOffsetScan::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedLimitOffsetScan::input_scan not accessed)";
  }
  if ((accessed_ & (1<<1)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedLimitOffsetScan::limit not accessed)";
  }
  if ((accessed_ & (1<<2)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedLimitOffsetScan::offset not accessed)";
  }
  if ((accessed_ & (1<<0)) != 0) {
    if (input_scan_ != nullptr) {
      ZETASQL_RETURN_IF_ERROR(input_scan_->CheckFieldsAccessed());
    }
  }
  if ((accessed_ & (1<<1)) != 0) {
    if (limit_ != nullptr) {
      ZETASQL_RETURN_IF_ERROR(limit_->CheckFieldsAccessed());
    }
  }
  if ((accessed_ & (1<<2)) != 0) {
    if (offset_ != nullptr) {
      ZETASQL_RETURN_IF_ERROR(offset_->CheckFieldsAccessed());
    }
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedLimitOffsetScan::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
  if (input_scan_ != nullptr) input_scan_->ClearFieldsAccessed();
  if (limit_ != nullptr) limit_->ClearFieldsAccessed();
  if (offset_ != nullptr) offset_->ClearFieldsAccessed();
}

const ResolvedNodeKind ResolvedWithRefScan::TYPE;

ResolvedWithRefScan::~ResolvedWithRefScan() {
}

zetasql_base::Status ResolvedWithRefScan::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedScanProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_with_ref_scan_node());
}

zetasql_base::Status ResolvedWithRefScan::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedWithRefScanProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  proto->set_with_query_name(with_query_name_);
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedWithRefScan>> ResolvedWithRefScan::RestoreFrom(
    const ResolvedWithRefScanProto& proto,
    const ResolvedNode::RestoreParams& params) {
  std::string with_query_name =
      proto.with_query_name();
  std::vector<ResolvedColumn> column_list;
  for (const auto& elem : proto.parent().column_list()) {
    ZETASQL_ASSIGN_OR_RETURN(auto elem_restored, RestoreFromImpl(elem, params));
    column_list.push_back(std::move(elem_restored));
  }
  std::vector<std::unique_ptr<const ResolvedOption>> hint_list;
  for (const auto& elem : proto.parent().hint_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedOption> elem_restored,
                     ResolvedOption::RestoreFrom(elem, params));
    hint_list.push_back(std::move(elem_restored));
  }
  bool is_ordered =
      proto.parent().is_ordered();
  auto node = MakeResolvedWithRefScan(
      std::move(column_list),
      std::move(with_query_name));

  node->set_hint_list(std::move(hint_list));
  node->set_is_ordered(std::move(is_ordered));
  return std::move(node);
}

void ResolvedWithRefScan::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
}

void ResolvedWithRefScan::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
}

zetasql_base::Status ResolvedWithRefScan::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedWithRefScan(this);
}

zetasql_base::Status ResolvedWithRefScan::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  return ::zetasql_base::OkStatus();
}

void ResolvedWithRefScan::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  {
    fields->emplace_back("with_query_name", ToStringImpl(with_query_name_));
  }
}

zetasql_base::Status ResolvedWithRefScan::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedWithRefScan::with_query_name not accessed)";
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedWithRefScan::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
}

const ResolvedNodeKind ResolvedAnalyticScan::TYPE;

ResolvedAnalyticScan::~ResolvedAnalyticScan() {
}

zetasql_base::Status ResolvedAnalyticScan::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedScanProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_analytic_scan_node());
}

zetasql_base::Status ResolvedAnalyticScan::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedAnalyticScanProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  if (input_scan_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(input_scan_->SaveTo(
        file_descriptor_set_map, proto->mutable_input_scan()));
  }
  for (const auto& elem : function_group_list_) {
    ZETASQL_RETURN_IF_ERROR(elem->SaveTo(
      file_descriptor_set_map, proto->add_function_group_list()));
  }
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedAnalyticScan>> ResolvedAnalyticScan::RestoreFrom(
    const ResolvedAnalyticScanProto& proto,
    const ResolvedNode::RestoreParams& params) {
  std::unique_ptr<const ResolvedScan> input_scan;
  if (proto.
  has_input_scan()) {
    ZETASQL_ASSIGN_OR_RETURN(input_scan,
                     ResolvedScan::RestoreFrom(
                         proto.input_scan(), params));
  }
  std::vector<std::unique_ptr<const ResolvedAnalyticFunctionGroup>> function_group_list;
  for (const auto& elem : proto.function_group_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedAnalyticFunctionGroup> elem_restored,
                     ResolvedAnalyticFunctionGroup::RestoreFrom(elem, params));
    function_group_list.push_back(std::move(elem_restored));
  }
  std::vector<ResolvedColumn> column_list;
  for (const auto& elem : proto.parent().column_list()) {
    ZETASQL_ASSIGN_OR_RETURN(auto elem_restored, RestoreFromImpl(elem, params));
    column_list.push_back(std::move(elem_restored));
  }
  std::vector<std::unique_ptr<const ResolvedOption>> hint_list;
  for (const auto& elem : proto.parent().hint_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedOption> elem_restored,
                     ResolvedOption::RestoreFrom(elem, params));
    hint_list.push_back(std::move(elem_restored));
  }
  bool is_ordered =
      proto.parent().is_ordered();
  auto node = MakeResolvedAnalyticScan(
      std::move(column_list),
      std::move(input_scan),
      std::move(function_group_list));

  node->set_hint_list(std::move(hint_list));
  node->set_is_ordered(std::move(is_ordered));
  return std::move(node);
}

void ResolvedAnalyticScan::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
  if (input_scan_ != nullptr) {
    child_nodes->emplace_back(input_scan_.get());
  }
  for (const auto& elem : function_group_list_) {
    child_nodes->emplace_back(elem.get());
  }
}

void ResolvedAnalyticScan::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
  if (input_scan_ != nullptr) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(
            &input_scan_));
    static_assert(sizeof(input_scan_) ==
                  sizeof(*(mutable_child_node_ptrs->back())),
                  "Incorrect casting of mutable child node");
  }
  for (auto& elem : function_group_list_) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(&elem));
  }
}

zetasql_base::Status ResolvedAnalyticScan::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedAnalyticScan(this);
}

zetasql_base::Status ResolvedAnalyticScan::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  if (input_scan_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(input_scan_.get()->Accept(visitor));
  }
  for (const auto& elem : function_group_list_) {
    ZETASQL_RETURN_IF_ERROR(elem.get()->Accept(visitor));
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedAnalyticScan::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  if (input_scan_ != nullptr) {
    fields->emplace_back("input_scan", input_scan_.get());
  }
  if (!function_group_list_.empty()) {
    fields->emplace_back("function_group_list", function_group_list_);
  }
}

zetasql_base::Status ResolvedAnalyticScan::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedAnalyticScan::input_scan not accessed)";
  }
  if ((accessed_ & (1<<1)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedAnalyticScan::function_group_list not accessed)";
  }
  if ((accessed_ & (1<<0)) != 0) {
    if (input_scan_ != nullptr) {
      ZETASQL_RETURN_IF_ERROR(input_scan_->CheckFieldsAccessed());
    }
  }
  if ((accessed_ & (1<<1)) != 0) {
    for (const auto& it : function_group_list_) ZETASQL_RETURN_IF_ERROR(it->CheckFieldsAccessed());
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedAnalyticScan::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
  if (input_scan_ != nullptr) input_scan_->ClearFieldsAccessed();
  for (const auto& it : function_group_list_) it->ClearFieldsAccessed();
}

const ResolvedNodeKind ResolvedSampleScan::TYPE;

const ResolvedSampleScan::SampleUnit ResolvedSampleScan::ROWS;
const ResolvedSampleScan::SampleUnit ResolvedSampleScan::PERCENT;

ResolvedSampleScan::~ResolvedSampleScan() {
}

zetasql_base::Status ResolvedSampleScan::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedScanProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_sample_scan_node());
}

zetasql_base::Status ResolvedSampleScan::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedSampleScanProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  if (input_scan_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(input_scan_->SaveTo(
        file_descriptor_set_map, proto->mutable_input_scan()));
  }
  proto->set_method(method_);
  if (size_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(size_->SaveTo(
        file_descriptor_set_map, proto->mutable_size()));
  }
  proto->set_unit(unit_);
  if (repeatable_argument_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(repeatable_argument_->SaveTo(
        file_descriptor_set_map, proto->mutable_repeatable_argument()));
  }
  if (weight_column_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(weight_column_->SaveTo(
        file_descriptor_set_map, proto->mutable_weight_column()));
  }
  for (const auto& elem : partition_by_list_) {
    ZETASQL_RETURN_IF_ERROR(elem->SaveTo(
      file_descriptor_set_map, proto->add_partition_by_list()));
  }
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedSampleScan>> ResolvedSampleScan::RestoreFrom(
    const ResolvedSampleScanProto& proto,
    const ResolvedNode::RestoreParams& params) {
  std::unique_ptr<const ResolvedScan> input_scan;
  if (proto.
  has_input_scan()) {
    ZETASQL_ASSIGN_OR_RETURN(input_scan,
                     ResolvedScan::RestoreFrom(
                         proto.input_scan(), params));
  }
  std::string method =
      proto.method();
  std::unique_ptr<const ResolvedExpr> size;
  if (proto.
  has_size()) {
    ZETASQL_ASSIGN_OR_RETURN(size,
                     ResolvedExpr::RestoreFrom(
                         proto.size(), params));
  }
  SampleUnit unit =
      proto.unit();
  std::unique_ptr<const ResolvedExpr> repeatable_argument;
  if (proto.
  has_repeatable_argument()) {
    ZETASQL_ASSIGN_OR_RETURN(repeatable_argument,
                     ResolvedExpr::RestoreFrom(
                         proto.repeatable_argument(), params));
  }
  std::unique_ptr<const ResolvedColumnHolder> weight_column;
  if (proto.
  has_weight_column()) {
    ZETASQL_ASSIGN_OR_RETURN(weight_column,
                     ResolvedColumnHolder::RestoreFrom(
                         proto.weight_column(), params));
  }
  std::vector<std::unique_ptr<const ResolvedExpr>> partition_by_list;
  for (const auto& elem : proto.partition_by_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedExpr> elem_restored,
                     ResolvedExpr::RestoreFrom(elem, params));
    partition_by_list.push_back(std::move(elem_restored));
  }
  std::vector<ResolvedColumn> column_list;
  for (const auto& elem : proto.parent().column_list()) {
    ZETASQL_ASSIGN_OR_RETURN(auto elem_restored, RestoreFromImpl(elem, params));
    column_list.push_back(std::move(elem_restored));
  }
  std::vector<std::unique_ptr<const ResolvedOption>> hint_list;
  for (const auto& elem : proto.parent().hint_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedOption> elem_restored,
                     ResolvedOption::RestoreFrom(elem, params));
    hint_list.push_back(std::move(elem_restored));
  }
  bool is_ordered =
      proto.parent().is_ordered();
  auto node = MakeResolvedSampleScan(
      std::move(column_list),
      std::move(input_scan),
      std::move(method),
      std::move(size),
      std::move(unit),
      std::move(repeatable_argument),
      std::move(weight_column),
      std::move(partition_by_list));

  node->set_hint_list(std::move(hint_list));
  node->set_is_ordered(std::move(is_ordered));
  return std::move(node);
}

void ResolvedSampleScan::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
  if (input_scan_ != nullptr) {
    child_nodes->emplace_back(input_scan_.get());
  }
  if (size_ != nullptr) {
    child_nodes->emplace_back(size_.get());
  }
  if (repeatable_argument_ != nullptr) {
    child_nodes->emplace_back(repeatable_argument_.get());
  }
  if (weight_column_ != nullptr) {
    child_nodes->emplace_back(weight_column_.get());
  }
  for (const auto& elem : partition_by_list_) {
    child_nodes->emplace_back(elem.get());
  }
}

void ResolvedSampleScan::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
  if (input_scan_ != nullptr) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(
            &input_scan_));
    static_assert(sizeof(input_scan_) ==
                  sizeof(*(mutable_child_node_ptrs->back())),
                  "Incorrect casting of mutable child node");
  }
  if (size_ != nullptr) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(
            &size_));
    static_assert(sizeof(size_) ==
                  sizeof(*(mutable_child_node_ptrs->back())),
                  "Incorrect casting of mutable child node");
  }
  if (repeatable_argument_ != nullptr) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(
            &repeatable_argument_));
    static_assert(sizeof(repeatable_argument_) ==
                  sizeof(*(mutable_child_node_ptrs->back())),
                  "Incorrect casting of mutable child node");
  }
  if (weight_column_ != nullptr) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(
            &weight_column_));
    static_assert(sizeof(weight_column_) ==
                  sizeof(*(mutable_child_node_ptrs->back())),
                  "Incorrect casting of mutable child node");
  }
  for (auto& elem : partition_by_list_) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(&elem));
  }
}

zetasql_base::Status ResolvedSampleScan::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedSampleScan(this);
}

zetasql_base::Status ResolvedSampleScan::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  if (input_scan_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(input_scan_.get()->Accept(visitor));
  }
  if (size_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(size_.get()->Accept(visitor));
  }
  if (repeatable_argument_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(repeatable_argument_.get()->Accept(visitor));
  }
  if (weight_column_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(weight_column_.get()->Accept(visitor));
  }
  for (const auto& elem : partition_by_list_) {
    ZETASQL_RETURN_IF_ERROR(elem.get()->Accept(visitor));
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedSampleScan::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  if (input_scan_ != nullptr) {
    fields->emplace_back("input_scan", input_scan_.get());
  }
  {
    fields->emplace_back("method", ToStringImpl(method_));
  }
  if (size_ != nullptr) {
    fields->emplace_back("size", size_.get());
  }
  {
    fields->emplace_back("unit", ToStringImpl(unit_));
  }
  if (repeatable_argument_ != nullptr) {
    fields->emplace_back("repeatable_argument", repeatable_argument_.get());
  }
  if (weight_column_ != nullptr) {
    fields->emplace_back("weight_column", weight_column_.get());
  }
  if (!partition_by_list_.empty()) {
    fields->emplace_back("partition_by_list", partition_by_list_);
  }
}

zetasql_base::Status ResolvedSampleScan::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedSampleScan::input_scan not accessed)";
  }
  if ((accessed_ & (1<<1)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedSampleScan::method not accessed)";
  }
  if ((accessed_ & (1<<2)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedSampleScan::size not accessed)";
  }
  if ((accessed_ & (1<<3)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedSampleScan::unit not accessed)";
  }
  if ((accessed_ & (1<<4)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedSampleScan::repeatable_argument not accessed)";
  }
  if ((accessed_ & (1<<5)) == 0 &&
      !IsDefaultValue(weight_column_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedSampleScan::weight_column not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<6)) == 0 &&
      !IsDefaultValue(partition_by_list_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedSampleScan::partition_by_list not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<0)) != 0) {
    if (input_scan_ != nullptr) {
      ZETASQL_RETURN_IF_ERROR(input_scan_->CheckFieldsAccessed());
    }
  }
  if ((accessed_ & (1<<2)) != 0) {
    if (size_ != nullptr) {
      ZETASQL_RETURN_IF_ERROR(size_->CheckFieldsAccessed());
    }
  }
  if ((accessed_ & (1<<4)) != 0) {
    if (repeatable_argument_ != nullptr) {
      ZETASQL_RETURN_IF_ERROR(repeatable_argument_->CheckFieldsAccessed());
    }
  }
  if ((accessed_ & (1<<5)) != 0) {
    if (weight_column_ != nullptr) {
      ZETASQL_RETURN_IF_ERROR(weight_column_->CheckFieldsAccessed());
    }
  }
  if ((accessed_ & (1<<6)) != 0) {
    for (const auto& it : partition_by_list_) ZETASQL_RETURN_IF_ERROR(it->CheckFieldsAccessed());
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedSampleScan::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
  if (input_scan_ != nullptr) input_scan_->ClearFieldsAccessed();
  if (size_ != nullptr) size_->ClearFieldsAccessed();
  if (repeatable_argument_ != nullptr) repeatable_argument_->ClearFieldsAccessed();
  if (weight_column_ != nullptr) weight_column_->ClearFieldsAccessed();
  for (const auto& it : partition_by_list_) it->ClearFieldsAccessed();
}

const ResolvedNodeKind ResolvedComputedColumn::TYPE;

ResolvedComputedColumn::~ResolvedComputedColumn() {
}

zetasql_base::Status ResolvedComputedColumn::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedArgumentProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_computed_column_node());
}

zetasql_base::Status ResolvedComputedColumn::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedComputedColumnProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  ZETASQL_RETURN_IF_ERROR(SaveToImpl(
      column_, file_descriptor_set_map,
      proto->mutable_column()));
  if (expr_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(expr_->SaveTo(
        file_descriptor_set_map, proto->mutable_expr()));
  }
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedComputedColumn>> ResolvedComputedColumn::RestoreFrom(
    const ResolvedComputedColumnProto& proto,
    const ResolvedNode::RestoreParams& params) {
  ZETASQL_ASSIGN_OR_RETURN(ResolvedColumn column,
                   RestoreFromImpl(proto.column(),
                                   params));
  std::unique_ptr<const ResolvedExpr> expr;
  if (proto.
  has_expr()) {
    ZETASQL_ASSIGN_OR_RETURN(expr,
                     ResolvedExpr::RestoreFrom(
                         proto.expr(), params));
  }
  auto node = MakeResolvedComputedColumn(
      std::move(column),
      std::move(expr));

  return std::move(node);
}

void ResolvedComputedColumn::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
  if (expr_ != nullptr) {
    child_nodes->emplace_back(expr_.get());
  }
}

void ResolvedComputedColumn::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
  if (expr_ != nullptr) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(
            &expr_));
    static_assert(sizeof(expr_) ==
                  sizeof(*(mutable_child_node_ptrs->back())),
                  "Incorrect casting of mutable child node");
  }
}

zetasql_base::Status ResolvedComputedColumn::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedComputedColumn(this);
}

zetasql_base::Status ResolvedComputedColumn::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  if (expr_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(expr_.get()->Accept(visitor));
  }
  return ::zetasql_base::OkStatus();
}

zetasql_base::Status ResolvedComputedColumn::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<1)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedComputedColumn::expr not accessed)";
  }
  if ((accessed_ & (1<<1)) != 0) {
    if (expr_ != nullptr) {
      ZETASQL_RETURN_IF_ERROR(expr_->CheckFieldsAccessed());
    }
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedComputedColumn::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
  if (expr_ != nullptr) expr_->ClearFieldsAccessed();
}

const ResolvedNodeKind ResolvedOrderByItem::TYPE;

ResolvedOrderByItem::~ResolvedOrderByItem() {
}

zetasql_base::Status ResolvedOrderByItem::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedArgumentProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_order_by_item_node());
}

zetasql_base::Status ResolvedOrderByItem::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedOrderByItemProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  if (column_ref_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(column_ref_->SaveTo(
        file_descriptor_set_map, proto->mutable_column_ref()));
  }
  if (collation_name_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(collation_name_->SaveTo(
        file_descriptor_set_map, proto->mutable_collation_name()));
  }
  proto->set_is_descending(is_descending_);
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedOrderByItem>> ResolvedOrderByItem::RestoreFrom(
    const ResolvedOrderByItemProto& proto,
    const ResolvedNode::RestoreParams& params) {
  std::unique_ptr<const ResolvedColumnRef> column_ref;
  if (proto.
  has_column_ref()) {
    ZETASQL_ASSIGN_OR_RETURN(column_ref,
                     ResolvedColumnRef::RestoreFrom(
                         proto.column_ref(), params));
  }
  std::unique_ptr<const ResolvedExpr> collation_name;
  if (proto.
  has_collation_name()) {
    ZETASQL_ASSIGN_OR_RETURN(collation_name,
                     ResolvedExpr::RestoreFrom(
                         proto.collation_name(), params));
  }
  bool is_descending =
      proto.is_descending();
  auto node = MakeResolvedOrderByItem(
      std::move(column_ref),
      std::move(collation_name),
      std::move(is_descending));

  return std::move(node);
}

void ResolvedOrderByItem::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
  if (column_ref_ != nullptr) {
    child_nodes->emplace_back(column_ref_.get());
  }
  if (collation_name_ != nullptr) {
    child_nodes->emplace_back(collation_name_.get());
  }
}

void ResolvedOrderByItem::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
  if (column_ref_ != nullptr) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(
            &column_ref_));
    static_assert(sizeof(column_ref_) ==
                  sizeof(*(mutable_child_node_ptrs->back())),
                  "Incorrect casting of mutable child node");
  }
  if (collation_name_ != nullptr) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(
            &collation_name_));
    static_assert(sizeof(collation_name_) ==
                  sizeof(*(mutable_child_node_ptrs->back())),
                  "Incorrect casting of mutable child node");
  }
}

zetasql_base::Status ResolvedOrderByItem::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedOrderByItem(this);
}

zetasql_base::Status ResolvedOrderByItem::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  if (column_ref_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(column_ref_.get()->Accept(visitor));
  }
  if (collation_name_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(collation_name_.get()->Accept(visitor));
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedOrderByItem::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  if (column_ref_ != nullptr) {
    fields->emplace_back("column_ref", column_ref_.get());
  }
  if (collation_name_ != nullptr) {
    fields->emplace_back("collation_name", collation_name_.get());
  }
  if (!IsDefaultValue(is_descending_)) {
    fields->emplace_back("is_descending", ToStringImpl(is_descending_));
  }
}

zetasql_base::Status ResolvedOrderByItem::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedOrderByItem::column_ref not accessed)";
  }
  if ((accessed_ & (1<<1)) == 0 &&
      !IsDefaultValue(collation_name_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedOrderByItem::collation_name not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<2)) == 0 &&
      !IsDefaultValue(is_descending_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedOrderByItem::is_descending not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<0)) != 0) {
    if (column_ref_ != nullptr) {
      ZETASQL_RETURN_IF_ERROR(column_ref_->CheckFieldsAccessed());
    }
  }
  if ((accessed_ & (1<<1)) != 0) {
    if (collation_name_ != nullptr) {
      ZETASQL_RETURN_IF_ERROR(collation_name_->CheckFieldsAccessed());
    }
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedOrderByItem::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
  if (column_ref_ != nullptr) column_ref_->ClearFieldsAccessed();
  if (collation_name_ != nullptr) collation_name_->ClearFieldsAccessed();
}

const ResolvedNodeKind ResolvedColumnAnnotations::TYPE;

ResolvedColumnAnnotations::~ResolvedColumnAnnotations() {
}

zetasql_base::Status ResolvedColumnAnnotations::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedArgumentProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_column_annotations_node());
}

zetasql_base::Status ResolvedColumnAnnotations::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedColumnAnnotationsProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  proto->set_not_null(not_null_);
  for (const auto& elem : option_list_) {
    ZETASQL_RETURN_IF_ERROR(elem->SaveTo(
      file_descriptor_set_map, proto->add_option_list()));
  }
  for (const auto& elem : child_list_) {
    ZETASQL_RETURN_IF_ERROR(elem->SaveTo(
      file_descriptor_set_map, proto->add_child_list()));
  }
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedColumnAnnotations>> ResolvedColumnAnnotations::RestoreFrom(
    const ResolvedColumnAnnotationsProto& proto,
    const ResolvedNode::RestoreParams& params) {
  bool not_null =
      proto.not_null();
  std::vector<std::unique_ptr<const ResolvedOption>> option_list;
  for (const auto& elem : proto.option_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedOption> elem_restored,
                     ResolvedOption::RestoreFrom(elem, params));
    option_list.push_back(std::move(elem_restored));
  }
  std::vector<std::unique_ptr<const ResolvedColumnAnnotations>> child_list;
  for (const auto& elem : proto.child_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedColumnAnnotations> elem_restored,
                     ResolvedColumnAnnotations::RestoreFrom(elem, params));
    child_list.push_back(std::move(elem_restored));
  }
  auto node = MakeResolvedColumnAnnotations(
      std::move(not_null),
      std::move(option_list),
      std::move(child_list));

  return std::move(node);
}

void ResolvedColumnAnnotations::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
  for (const auto& elem : option_list_) {
    child_nodes->emplace_back(elem.get());
  }
  for (const auto& elem : child_list_) {
    child_nodes->emplace_back(elem.get());
  }
}

void ResolvedColumnAnnotations::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
  for (auto& elem : option_list_) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(&elem));
  }
  for (auto& elem : child_list_) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(&elem));
  }
}

zetasql_base::Status ResolvedColumnAnnotations::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedColumnAnnotations(this);
}

zetasql_base::Status ResolvedColumnAnnotations::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  for (const auto& elem : option_list_) {
    ZETASQL_RETURN_IF_ERROR(elem.get()->Accept(visitor));
  }
  for (const auto& elem : child_list_) {
    ZETASQL_RETURN_IF_ERROR(elem.get()->Accept(visitor));
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedColumnAnnotations::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  if (!IsDefaultValue(not_null_)) {
    fields->emplace_back("not_null", ToStringImpl(not_null_));
  }
  if (!option_list_.empty()) {
    fields->emplace_back("option_list", option_list_);
  }
  if (!child_list_.empty()) {
    fields->emplace_back("child_list", child_list_);
  }
}

zetasql_base::Status ResolvedColumnAnnotations::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0 &&
      !IsDefaultValue(not_null_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedColumnAnnotations::not_null not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<1)) == 0 &&
      !IsDefaultValue(option_list_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedColumnAnnotations::option_list not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<2)) == 0 &&
      !IsDefaultValue(child_list_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedColumnAnnotations::child_list not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<1)) != 0) {
    for (const auto& it : option_list_) ZETASQL_RETURN_IF_ERROR(it->CheckFieldsAccessed());
  }
  if ((accessed_ & (1<<2)) != 0) {
    for (const auto& it : child_list_) ZETASQL_RETURN_IF_ERROR(it->CheckFieldsAccessed());
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedColumnAnnotations::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
  for (const auto& it : option_list_) it->ClearFieldsAccessed();
  for (const auto& it : child_list_) it->ClearFieldsAccessed();
}

const ResolvedNodeKind ResolvedGeneratedColumnInfo::TYPE;

ResolvedGeneratedColumnInfo::~ResolvedGeneratedColumnInfo() {
}

zetasql_base::Status ResolvedGeneratedColumnInfo::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedArgumentProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_generated_column_info_node());
}

zetasql_base::Status ResolvedGeneratedColumnInfo::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedGeneratedColumnInfoProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  if (expression_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(expression_->SaveTo(
        file_descriptor_set_map, proto->mutable_expression()));
  }
  proto->set_is_stored(is_stored_);
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedGeneratedColumnInfo>> ResolvedGeneratedColumnInfo::RestoreFrom(
    const ResolvedGeneratedColumnInfoProto& proto,
    const ResolvedNode::RestoreParams& params) {
  std::unique_ptr<const ResolvedExpr> expression;
  if (proto.
  has_expression()) {
    ZETASQL_ASSIGN_OR_RETURN(expression,
                     ResolvedExpr::RestoreFrom(
                         proto.expression(), params));
  }
  bool is_stored =
      proto.is_stored();
  auto node = MakeResolvedGeneratedColumnInfo(
      std::move(expression),
      std::move(is_stored));

  return std::move(node);
}

void ResolvedGeneratedColumnInfo::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
  if (expression_ != nullptr) {
    child_nodes->emplace_back(expression_.get());
  }
}

void ResolvedGeneratedColumnInfo::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
  if (expression_ != nullptr) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(
            &expression_));
    static_assert(sizeof(expression_) ==
                  sizeof(*(mutable_child_node_ptrs->back())),
                  "Incorrect casting of mutable child node");
  }
}

zetasql_base::Status ResolvedGeneratedColumnInfo::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedGeneratedColumnInfo(this);
}

zetasql_base::Status ResolvedGeneratedColumnInfo::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  if (expression_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(expression_.get()->Accept(visitor));
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedGeneratedColumnInfo::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  if (expression_ != nullptr) {
    fields->emplace_back("expression", expression_.get());
  }
  {
    fields->emplace_back("is_stored", ToStringImpl(is_stored_));
  }
}

zetasql_base::Status ResolvedGeneratedColumnInfo::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedGeneratedColumnInfo::expression not accessed)";
  }
  if ((accessed_ & (1<<1)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedGeneratedColumnInfo::is_stored not accessed)";
  }
  if ((accessed_ & (1<<0)) != 0) {
    if (expression_ != nullptr) {
      ZETASQL_RETURN_IF_ERROR(expression_->CheckFieldsAccessed());
    }
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedGeneratedColumnInfo::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
  if (expression_ != nullptr) expression_->ClearFieldsAccessed();
}

const ResolvedNodeKind ResolvedColumnDefinition::TYPE;

ResolvedColumnDefinition::~ResolvedColumnDefinition() {
}

zetasql_base::Status ResolvedColumnDefinition::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedArgumentProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_column_definition_node());
}

zetasql_base::Status ResolvedColumnDefinition::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedColumnDefinitionProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  proto->set_name(name_);
  ZETASQL_RETURN_IF_ERROR(SaveToImpl(
      type_, file_descriptor_set_map,
      proto->mutable_type()));
  if (annotations_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(annotations_->SaveTo(
        file_descriptor_set_map, proto->mutable_annotations()));
  }
  proto->set_is_hidden(is_hidden_);
  ZETASQL_RETURN_IF_ERROR(SaveToImpl(
      column_, file_descriptor_set_map,
      proto->mutable_column()));
  if (generated_column_info_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(generated_column_info_->SaveTo(
        file_descriptor_set_map, proto->mutable_generated_column_info()));
  }
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedColumnDefinition>> ResolvedColumnDefinition::RestoreFrom(
    const ResolvedColumnDefinitionProto& proto,
    const ResolvedNode::RestoreParams& params) {
  std::string name =
      proto.name();
  ZETASQL_ASSIGN_OR_RETURN(const Type* type,
                   RestoreFromImpl(proto.type(),
                                   params));
  std::unique_ptr<const ResolvedColumnAnnotations> annotations;
  if (proto.
  has_annotations()) {
    ZETASQL_ASSIGN_OR_RETURN(annotations,
                     ResolvedColumnAnnotations::RestoreFrom(
                         proto.annotations(), params));
  }
  bool is_hidden =
      proto.is_hidden();
  ZETASQL_ASSIGN_OR_RETURN(ResolvedColumn column,
                   RestoreFromImpl(proto.column(),
                                   params));
  std::unique_ptr<const ResolvedGeneratedColumnInfo> generated_column_info;
  if (proto.
  has_generated_column_info()) {
    ZETASQL_ASSIGN_OR_RETURN(generated_column_info,
                     ResolvedGeneratedColumnInfo::RestoreFrom(
                         proto.generated_column_info(), params));
  }
  auto node = MakeResolvedColumnDefinition(
      std::move(name),
      std::move(type),
      std::move(annotations),
      std::move(is_hidden),
      std::move(column),
      std::move(generated_column_info));

  return std::move(node);
}

void ResolvedColumnDefinition::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
  if (annotations_ != nullptr) {
    child_nodes->emplace_back(annotations_.get());
  }
  if (generated_column_info_ != nullptr) {
    child_nodes->emplace_back(generated_column_info_.get());
  }
}

void ResolvedColumnDefinition::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
  if (annotations_ != nullptr) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(
            &annotations_));
    static_assert(sizeof(annotations_) ==
                  sizeof(*(mutable_child_node_ptrs->back())),
                  "Incorrect casting of mutable child node");
  }
  if (generated_column_info_ != nullptr) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(
            &generated_column_info_));
    static_assert(sizeof(generated_column_info_) ==
                  sizeof(*(mutable_child_node_ptrs->back())),
                  "Incorrect casting of mutable child node");
  }
}

zetasql_base::Status ResolvedColumnDefinition::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedColumnDefinition(this);
}

zetasql_base::Status ResolvedColumnDefinition::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  if (annotations_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(annotations_.get()->Accept(visitor));
  }
  if (generated_column_info_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(generated_column_info_.get()->Accept(visitor));
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedColumnDefinition::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  {
    fields->emplace_back("name", ToStringImpl(name_));
  }
  {
    fields->emplace_back("type", ToStringImpl(type_));
  }
  if (annotations_ != nullptr) {
    fields->emplace_back("annotations", annotations_.get());
  }
  if (!IsDefaultValue(is_hidden_)) {
    fields->emplace_back("is_hidden", ToStringImpl(is_hidden_));
  }
  if (!IsDefaultValue(column_)) {
    fields->emplace_back("column", ToStringImpl(column_));
  }
  if (generated_column_info_ != nullptr) {
    fields->emplace_back("generated_column_info", generated_column_info_.get());
  }
}

zetasql_base::Status ResolvedColumnDefinition::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedColumnDefinition::name not accessed)";
  }
  if ((accessed_ & (1<<1)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedColumnDefinition::type not accessed)";
  }
  if ((accessed_ & (1<<2)) == 0 &&
      !IsDefaultValue(annotations_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedColumnDefinition::annotations not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<3)) == 0 &&
      !IsDefaultValue(is_hidden_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedColumnDefinition::is_hidden not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<5)) == 0 &&
      !IsDefaultValue(generated_column_info_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedColumnDefinition::generated_column_info not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<2)) != 0) {
    if (annotations_ != nullptr) {
      ZETASQL_RETURN_IF_ERROR(annotations_->CheckFieldsAccessed());
    }
  }
  if ((accessed_ & (1<<5)) != 0) {
    if (generated_column_info_ != nullptr) {
      ZETASQL_RETURN_IF_ERROR(generated_column_info_->CheckFieldsAccessed());
    }
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedColumnDefinition::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
  if (annotations_ != nullptr) annotations_->ClearFieldsAccessed();
  if (generated_column_info_ != nullptr) generated_column_info_->ClearFieldsAccessed();
}

const ResolvedNodeKind ResolvedPrimaryKey::TYPE;

ResolvedPrimaryKey::~ResolvedPrimaryKey() {
}

zetasql_base::Status ResolvedPrimaryKey::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedArgumentProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_primary_key_node());
}

zetasql_base::Status ResolvedPrimaryKey::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedPrimaryKeyProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  for (const auto& elem : column_offset_list_) {
    proto->add_column_offset_list(elem);
  }
  for (const auto& elem : option_list_) {
    ZETASQL_RETURN_IF_ERROR(elem->SaveTo(
      file_descriptor_set_map, proto->add_option_list()));
  }
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedPrimaryKey>> ResolvedPrimaryKey::RestoreFrom(
    const ResolvedPrimaryKeyProto& proto,
    const ResolvedNode::RestoreParams& params) {
  std::vector<int> column_offset_list;
  for (const auto& elem : proto.column_offset_list()) {
    column_offset_list.push_back(elem);
  }
  std::vector<std::unique_ptr<const ResolvedOption>> option_list;
  for (const auto& elem : proto.option_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedOption> elem_restored,
                     ResolvedOption::RestoreFrom(elem, params));
    option_list.push_back(std::move(elem_restored));
  }
  auto node = MakeResolvedPrimaryKey(
      std::move(column_offset_list),
      std::move(option_list));

  return std::move(node);
}

void ResolvedPrimaryKey::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
  for (const auto& elem : option_list_) {
    child_nodes->emplace_back(elem.get());
  }
}

void ResolvedPrimaryKey::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
  for (auto& elem : option_list_) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(&elem));
  }
}

zetasql_base::Status ResolvedPrimaryKey::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedPrimaryKey(this);
}

zetasql_base::Status ResolvedPrimaryKey::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  for (const auto& elem : option_list_) {
    ZETASQL_RETURN_IF_ERROR(elem.get()->Accept(visitor));
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedPrimaryKey::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  {
    fields->emplace_back("column_offset_list", ToStringCommaSeparated(column_offset_list_));
  }
  if (!option_list_.empty()) {
    fields->emplace_back("option_list", option_list_);
  }
}

zetasql_base::Status ResolvedPrimaryKey::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedPrimaryKey::column_offset_list not accessed)";
  }
  if ((accessed_ & (1<<1)) == 0 &&
      !IsDefaultValue(option_list_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedPrimaryKey::option_list not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<1)) != 0) {
    for (const auto& it : option_list_) ZETASQL_RETURN_IF_ERROR(it->CheckFieldsAccessed());
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedPrimaryKey::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
  for (const auto& it : option_list_) it->ClearFieldsAccessed();
}

const ResolvedNodeKind ResolvedForeignKey::TYPE;

const ResolvedForeignKey::MatchMode ResolvedForeignKey::SIMPLE;
const ResolvedForeignKey::MatchMode ResolvedForeignKey::FULL;
const ResolvedForeignKey::MatchMode ResolvedForeignKey::NOT_DISTINCT;
const ResolvedForeignKey::ActionOperation ResolvedForeignKey::NO_ACTION;
const ResolvedForeignKey::ActionOperation ResolvedForeignKey::RESTRICT;
const ResolvedForeignKey::ActionOperation ResolvedForeignKey::CASCADE;
const ResolvedForeignKey::ActionOperation ResolvedForeignKey::SET_NULL;

ResolvedForeignKey::~ResolvedForeignKey() {
}

zetasql_base::Status ResolvedForeignKey::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedArgumentProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_foreign_key_node());
}

zetasql_base::Status ResolvedForeignKey::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedForeignKeyProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  proto->set_constraint_name(constraint_name_);
  for (const auto& elem : referencing_column_offset_list_) {
    proto->add_referencing_column_offset_list(elem);
  }
  ZETASQL_RETURN_IF_ERROR(SaveToImpl(
      referenced_table_, file_descriptor_set_map,
      proto->mutable_referenced_table()));
  for (const auto& elem : referenced_column_offset_list_) {
    proto->add_referenced_column_offset_list(elem);
  }
  proto->set_match_mode(match_mode_);
  proto->set_update_action(update_action_);
  proto->set_delete_action(delete_action_);
  proto->set_enforced(enforced_);
  for (const auto& elem : option_list_) {
    ZETASQL_RETURN_IF_ERROR(elem->SaveTo(
      file_descriptor_set_map, proto->add_option_list()));
  }
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedForeignKey>> ResolvedForeignKey::RestoreFrom(
    const ResolvedForeignKeyProto& proto,
    const ResolvedNode::RestoreParams& params) {
  std::string constraint_name =
      proto.constraint_name();
  std::vector<int> referencing_column_offset_list;
  for (const auto& elem : proto.referencing_column_offset_list()) {
    referencing_column_offset_list.push_back(elem);
  }
  ZETASQL_ASSIGN_OR_RETURN(const Table* referenced_table,
                   RestoreFromImpl(proto.referenced_table(),
                                   params));
  std::vector<int> referenced_column_offset_list;
  for (const auto& elem : proto.referenced_column_offset_list()) {
    referenced_column_offset_list.push_back(elem);
  }
  MatchMode match_mode =
      proto.match_mode();
  ActionOperation update_action =
      proto.update_action();
  ActionOperation delete_action =
      proto.delete_action();
  bool enforced =
      proto.enforced();
  std::vector<std::unique_ptr<const ResolvedOption>> option_list;
  for (const auto& elem : proto.option_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedOption> elem_restored,
                     ResolvedOption::RestoreFrom(elem, params));
    option_list.push_back(std::move(elem_restored));
  }
  auto node = MakeResolvedForeignKey(
      std::move(constraint_name),
      std::move(referencing_column_offset_list),
      std::move(referenced_table),
      std::move(referenced_column_offset_list),
      std::move(match_mode),
      std::move(update_action),
      std::move(delete_action),
      std::move(enforced),
      std::move(option_list));

  return std::move(node);
}

void ResolvedForeignKey::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
  for (const auto& elem : option_list_) {
    child_nodes->emplace_back(elem.get());
  }
}

void ResolvedForeignKey::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
  for (auto& elem : option_list_) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(&elem));
  }
}

zetasql_base::Status ResolvedForeignKey::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedForeignKey(this);
}

zetasql_base::Status ResolvedForeignKey::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  for (const auto& elem : option_list_) {
    ZETASQL_RETURN_IF_ERROR(elem.get()->Accept(visitor));
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedForeignKey::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  {
    fields->emplace_back("constraint_name", ToStringImpl(constraint_name_));
  }
  {
    fields->emplace_back("referencing_column_offset_list", ToStringCommaSeparated(referencing_column_offset_list_));
  }
  {
    fields->emplace_back("referenced_table", ToStringImpl(referenced_table_));
  }
  {
    fields->emplace_back("referenced_column_offset_list", ToStringCommaSeparated(referenced_column_offset_list_));
  }
  {
    fields->emplace_back("match_mode", ToStringImpl(match_mode_));
  }
  {
    fields->emplace_back("update_action", ToStringImpl(update_action_));
  }
  {
    fields->emplace_back("delete_action", ToStringImpl(delete_action_));
  }
  {
    fields->emplace_back("enforced", ToStringImpl(enforced_));
  }
  if (!option_list_.empty()) {
    fields->emplace_back("option_list", option_list_);
  }
}

zetasql_base::Status ResolvedForeignKey::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedForeignKey::constraint_name not accessed)";
  }
  if ((accessed_ & (1<<1)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedForeignKey::referencing_column_offset_list not accessed)";
  }
  if ((accessed_ & (1<<2)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedForeignKey::referenced_table not accessed)";
  }
  if ((accessed_ & (1<<3)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedForeignKey::referenced_column_offset_list not accessed)";
  }
  if ((accessed_ & (1<<4)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedForeignKey::match_mode not accessed)";
  }
  if ((accessed_ & (1<<5)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedForeignKey::update_action not accessed)";
  }
  if ((accessed_ & (1<<6)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedForeignKey::delete_action not accessed)";
  }
  if ((accessed_ & (1<<7)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedForeignKey::enforced not accessed)";
  }
  if ((accessed_ & (1<<8)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedForeignKey::option_list not accessed)";
  }
  if ((accessed_ & (1<<8)) != 0) {
    for (const auto& it : option_list_) ZETASQL_RETURN_IF_ERROR(it->CheckFieldsAccessed());
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedForeignKey::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
  for (const auto& it : option_list_) it->ClearFieldsAccessed();
}

const ResolvedNodeKind ResolvedCheckConstraint::TYPE;

ResolvedCheckConstraint::~ResolvedCheckConstraint() {
}

zetasql_base::Status ResolvedCheckConstraint::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedArgumentProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_check_constraint_node());
}

zetasql_base::Status ResolvedCheckConstraint::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedCheckConstraintProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  proto->set_constraint_name(constraint_name_);
  if (expression_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(expression_->SaveTo(
        file_descriptor_set_map, proto->mutable_expression()));
  }
  proto->set_enforced(enforced_);
  for (const auto& elem : option_list_) {
    ZETASQL_RETURN_IF_ERROR(elem->SaveTo(
      file_descriptor_set_map, proto->add_option_list()));
  }
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedCheckConstraint>> ResolvedCheckConstraint::RestoreFrom(
    const ResolvedCheckConstraintProto& proto,
    const ResolvedNode::RestoreParams& params) {
  std::string constraint_name =
      proto.constraint_name();
  std::unique_ptr<const ResolvedExpr> expression;
  if (proto.
  has_expression()) {
    ZETASQL_ASSIGN_OR_RETURN(expression,
                     ResolvedExpr::RestoreFrom(
                         proto.expression(), params));
  }
  bool enforced =
      proto.enforced();
  std::vector<std::unique_ptr<const ResolvedOption>> option_list;
  for (const auto& elem : proto.option_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedOption> elem_restored,
                     ResolvedOption::RestoreFrom(elem, params));
    option_list.push_back(std::move(elem_restored));
  }
  auto node = MakeResolvedCheckConstraint(
      std::move(constraint_name),
      std::move(expression),
      std::move(enforced),
      std::move(option_list));

  return std::move(node);
}

void ResolvedCheckConstraint::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
  if (expression_ != nullptr) {
    child_nodes->emplace_back(expression_.get());
  }
  for (const auto& elem : option_list_) {
    child_nodes->emplace_back(elem.get());
  }
}

void ResolvedCheckConstraint::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
  if (expression_ != nullptr) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(
            &expression_));
    static_assert(sizeof(expression_) ==
                  sizeof(*(mutable_child_node_ptrs->back())),
                  "Incorrect casting of mutable child node");
  }
  for (auto& elem : option_list_) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(&elem));
  }
}

zetasql_base::Status ResolvedCheckConstraint::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedCheckConstraint(this);
}

zetasql_base::Status ResolvedCheckConstraint::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  if (expression_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(expression_.get()->Accept(visitor));
  }
  for (const auto& elem : option_list_) {
    ZETASQL_RETURN_IF_ERROR(elem.get()->Accept(visitor));
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedCheckConstraint::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  {
    fields->emplace_back("constraint_name", ToStringImpl(constraint_name_));
  }
  if (expression_ != nullptr) {
    fields->emplace_back("expression", expression_.get());
  }
  {
    fields->emplace_back("enforced", ToStringImpl(enforced_));
  }
  if (!option_list_.empty()) {
    fields->emplace_back("option_list", option_list_);
  }
}

zetasql_base::Status ResolvedCheckConstraint::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedCheckConstraint::constraint_name not accessed)";
  }
  if ((accessed_ & (1<<1)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedCheckConstraint::expression not accessed)";
  }
  if ((accessed_ & (1<<2)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedCheckConstraint::enforced not accessed)";
  }
  if ((accessed_ & (1<<3)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedCheckConstraint::option_list not accessed)";
  }
  if ((accessed_ & (1<<1)) != 0) {
    if (expression_ != nullptr) {
      ZETASQL_RETURN_IF_ERROR(expression_->CheckFieldsAccessed());
    }
  }
  if ((accessed_ & (1<<3)) != 0) {
    for (const auto& it : option_list_) ZETASQL_RETURN_IF_ERROR(it->CheckFieldsAccessed());
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedCheckConstraint::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
  if (expression_ != nullptr) expression_->ClearFieldsAccessed();
  for (const auto& it : option_list_) it->ClearFieldsAccessed();
}

const ResolvedNodeKind ResolvedOutputColumn::TYPE;

ResolvedOutputColumn::~ResolvedOutputColumn() {
}

zetasql_base::Status ResolvedOutputColumn::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedArgumentProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_output_column_node());
}

zetasql_base::Status ResolvedOutputColumn::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedOutputColumnProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  proto->set_name(name_);
  ZETASQL_RETURN_IF_ERROR(SaveToImpl(
      column_, file_descriptor_set_map,
      proto->mutable_column()));
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedOutputColumn>> ResolvedOutputColumn::RestoreFrom(
    const ResolvedOutputColumnProto& proto,
    const ResolvedNode::RestoreParams& params) {
  std::string name =
      proto.name();
  ZETASQL_ASSIGN_OR_RETURN(ResolvedColumn column,
                   RestoreFromImpl(proto.column(),
                                   params));
  auto node = MakeResolvedOutputColumn(
      std::move(name),
      std::move(column));

  return std::move(node);
}

void ResolvedOutputColumn::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
}

void ResolvedOutputColumn::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
}

zetasql_base::Status ResolvedOutputColumn::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedOutputColumn(this);
}

zetasql_base::Status ResolvedOutputColumn::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  return ::zetasql_base::OkStatus();
}

zetasql_base::Status ResolvedOutputColumn::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<1)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedOutputColumn::column not accessed)";
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedOutputColumn::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
}

const ResolvedNodeKind ResolvedProjectScan::TYPE;

ResolvedProjectScan::~ResolvedProjectScan() {
}

zetasql_base::Status ResolvedProjectScan::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedScanProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_project_scan_node());
}

zetasql_base::Status ResolvedProjectScan::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedProjectScanProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  for (const auto& elem : expr_list_) {
    ZETASQL_RETURN_IF_ERROR(elem->SaveTo(
      file_descriptor_set_map, proto->add_expr_list()));
  }
  if (input_scan_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(input_scan_->SaveTo(
        file_descriptor_set_map, proto->mutable_input_scan()));
  }
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedProjectScan>> ResolvedProjectScan::RestoreFrom(
    const ResolvedProjectScanProto& proto,
    const ResolvedNode::RestoreParams& params) {
  std::vector<std::unique_ptr<const ResolvedComputedColumn>> expr_list;
  for (const auto& elem : proto.expr_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedComputedColumn> elem_restored,
                     ResolvedComputedColumn::RestoreFrom(elem, params));
    expr_list.push_back(std::move(elem_restored));
  }
  std::unique_ptr<const ResolvedScan> input_scan;
  if (proto.
  has_input_scan()) {
    ZETASQL_ASSIGN_OR_RETURN(input_scan,
                     ResolvedScan::RestoreFrom(
                         proto.input_scan(), params));
  }
  std::vector<ResolvedColumn> column_list;
  for (const auto& elem : proto.parent().column_list()) {
    ZETASQL_ASSIGN_OR_RETURN(auto elem_restored, RestoreFromImpl(elem, params));
    column_list.push_back(std::move(elem_restored));
  }
  std::vector<std::unique_ptr<const ResolvedOption>> hint_list;
  for (const auto& elem : proto.parent().hint_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedOption> elem_restored,
                     ResolvedOption::RestoreFrom(elem, params));
    hint_list.push_back(std::move(elem_restored));
  }
  bool is_ordered =
      proto.parent().is_ordered();
  auto node = MakeResolvedProjectScan(
      std::move(column_list),
      std::move(expr_list),
      std::move(input_scan));

  node->set_hint_list(std::move(hint_list));
  node->set_is_ordered(std::move(is_ordered));
  return std::move(node);
}

void ResolvedProjectScan::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
  for (const auto& elem : expr_list_) {
    child_nodes->emplace_back(elem.get());
  }
  if (input_scan_ != nullptr) {
    child_nodes->emplace_back(input_scan_.get());
  }
}

void ResolvedProjectScan::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
  for (auto& elem : expr_list_) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(&elem));
  }
  if (input_scan_ != nullptr) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(
            &input_scan_));
    static_assert(sizeof(input_scan_) ==
                  sizeof(*(mutable_child_node_ptrs->back())),
                  "Incorrect casting of mutable child node");
  }
}

zetasql_base::Status ResolvedProjectScan::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedProjectScan(this);
}

zetasql_base::Status ResolvedProjectScan::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  for (const auto& elem : expr_list_) {
    ZETASQL_RETURN_IF_ERROR(elem.get()->Accept(visitor));
  }
  if (input_scan_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(input_scan_.get()->Accept(visitor));
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedProjectScan::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  if (!expr_list_.empty()) {
    fields->emplace_back("expr_list", expr_list_);
  }
  if (input_scan_ != nullptr) {
    fields->emplace_back("input_scan", input_scan_.get());
  }
}

zetasql_base::Status ResolvedProjectScan::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedProjectScan::expr_list not accessed)";
  }
  if ((accessed_ & (1<<1)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedProjectScan::input_scan not accessed)";
  }
  if ((accessed_ & (1<<0)) != 0) {
    for (const auto& it : expr_list_) ZETASQL_RETURN_IF_ERROR(it->CheckFieldsAccessed());
  }
  if ((accessed_ & (1<<1)) != 0) {
    if (input_scan_ != nullptr) {
      ZETASQL_RETURN_IF_ERROR(input_scan_->CheckFieldsAccessed());
    }
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedProjectScan::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
  for (const auto& it : expr_list_) it->ClearFieldsAccessed();
  if (input_scan_ != nullptr) input_scan_->ClearFieldsAccessed();
}

const ResolvedNodeKind ResolvedTVFScan::TYPE;

ResolvedTVFScan::~ResolvedTVFScan() {
}

zetasql_base::Status ResolvedTVFScan::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedScanProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_tvfscan_node());
}

zetasql_base::Status ResolvedTVFScan::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedTVFScanProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  ZETASQL_RETURN_IF_ERROR(SaveToImpl(
      tvf_, file_descriptor_set_map,
      proto->mutable_tvf()));
  ZETASQL_RETURN_IF_ERROR(SaveToImpl(
      signature_, file_descriptor_set_map,
      proto->mutable_signature()));
  for (const auto& elem : argument_list_) {
    ZETASQL_RETURN_IF_ERROR(elem->SaveTo(
      file_descriptor_set_map, proto->add_argument_list()));
  }
  proto->set_alias(alias_);
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedTVFScan>> ResolvedTVFScan::RestoreFrom(
    const ResolvedTVFScanProto& proto,
    const ResolvedNode::RestoreParams& params) {
  ZETASQL_ASSIGN_OR_RETURN(const TableValuedFunction* tvf,
                   RestoreFromImpl(proto.tvf(),
                                   params));
  ZETASQL_ASSIGN_OR_RETURN(std::shared_ptr<TVFSignature> signature,
                   RestoreFromImpl(proto.signature(),
                                   params));
  std::vector<std::unique_ptr<const ResolvedTVFArgument>> argument_list;
  for (const auto& elem : proto.argument_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedTVFArgument> elem_restored,
                     ResolvedTVFArgument::RestoreFrom(elem, params));
    argument_list.push_back(std::move(elem_restored));
  }
  std::string alias =
      proto.alias();
  std::vector<ResolvedColumn> column_list;
  for (const auto& elem : proto.parent().column_list()) {
    ZETASQL_ASSIGN_OR_RETURN(auto elem_restored, RestoreFromImpl(elem, params));
    column_list.push_back(std::move(elem_restored));
  }
  std::vector<std::unique_ptr<const ResolvedOption>> hint_list;
  for (const auto& elem : proto.parent().hint_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedOption> elem_restored,
                     ResolvedOption::RestoreFrom(elem, params));
    hint_list.push_back(std::move(elem_restored));
  }
  bool is_ordered =
      proto.parent().is_ordered();
  auto node = MakeResolvedTVFScan(
      std::move(column_list),
      std::move(tvf),
      std::move(signature),
      std::move(argument_list),
      std::move(alias));

  node->set_hint_list(std::move(hint_list));
  node->set_is_ordered(std::move(is_ordered));
  return std::move(node);
}

void ResolvedTVFScan::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
  for (const auto& elem : argument_list_) {
    child_nodes->emplace_back(elem.get());
  }
}

void ResolvedTVFScan::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
  for (auto& elem : argument_list_) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(&elem));
  }
}

zetasql_base::Status ResolvedTVFScan::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedTVFScan(this);
}

zetasql_base::Status ResolvedTVFScan::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  for (const auto& elem : argument_list_) {
    ZETASQL_RETURN_IF_ERROR(elem.get()->Accept(visitor));
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedTVFScan::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  {
    fields->emplace_back("tvf", ToStringImpl(tvf_));
  }
  {
    fields->emplace_back("signature", ToStringImpl(signature_));
  }
  if (!argument_list_.empty()) {
    fields->emplace_back("argument_list", argument_list_);
  }
  if (!IsDefaultValue(alias_)) {
    fields->emplace_back("alias", ToStringImpl(alias_));
  }
}

zetasql_base::Status ResolvedTVFScan::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedTVFScan::tvf not accessed)";
  }
  if ((accessed_ & (1<<1)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedTVFScan::signature not accessed)";
  }
  if ((accessed_ & (1<<2)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedTVFScan::argument_list not accessed)";
  }
  if ((accessed_ & (1<<2)) != 0) {
    for (const auto& it : argument_list_) ZETASQL_RETURN_IF_ERROR(it->CheckFieldsAccessed());
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedTVFScan::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
  for (const auto& it : argument_list_) it->ClearFieldsAccessed();
}

const ResolvedNodeKind ResolvedTVFArgument::TYPE;

ResolvedTVFArgument::~ResolvedTVFArgument() {
}

zetasql_base::Status ResolvedTVFArgument::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedArgumentProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_tvfargument_node());
}

zetasql_base::Status ResolvedTVFArgument::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedTVFArgumentProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  if (expr_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(expr_->SaveTo(
        file_descriptor_set_map, proto->mutable_expr()));
  }
  if (scan_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(scan_->SaveTo(
        file_descriptor_set_map, proto->mutable_scan()));
  }
  if (model_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(model_->SaveTo(
        file_descriptor_set_map, proto->mutable_model()));
  }
  for (const auto& elem : argument_column_list_) {
    ZETASQL_RETURN_IF_ERROR(SaveToImpl(
        elem, file_descriptor_set_map, proto->add_argument_column_list()));
  }
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedTVFArgument>> ResolvedTVFArgument::RestoreFrom(
    const ResolvedTVFArgumentProto& proto,
    const ResolvedNode::RestoreParams& params) {
  std::unique_ptr<const ResolvedExpr> expr;
  if (proto.
  has_expr()) {
    ZETASQL_ASSIGN_OR_RETURN(expr,
                     ResolvedExpr::RestoreFrom(
                         proto.expr(), params));
  }
  std::unique_ptr<const ResolvedScan> scan;
  if (proto.
  has_scan()) {
    ZETASQL_ASSIGN_OR_RETURN(scan,
                     ResolvedScan::RestoreFrom(
                         proto.scan(), params));
  }
  std::unique_ptr<const ResolvedModel> model;
  if (proto.
  has_model()) {
    ZETASQL_ASSIGN_OR_RETURN(model,
                     ResolvedModel::RestoreFrom(
                         proto.model(), params));
  }
  std::vector<ResolvedColumn> argument_column_list;
  for (const auto& elem : proto.argument_column_list()) {
    ZETASQL_ASSIGN_OR_RETURN(auto elem_restored, RestoreFromImpl(elem, params));
    argument_column_list.push_back(std::move(elem_restored));
  }
  auto node = MakeResolvedTVFArgument(
      std::move(expr),
      std::move(scan),
      std::move(model),
      std::move(argument_column_list));

  return std::move(node);
}

void ResolvedTVFArgument::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
  if (expr_ != nullptr) {
    child_nodes->emplace_back(expr_.get());
  }
  if (scan_ != nullptr) {
    child_nodes->emplace_back(scan_.get());
  }
  if (model_ != nullptr) {
    child_nodes->emplace_back(model_.get());
  }
}

void ResolvedTVFArgument::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
  if (expr_ != nullptr) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(
            &expr_));
    static_assert(sizeof(expr_) ==
                  sizeof(*(mutable_child_node_ptrs->back())),
                  "Incorrect casting of mutable child node");
  }
  if (scan_ != nullptr) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(
            &scan_));
    static_assert(sizeof(scan_) ==
                  sizeof(*(mutable_child_node_ptrs->back())),
                  "Incorrect casting of mutable child node");
  }
  if (model_ != nullptr) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(
            &model_));
    static_assert(sizeof(model_) ==
                  sizeof(*(mutable_child_node_ptrs->back())),
                  "Incorrect casting of mutable child node");
  }
}

zetasql_base::Status ResolvedTVFArgument::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedTVFArgument(this);
}

zetasql_base::Status ResolvedTVFArgument::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  if (expr_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(expr_.get()->Accept(visitor));
  }
  if (scan_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(scan_.get()->Accept(visitor));
  }
  if (model_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(model_.get()->Accept(visitor));
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedTVFArgument::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  if (expr_ != nullptr) {
    fields->emplace_back("expr", expr_.get());
  }
  if (scan_ != nullptr) {
    fields->emplace_back("scan", scan_.get());
  }
  if (model_ != nullptr) {
    fields->emplace_back("model", model_.get());
  }
  if (!IsDefaultValue(argument_column_list_)) {
    fields->emplace_back("argument_column_list", ToStringImpl(argument_column_list_));
  }
}

zetasql_base::Status ResolvedTVFArgument::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0 &&
      !IsDefaultValue(expr_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedTVFArgument::expr not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<1)) == 0 &&
      !IsDefaultValue(scan_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedTVFArgument::scan not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<2)) == 0 &&
      !IsDefaultValue(model_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedTVFArgument::model not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<3)) == 0 &&
      !IsDefaultValue(argument_column_list_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedTVFArgument::argument_column_list not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<0)) != 0) {
    if (expr_ != nullptr) {
      ZETASQL_RETURN_IF_ERROR(expr_->CheckFieldsAccessed());
    }
  }
  if ((accessed_ & (1<<1)) != 0) {
    if (scan_ != nullptr) {
      ZETASQL_RETURN_IF_ERROR(scan_->CheckFieldsAccessed());
    }
  }
  if ((accessed_ & (1<<2)) != 0) {
    if (model_ != nullptr) {
      ZETASQL_RETURN_IF_ERROR(model_->CheckFieldsAccessed());
    }
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedTVFArgument::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
  if (expr_ != nullptr) expr_->ClearFieldsAccessed();
  if (scan_ != nullptr) scan_->ClearFieldsAccessed();
  if (model_ != nullptr) model_->ClearFieldsAccessed();
}

const ResolvedStatement::ObjectAccess ResolvedStatement::NONE;
const ResolvedStatement::ObjectAccess ResolvedStatement::READ;
const ResolvedStatement::ObjectAccess ResolvedStatement::WRITE;
const ResolvedStatement::ObjectAccess ResolvedStatement::READ_WRITE;

ResolvedStatement::~ResolvedStatement() {
}

zetasql_base::Status ResolvedStatement::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedNodeProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_statement_node());
}

zetasql_base::Status ResolvedStatement::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedStatementProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  for (const auto& elem : hint_list_) {
    ZETASQL_RETURN_IF_ERROR(elem->SaveTo(
      file_descriptor_set_map, proto->add_hint_list()));
  }
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedStatement>> ResolvedStatement::RestoreFrom(
    const AnyResolvedStatementProto& proto,
    const ResolvedNode::RestoreParams& params) {
  switch (proto.node_case()) {
    case AnyResolvedStatementProto::kResolvedExplainStmtNode:
      return ResolvedExplainStmt::RestoreFrom(
          proto.resolved_explain_stmt_node(), params);
    case AnyResolvedStatementProto::kResolvedQueryStmtNode:
      return ResolvedQueryStmt::RestoreFrom(
          proto.resolved_query_stmt_node(), params);
    case AnyResolvedStatementProto::kResolvedCreateStatementNode:
      return ResolvedCreateStatement::RestoreFrom(
          proto.resolved_create_statement_node(), params);
    case AnyResolvedStatementProto::kResolvedExportDataStmtNode:
      return ResolvedExportDataStmt::RestoreFrom(
          proto.resolved_export_data_stmt_node(), params);
    case AnyResolvedStatementProto::kResolvedDefineTableStmtNode:
      return ResolvedDefineTableStmt::RestoreFrom(
          proto.resolved_define_table_stmt_node(), params);
    case AnyResolvedStatementProto::kResolvedDescribeStmtNode:
      return ResolvedDescribeStmt::RestoreFrom(
          proto.resolved_describe_stmt_node(), params);
    case AnyResolvedStatementProto::kResolvedShowStmtNode:
      return ResolvedShowStmt::RestoreFrom(
          proto.resolved_show_stmt_node(), params);
    case AnyResolvedStatementProto::kResolvedBeginStmtNode:
      return ResolvedBeginStmt::RestoreFrom(
          proto.resolved_begin_stmt_node(), params);
    case AnyResolvedStatementProto::kResolvedCommitStmtNode:
      return ResolvedCommitStmt::RestoreFrom(
          proto.resolved_commit_stmt_node(), params);
    case AnyResolvedStatementProto::kResolvedRollbackStmtNode:
      return ResolvedRollbackStmt::RestoreFrom(
          proto.resolved_rollback_stmt_node(), params);
    case AnyResolvedStatementProto::kResolvedDropStmtNode:
      return ResolvedDropStmt::RestoreFrom(
          proto.resolved_drop_stmt_node(), params);
    case AnyResolvedStatementProto::kResolvedInsertStmtNode:
      return ResolvedInsertStmt::RestoreFrom(
          proto.resolved_insert_stmt_node(), params);
    case AnyResolvedStatementProto::kResolvedDeleteStmtNode:
      return ResolvedDeleteStmt::RestoreFrom(
          proto.resolved_delete_stmt_node(), params);
    case AnyResolvedStatementProto::kResolvedUpdateStmtNode:
      return ResolvedUpdateStmt::RestoreFrom(
          proto.resolved_update_stmt_node(), params);
    case AnyResolvedStatementProto::kResolvedGrantOrRevokeStmtNode:
      return ResolvedGrantOrRevokeStmt::RestoreFrom(
          proto.resolved_grant_or_revoke_stmt_node(), params);
    case AnyResolvedStatementProto::kResolvedAlterTableSetOptionsStmtNode:
      return ResolvedAlterTableSetOptionsStmt::RestoreFrom(
          proto.resolved_alter_table_set_options_stmt_node(), params);
    case AnyResolvedStatementProto::kResolvedRenameStmtNode:
      return ResolvedRenameStmt::RestoreFrom(
          proto.resolved_rename_stmt_node(), params);
    case AnyResolvedStatementProto::kResolvedCreateRowPolicyStmtNode:
      return ResolvedCreateRowPolicyStmt::RestoreFrom(
          proto.resolved_create_row_policy_stmt_node(), params);
    case AnyResolvedStatementProto::kResolvedDropRowPolicyStmtNode:
      return ResolvedDropRowPolicyStmt::RestoreFrom(
          proto.resolved_drop_row_policy_stmt_node(), params);
    case AnyResolvedStatementProto::kResolvedAlterRowPolicyStmtNode:
      return ResolvedAlterRowPolicyStmt::RestoreFrom(
          proto.resolved_alter_row_policy_stmt_node(), params);
    case AnyResolvedStatementProto::kResolvedDropFunctionStmtNode:
      return ResolvedDropFunctionStmt::RestoreFrom(
          proto.resolved_drop_function_stmt_node(), params);
    case AnyResolvedStatementProto::kResolvedCallStmtNode:
      return ResolvedCallStmt::RestoreFrom(
          proto.resolved_call_stmt_node(), params);
    case AnyResolvedStatementProto::kResolvedImportStmtNode:
      return ResolvedImportStmt::RestoreFrom(
          proto.resolved_import_stmt_node(), params);
    case AnyResolvedStatementProto::kResolvedModuleStmtNode:
      return ResolvedModuleStmt::RestoreFrom(
          proto.resolved_module_stmt_node(), params);
    case AnyResolvedStatementProto::kResolvedCreateDatabaseStmtNode:
      return ResolvedCreateDatabaseStmt::RestoreFrom(
          proto.resolved_create_database_stmt_node(), params);
    case AnyResolvedStatementProto::kResolvedAssertStmtNode:
      return ResolvedAssertStmt::RestoreFrom(
          proto.resolved_assert_stmt_node(), params);
    case AnyResolvedStatementProto::kResolvedMergeStmtNode:
      return ResolvedMergeStmt::RestoreFrom(
          proto.resolved_merge_stmt_node(), params);
    case AnyResolvedStatementProto::kResolvedAlterObjectStmtNode:
      return ResolvedAlterObjectStmt::RestoreFrom(
          proto.resolved_alter_object_stmt_node(), params);
    case AnyResolvedStatementProto::kResolvedSetTransactionStmtNode:
      return ResolvedSetTransactionStmt::RestoreFrom(
          proto.resolved_set_transaction_stmt_node(), params);
    case AnyResolvedStatementProto::kResolvedDropMaterializedViewStmtNode:
      return ResolvedDropMaterializedViewStmt::RestoreFrom(
          proto.resolved_drop_materialized_view_stmt_node(), params);
    case AnyResolvedStatementProto::kResolvedStartBatchStmtNode:
      return ResolvedStartBatchStmt::RestoreFrom(
          proto.resolved_start_batch_stmt_node(), params);
    case AnyResolvedStatementProto::kResolvedRunBatchStmtNode:
      return ResolvedRunBatchStmt::RestoreFrom(
          proto.resolved_run_batch_stmt_node(), params);
    case AnyResolvedStatementProto::kResolvedAbortBatchStmtNode:
      return ResolvedAbortBatchStmt::RestoreFrom(
          proto.resolved_abort_batch_stmt_node(), params);
  case AnyResolvedStatementProto::NODE_NOT_SET:
    return ::zetasql_base::InvalidArgumentErrorBuilder(ZETASQL_LOC)
        << "No subnode types set in ResolvedStatementProto";
  }
}

void ResolvedStatement::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
  for (const auto& elem : hint_list_) {
    child_nodes->emplace_back(elem.get());
  }
}

void ResolvedStatement::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
  for (auto& elem : hint_list_) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(&elem));
  }
}

zetasql_base::Status ResolvedStatement::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedStatement(this);
}

zetasql_base::Status ResolvedStatement::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  for (const auto& elem : hint_list_) {
    ZETASQL_RETURN_IF_ERROR(elem.get()->Accept(visitor));
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedStatement::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  if (!hint_list_.empty()) {
    fields->emplace_back("hint_list", hint_list_);
  }
}

zetasql_base::Status ResolvedStatement::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) != 0) {
    for (const auto& it : hint_list_) ZETASQL_RETURN_IF_ERROR(it->CheckFieldsAccessed());
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedStatement::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
  for (const auto& it : hint_list_) it->ClearFieldsAccessed();
}

const ResolvedNodeKind ResolvedExplainStmt::TYPE;

ResolvedExplainStmt::~ResolvedExplainStmt() {
}

zetasql_base::Status ResolvedExplainStmt::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedStatementProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_explain_stmt_node());
}

zetasql_base::Status ResolvedExplainStmt::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedExplainStmtProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  if (statement_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(statement_->SaveTo(
        file_descriptor_set_map, proto->mutable_statement()));
  }
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedExplainStmt>> ResolvedExplainStmt::RestoreFrom(
    const ResolvedExplainStmtProto& proto,
    const ResolvedNode::RestoreParams& params) {
  std::unique_ptr<const ResolvedStatement> statement;
  if (proto.
  has_statement()) {
    ZETASQL_ASSIGN_OR_RETURN(statement,
                     ResolvedStatement::RestoreFrom(
                         proto.statement(), params));
  }
  std::vector<std::unique_ptr<const ResolvedOption>> hint_list;
  for (const auto& elem : proto.parent().hint_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedOption> elem_restored,
                     ResolvedOption::RestoreFrom(elem, params));
    hint_list.push_back(std::move(elem_restored));
  }
  auto node = MakeResolvedExplainStmt(
      std::move(statement));

  node->set_hint_list(std::move(hint_list));
  return std::move(node);
}

void ResolvedExplainStmt::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
  if (statement_ != nullptr) {
    child_nodes->emplace_back(statement_.get());
  }
}

void ResolvedExplainStmt::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
  if (statement_ != nullptr) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(
            &statement_));
    static_assert(sizeof(statement_) ==
                  sizeof(*(mutable_child_node_ptrs->back())),
                  "Incorrect casting of mutable child node");
  }
}

zetasql_base::Status ResolvedExplainStmt::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedExplainStmt(this);
}

zetasql_base::Status ResolvedExplainStmt::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  if (statement_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(statement_.get()->Accept(visitor));
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedExplainStmt::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  if (statement_ != nullptr) {
    fields->emplace_back("statement", statement_.get());
  }
}

zetasql_base::Status ResolvedExplainStmt::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedExplainStmt::statement not accessed)";
  }
  if ((accessed_ & (1<<0)) != 0) {
    if (statement_ != nullptr) {
      ZETASQL_RETURN_IF_ERROR(statement_->CheckFieldsAccessed());
    }
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedExplainStmt::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
  if (statement_ != nullptr) statement_->ClearFieldsAccessed();
}

const ResolvedNodeKind ResolvedQueryStmt::TYPE;

ResolvedQueryStmt::~ResolvedQueryStmt() {
}

zetasql_base::Status ResolvedQueryStmt::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedStatementProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_query_stmt_node());
}

zetasql_base::Status ResolvedQueryStmt::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedQueryStmtProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  for (const auto& elem : output_column_list_) {
    ZETASQL_RETURN_IF_ERROR(elem->SaveTo(
      file_descriptor_set_map, proto->add_output_column_list()));
  }
  proto->set_is_value_table(is_value_table_);
  if (query_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(query_->SaveTo(
        file_descriptor_set_map, proto->mutable_query()));
  }
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedQueryStmt>> ResolvedQueryStmt::RestoreFrom(
    const ResolvedQueryStmtProto& proto,
    const ResolvedNode::RestoreParams& params) {
  std::vector<std::unique_ptr<const ResolvedOutputColumn>> output_column_list;
  for (const auto& elem : proto.output_column_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedOutputColumn> elem_restored,
                     ResolvedOutputColumn::RestoreFrom(elem, params));
    output_column_list.push_back(std::move(elem_restored));
  }
  bool is_value_table =
      proto.is_value_table();
  std::unique_ptr<const ResolvedScan> query;
  if (proto.
  has_query()) {
    ZETASQL_ASSIGN_OR_RETURN(query,
                     ResolvedScan::RestoreFrom(
                         proto.query(), params));
  }
  std::vector<std::unique_ptr<const ResolvedOption>> hint_list;
  for (const auto& elem : proto.parent().hint_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedOption> elem_restored,
                     ResolvedOption::RestoreFrom(elem, params));
    hint_list.push_back(std::move(elem_restored));
  }
  auto node = MakeResolvedQueryStmt(
      std::move(output_column_list),
      std::move(is_value_table),
      std::move(query));

  node->set_hint_list(std::move(hint_list));
  return std::move(node);
}

void ResolvedQueryStmt::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
  for (const auto& elem : output_column_list_) {
    child_nodes->emplace_back(elem.get());
  }
  if (query_ != nullptr) {
    child_nodes->emplace_back(query_.get());
  }
}

void ResolvedQueryStmt::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
  for (auto& elem : output_column_list_) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(&elem));
  }
  if (query_ != nullptr) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(
            &query_));
    static_assert(sizeof(query_) ==
                  sizeof(*(mutable_child_node_ptrs->back())),
                  "Incorrect casting of mutable child node");
  }
}

zetasql_base::Status ResolvedQueryStmt::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedQueryStmt(this);
}

zetasql_base::Status ResolvedQueryStmt::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  for (const auto& elem : output_column_list_) {
    ZETASQL_RETURN_IF_ERROR(elem.get()->Accept(visitor));
  }
  if (query_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(query_.get()->Accept(visitor));
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedQueryStmt::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  if (!output_column_list_.empty()) {
    fields->emplace_back("output_column_list", output_column_list_);
  }
  if (!IsDefaultValue(is_value_table_)) {
    fields->emplace_back("is_value_table", ToStringImpl(is_value_table_));
  }
  if (query_ != nullptr) {
    fields->emplace_back("query", query_.get());
  }
}

zetasql_base::Status ResolvedQueryStmt::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedQueryStmt::output_column_list not accessed)";
  }
  if ((accessed_ & (1<<1)) == 0 &&
      !IsDefaultValue(is_value_table_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedQueryStmt::is_value_table not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<2)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedQueryStmt::query not accessed)";
  }
  if ((accessed_ & (1<<0)) != 0) {
    for (const auto& it : output_column_list_) ZETASQL_RETURN_IF_ERROR(it->CheckFieldsAccessed());
  }
  if ((accessed_ & (1<<2)) != 0) {
    if (query_ != nullptr) {
      ZETASQL_RETURN_IF_ERROR(query_->CheckFieldsAccessed());
    }
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedQueryStmt::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
  for (const auto& it : output_column_list_) it->ClearFieldsAccessed();
  if (query_ != nullptr) query_->ClearFieldsAccessed();
}

const ResolvedNodeKind ResolvedCreateDatabaseStmt::TYPE;

ResolvedCreateDatabaseStmt::~ResolvedCreateDatabaseStmt() {
}

zetasql_base::Status ResolvedCreateDatabaseStmt::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedStatementProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_create_database_stmt_node());
}

zetasql_base::Status ResolvedCreateDatabaseStmt::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedCreateDatabaseStmtProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  for (const auto& elem : name_path_) {
    proto->add_name_path(elem);
  }
  for (const auto& elem : option_list_) {
    ZETASQL_RETURN_IF_ERROR(elem->SaveTo(
      file_descriptor_set_map, proto->add_option_list()));
  }
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedCreateDatabaseStmt>> ResolvedCreateDatabaseStmt::RestoreFrom(
    const ResolvedCreateDatabaseStmtProto& proto,
    const ResolvedNode::RestoreParams& params) {
  std::vector<std::string> name_path;
  for (const auto& elem : proto.name_path()) {
    name_path.push_back(elem);
  }
  std::vector<std::unique_ptr<const ResolvedOption>> option_list;
  for (const auto& elem : proto.option_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedOption> elem_restored,
                     ResolvedOption::RestoreFrom(elem, params));
    option_list.push_back(std::move(elem_restored));
  }
  std::vector<std::unique_ptr<const ResolvedOption>> hint_list;
  for (const auto& elem : proto.parent().hint_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedOption> elem_restored,
                     ResolvedOption::RestoreFrom(elem, params));
    hint_list.push_back(std::move(elem_restored));
  }
  auto node = MakeResolvedCreateDatabaseStmt(
      std::move(name_path),
      std::move(option_list));

  node->set_hint_list(std::move(hint_list));
  return std::move(node);
}

void ResolvedCreateDatabaseStmt::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
  for (const auto& elem : option_list_) {
    child_nodes->emplace_back(elem.get());
  }
}

void ResolvedCreateDatabaseStmt::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
  for (auto& elem : option_list_) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(&elem));
  }
}

zetasql_base::Status ResolvedCreateDatabaseStmt::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedCreateDatabaseStmt(this);
}

zetasql_base::Status ResolvedCreateDatabaseStmt::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  for (const auto& elem : option_list_) {
    ZETASQL_RETURN_IF_ERROR(elem.get()->Accept(visitor));
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedCreateDatabaseStmt::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  {
    fields->emplace_back("name_path", ToStringImpl(name_path_));
  }
  if (!option_list_.empty()) {
    fields->emplace_back("option_list", option_list_);
  }
}

zetasql_base::Status ResolvedCreateDatabaseStmt::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedCreateDatabaseStmt::name_path not accessed)";
  }
  if ((accessed_ & (1<<1)) == 0 &&
      !IsDefaultValue(option_list_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedCreateDatabaseStmt::option_list not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<1)) != 0) {
    for (const auto& it : option_list_) ZETASQL_RETURN_IF_ERROR(it->CheckFieldsAccessed());
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedCreateDatabaseStmt::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
  for (const auto& it : option_list_) it->ClearFieldsAccessed();
}

const ResolvedCreateStatement::CreateScope ResolvedCreateStatement::CREATE_DEFAULT_SCOPE;
const ResolvedCreateStatement::CreateScope ResolvedCreateStatement::CREATE_PRIVATE;
const ResolvedCreateStatement::CreateScope ResolvedCreateStatement::CREATE_PUBLIC;
const ResolvedCreateStatement::CreateScope ResolvedCreateStatement::CREATE_TEMP;
const ResolvedCreateStatement::CreateMode ResolvedCreateStatement::CREATE_DEFAULT;
const ResolvedCreateStatement::CreateMode ResolvedCreateStatement::CREATE_OR_REPLACE;
const ResolvedCreateStatement::CreateMode ResolvedCreateStatement::CREATE_IF_NOT_EXISTS;
const ResolvedCreateStatement::SqlSecurity ResolvedCreateStatement::SQL_SECURITY_UNSPECIFIED;
const ResolvedCreateStatement::SqlSecurity ResolvedCreateStatement::SQL_SECURITY_DEFINER;
const ResolvedCreateStatement::SqlSecurity ResolvedCreateStatement::SQL_SECURITY_INVOKER;

ResolvedCreateStatement::~ResolvedCreateStatement() {
}

zetasql_base::Status ResolvedCreateStatement::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedStatementProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_create_statement_node());
}

zetasql_base::Status ResolvedCreateStatement::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedCreateStatementProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  for (const auto& elem : name_path_) {
    proto->add_name_path(elem);
  }
  proto->set_create_scope(create_scope_);
  proto->set_create_mode(create_mode_);
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedCreateStatement>> ResolvedCreateStatement::RestoreFrom(
    const AnyResolvedCreateStatementProto& proto,
    const ResolvedNode::RestoreParams& params) {
  switch (proto.node_case()) {
    case AnyResolvedCreateStatementProto::kResolvedCreateExternalTableStmtNode:
      return ResolvedCreateExternalTableStmt::RestoreFrom(
          proto.resolved_create_external_table_stmt_node(), params);
    case AnyResolvedCreateStatementProto::kResolvedCreateFunctionStmtNode:
      return ResolvedCreateFunctionStmt::RestoreFrom(
          proto.resolved_create_function_stmt_node(), params);
    case AnyResolvedCreateStatementProto::kResolvedCreateTableFunctionStmtNode:
      return ResolvedCreateTableFunctionStmt::RestoreFrom(
          proto.resolved_create_table_function_stmt_node(), params);
    case AnyResolvedCreateStatementProto::kResolvedCreateIndexStmtNode:
      return ResolvedCreateIndexStmt::RestoreFrom(
          proto.resolved_create_index_stmt_node(), params);
    case AnyResolvedCreateStatementProto::kResolvedCreateConstantStmtNode:
      return ResolvedCreateConstantStmt::RestoreFrom(
          proto.resolved_create_constant_stmt_node(), params);
    case AnyResolvedCreateStatementProto::kResolvedCreateTableStmtBaseNode:
      return ResolvedCreateTableStmtBase::RestoreFrom(
          proto.resolved_create_table_stmt_base_node(), params);
    case AnyResolvedCreateStatementProto::kResolvedCreateModelStmtNode:
      return ResolvedCreateModelStmt::RestoreFrom(
          proto.resolved_create_model_stmt_node(), params);
    case AnyResolvedCreateStatementProto::kResolvedCreateViewBaseNode:
      return ResolvedCreateViewBase::RestoreFrom(
          proto.resolved_create_view_base_node(), params);
    case AnyResolvedCreateStatementProto::kResolvedCreateProcedureStmtNode:
      return ResolvedCreateProcedureStmt::RestoreFrom(
          proto.resolved_create_procedure_stmt_node(), params);
  case AnyResolvedCreateStatementProto::NODE_NOT_SET:
    return ::zetasql_base::InvalidArgumentErrorBuilder(ZETASQL_LOC)
        << "No subnode types set in ResolvedCreateStatementProto";
  }
}

void ResolvedCreateStatement::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
}

void ResolvedCreateStatement::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
}

zetasql_base::Status ResolvedCreateStatement::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedCreateStatement(this);
}

zetasql_base::Status ResolvedCreateStatement::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  return ::zetasql_base::OkStatus();
}

void ResolvedCreateStatement::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  if (!IsDefaultValue(name_path_)) {
    fields->emplace_back("name_path", ToStringImpl(name_path_));
  }
  if (!IsDefaultValue(create_scope_)) {
    fields->emplace_back("create_scope", ToStringImpl(create_scope_));
  }
  if (!IsDefaultValue(create_mode_)) {
    fields->emplace_back("create_mode", ToStringImpl(create_mode_));
  }
}

zetasql_base::Status ResolvedCreateStatement::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0 &&
      !IsDefaultValue(name_path_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedCreateStatement::name_path not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<1)) == 0 &&
      !IsDefaultValue(create_scope_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedCreateStatement::create_scope not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<2)) == 0 &&
      !IsDefaultValue(create_mode_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedCreateStatement::create_mode not accessed "
           "and has non-default value)";
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedCreateStatement::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
}

const ResolvedNodeKind ResolvedIndexItem::TYPE;

ResolvedIndexItem::~ResolvedIndexItem() {
}

zetasql_base::Status ResolvedIndexItem::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedArgumentProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_index_item_node());
}

zetasql_base::Status ResolvedIndexItem::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedIndexItemProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  if (column_ref_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(column_ref_->SaveTo(
        file_descriptor_set_map, proto->mutable_column_ref()));
  }
  proto->set_descending(descending_);
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedIndexItem>> ResolvedIndexItem::RestoreFrom(
    const ResolvedIndexItemProto& proto,
    const ResolvedNode::RestoreParams& params) {
  std::unique_ptr<const ResolvedColumnRef> column_ref;
  if (proto.
  has_column_ref()) {
    ZETASQL_ASSIGN_OR_RETURN(column_ref,
                     ResolvedColumnRef::RestoreFrom(
                         proto.column_ref(), params));
  }
  bool descending =
      proto.descending();
  auto node = MakeResolvedIndexItem(
      std::move(column_ref),
      std::move(descending));

  return std::move(node);
}

void ResolvedIndexItem::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
  if (column_ref_ != nullptr) {
    child_nodes->emplace_back(column_ref_.get());
  }
}

void ResolvedIndexItem::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
  if (column_ref_ != nullptr) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(
            &column_ref_));
    static_assert(sizeof(column_ref_) ==
                  sizeof(*(mutable_child_node_ptrs->back())),
                  "Incorrect casting of mutable child node");
  }
}

zetasql_base::Status ResolvedIndexItem::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedIndexItem(this);
}

zetasql_base::Status ResolvedIndexItem::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  if (column_ref_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(column_ref_.get()->Accept(visitor));
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedIndexItem::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  if (column_ref_ != nullptr) {
    fields->emplace_back("column_ref", column_ref_.get());
  }
  {
    fields->emplace_back("descending", ToStringImpl(descending_));
  }
}

zetasql_base::Status ResolvedIndexItem::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedIndexItem::column_ref not accessed)";
  }
  if ((accessed_ & (1<<1)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedIndexItem::descending not accessed)";
  }
  if ((accessed_ & (1<<0)) != 0) {
    if (column_ref_ != nullptr) {
      ZETASQL_RETURN_IF_ERROR(column_ref_->CheckFieldsAccessed());
    }
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedIndexItem::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
  if (column_ref_ != nullptr) column_ref_->ClearFieldsAccessed();
}

const ResolvedNodeKind ResolvedUnnestItem::TYPE;

ResolvedUnnestItem::~ResolvedUnnestItem() {
}

zetasql_base::Status ResolvedUnnestItem::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedArgumentProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_unnest_item_node());
}

zetasql_base::Status ResolvedUnnestItem::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedUnnestItemProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  if (array_expr_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(array_expr_->SaveTo(
        file_descriptor_set_map, proto->mutable_array_expr()));
  }
  ZETASQL_RETURN_IF_ERROR(SaveToImpl(
      element_column_, file_descriptor_set_map,
      proto->mutable_element_column()));
  if (array_offset_column_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(array_offset_column_->SaveTo(
        file_descriptor_set_map, proto->mutable_array_offset_column()));
  }
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedUnnestItem>> ResolvedUnnestItem::RestoreFrom(
    const ResolvedUnnestItemProto& proto,
    const ResolvedNode::RestoreParams& params) {
  std::unique_ptr<const ResolvedExpr> array_expr;
  if (proto.
  has_array_expr()) {
    ZETASQL_ASSIGN_OR_RETURN(array_expr,
                     ResolvedExpr::RestoreFrom(
                         proto.array_expr(), params));
  }
  ZETASQL_ASSIGN_OR_RETURN(ResolvedColumn element_column,
                   RestoreFromImpl(proto.element_column(),
                                   params));
  std::unique_ptr<const ResolvedColumnHolder> array_offset_column;
  if (proto.
  has_array_offset_column()) {
    ZETASQL_ASSIGN_OR_RETURN(array_offset_column,
                     ResolvedColumnHolder::RestoreFrom(
                         proto.array_offset_column(), params));
  }
  auto node = MakeResolvedUnnestItem(
      std::move(array_expr),
      std::move(element_column),
      std::move(array_offset_column));

  return std::move(node);
}

void ResolvedUnnestItem::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
  if (array_expr_ != nullptr) {
    child_nodes->emplace_back(array_expr_.get());
  }
  if (array_offset_column_ != nullptr) {
    child_nodes->emplace_back(array_offset_column_.get());
  }
}

void ResolvedUnnestItem::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
  if (array_expr_ != nullptr) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(
            &array_expr_));
    static_assert(sizeof(array_expr_) ==
                  sizeof(*(mutable_child_node_ptrs->back())),
                  "Incorrect casting of mutable child node");
  }
  if (array_offset_column_ != nullptr) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(
            &array_offset_column_));
    static_assert(sizeof(array_offset_column_) ==
                  sizeof(*(mutable_child_node_ptrs->back())),
                  "Incorrect casting of mutable child node");
  }
}

zetasql_base::Status ResolvedUnnestItem::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedUnnestItem(this);
}

zetasql_base::Status ResolvedUnnestItem::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  if (array_expr_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(array_expr_.get()->Accept(visitor));
  }
  if (array_offset_column_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(array_offset_column_.get()->Accept(visitor));
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedUnnestItem::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  if (array_expr_ != nullptr) {
    fields->emplace_back("array_expr", array_expr_.get());
  }
  {
    fields->emplace_back("element_column", ToStringImpl(element_column_));
  }
  if (array_offset_column_ != nullptr) {
    fields->emplace_back("array_offset_column", array_offset_column_.get());
  }
}

zetasql_base::Status ResolvedUnnestItem::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedUnnestItem::array_expr not accessed)";
  }
  if ((accessed_ & (1<<1)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedUnnestItem::element_column not accessed)";
  }
  if ((accessed_ & (1<<2)) == 0 &&
      !IsDefaultValue(array_offset_column_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedUnnestItem::array_offset_column not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<0)) != 0) {
    if (array_expr_ != nullptr) {
      ZETASQL_RETURN_IF_ERROR(array_expr_->CheckFieldsAccessed());
    }
  }
  if ((accessed_ & (1<<2)) != 0) {
    if (array_offset_column_ != nullptr) {
      ZETASQL_RETURN_IF_ERROR(array_offset_column_->CheckFieldsAccessed());
    }
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedUnnestItem::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
  if (array_expr_ != nullptr) array_expr_->ClearFieldsAccessed();
  if (array_offset_column_ != nullptr) array_offset_column_->ClearFieldsAccessed();
}

const ResolvedNodeKind ResolvedCreateIndexStmt::TYPE;

ResolvedCreateIndexStmt::~ResolvedCreateIndexStmt() {
}

zetasql_base::Status ResolvedCreateIndexStmt::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedCreateStatementProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_create_index_stmt_node());
}

zetasql_base::Status ResolvedCreateIndexStmt::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedCreateIndexStmtProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  for (const auto& elem : table_name_path_) {
    proto->add_table_name_path(elem);
  }
  if (table_scan_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(table_scan_->SaveTo(
        file_descriptor_set_map, proto->mutable_table_scan()));
  }
  proto->set_is_unique(is_unique_);
  for (const auto& elem : index_item_list_) {
    ZETASQL_RETURN_IF_ERROR(elem->SaveTo(
      file_descriptor_set_map, proto->add_index_item_list()));
  }
  for (const auto& elem : storing_expression_list_) {
    ZETASQL_RETURN_IF_ERROR(elem->SaveTo(
      file_descriptor_set_map, proto->add_storing_expression_list()));
  }
  for (const auto& elem : option_list_) {
    ZETASQL_RETURN_IF_ERROR(elem->SaveTo(
      file_descriptor_set_map, proto->add_option_list()));
  }
  for (const auto& elem : computed_columns_list_) {
    ZETASQL_RETURN_IF_ERROR(elem->SaveTo(
      file_descriptor_set_map, proto->add_computed_columns_list()));
  }
  for (const auto& elem : unnest_expressions_list_) {
    ZETASQL_RETURN_IF_ERROR(elem->SaveTo(
      file_descriptor_set_map, proto->add_unnest_expressions_list()));
  }
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedCreateIndexStmt>> ResolvedCreateIndexStmt::RestoreFrom(
    const ResolvedCreateIndexStmtProto& proto,
    const ResolvedNode::RestoreParams& params) {
  std::vector<std::string> table_name_path;
  for (const auto& elem : proto.table_name_path()) {
    table_name_path.push_back(elem);
  }
  std::unique_ptr<const ResolvedTableScan> table_scan;
  if (proto.
  has_table_scan()) {
    ZETASQL_ASSIGN_OR_RETURN(table_scan,
                     ResolvedTableScan::RestoreFrom(
                         proto.table_scan(), params));
  }
  bool is_unique =
      proto.is_unique();
  std::vector<std::unique_ptr<const ResolvedIndexItem>> index_item_list;
  for (const auto& elem : proto.index_item_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedIndexItem> elem_restored,
                     ResolvedIndexItem::RestoreFrom(elem, params));
    index_item_list.push_back(std::move(elem_restored));
  }
  std::vector<std::unique_ptr<const ResolvedExpr>> storing_expression_list;
  for (const auto& elem : proto.storing_expression_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedExpr> elem_restored,
                     ResolvedExpr::RestoreFrom(elem, params));
    storing_expression_list.push_back(std::move(elem_restored));
  }
  std::vector<std::unique_ptr<const ResolvedOption>> option_list;
  for (const auto& elem : proto.option_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedOption> elem_restored,
                     ResolvedOption::RestoreFrom(elem, params));
    option_list.push_back(std::move(elem_restored));
  }
  std::vector<std::unique_ptr<const ResolvedComputedColumn>> computed_columns_list;
  for (const auto& elem : proto.computed_columns_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedComputedColumn> elem_restored,
                     ResolvedComputedColumn::RestoreFrom(elem, params));
    computed_columns_list.push_back(std::move(elem_restored));
  }
  std::vector<std::unique_ptr<const ResolvedUnnestItem>> unnest_expressions_list;
  for (const auto& elem : proto.unnest_expressions_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedUnnestItem> elem_restored,
                     ResolvedUnnestItem::RestoreFrom(elem, params));
    unnest_expressions_list.push_back(std::move(elem_restored));
  }
  std::vector<std::unique_ptr<const ResolvedOption>> hint_list;
  for (const auto& elem : proto.parent().parent().hint_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedOption> elem_restored,
                     ResolvedOption::RestoreFrom(elem, params));
    hint_list.push_back(std::move(elem_restored));
  }
  std::vector<std::string> name_path;
  for (const auto& elem : proto.parent().name_path()) {
    name_path.push_back(elem);
  }
  CreateScope create_scope =
      proto.parent().create_scope();
  CreateMode create_mode =
      proto.parent().create_mode();
  auto node = MakeResolvedCreateIndexStmt(
      std::move(name_path),
      std::move(create_scope),
      std::move(create_mode),
      std::move(table_name_path),
      std::move(table_scan),
      std::move(is_unique),
      std::move(index_item_list),
      std::move(storing_expression_list),
      std::move(option_list),
      std::move(computed_columns_list),
      std::move(unnest_expressions_list));

  node->set_hint_list(std::move(hint_list));
  return std::move(node);
}

void ResolvedCreateIndexStmt::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
  if (table_scan_ != nullptr) {
    child_nodes->emplace_back(table_scan_.get());
  }
  for (const auto& elem : index_item_list_) {
    child_nodes->emplace_back(elem.get());
  }
  for (const auto& elem : storing_expression_list_) {
    child_nodes->emplace_back(elem.get());
  }
  for (const auto& elem : option_list_) {
    child_nodes->emplace_back(elem.get());
  }
  for (const auto& elem : computed_columns_list_) {
    child_nodes->emplace_back(elem.get());
  }
  for (const auto& elem : unnest_expressions_list_) {
    child_nodes->emplace_back(elem.get());
  }
}

void ResolvedCreateIndexStmt::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
  if (table_scan_ != nullptr) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(
            &table_scan_));
    static_assert(sizeof(table_scan_) ==
                  sizeof(*(mutable_child_node_ptrs->back())),
                  "Incorrect casting of mutable child node");
  }
  for (auto& elem : index_item_list_) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(&elem));
  }
  for (auto& elem : storing_expression_list_) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(&elem));
  }
  for (auto& elem : option_list_) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(&elem));
  }
  for (auto& elem : computed_columns_list_) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(&elem));
  }
  for (auto& elem : unnest_expressions_list_) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(&elem));
  }
}

zetasql_base::Status ResolvedCreateIndexStmt::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedCreateIndexStmt(this);
}

zetasql_base::Status ResolvedCreateIndexStmt::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  if (table_scan_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(table_scan_.get()->Accept(visitor));
  }
  for (const auto& elem : index_item_list_) {
    ZETASQL_RETURN_IF_ERROR(elem.get()->Accept(visitor));
  }
  for (const auto& elem : storing_expression_list_) {
    ZETASQL_RETURN_IF_ERROR(elem.get()->Accept(visitor));
  }
  for (const auto& elem : option_list_) {
    ZETASQL_RETURN_IF_ERROR(elem.get()->Accept(visitor));
  }
  for (const auto& elem : computed_columns_list_) {
    ZETASQL_RETURN_IF_ERROR(elem.get()->Accept(visitor));
  }
  for (const auto& elem : unnest_expressions_list_) {
    ZETASQL_RETURN_IF_ERROR(elem.get()->Accept(visitor));
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedCreateIndexStmt::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  {
    fields->emplace_back("table_name_path", ToStringImpl(table_name_path_));
  }
  if (table_scan_ != nullptr) {
    fields->emplace_back("table_scan", table_scan_.get());
  }
  {
    fields->emplace_back("is_unique", ToStringImpl(is_unique_));
  }
  if (!index_item_list_.empty()) {
    fields->emplace_back("index_item_list", index_item_list_);
  }
  if (!storing_expression_list_.empty()) {
    fields->emplace_back("storing_expression_list", storing_expression_list_);
  }
  if (!option_list_.empty()) {
    fields->emplace_back("option_list", option_list_);
  }
  if (!computed_columns_list_.empty()) {
    fields->emplace_back("computed_columns_list", computed_columns_list_);
  }
  if (!unnest_expressions_list_.empty()) {
    fields->emplace_back("unnest_expressions_list", unnest_expressions_list_);
  }
}

zetasql_base::Status ResolvedCreateIndexStmt::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedCreateIndexStmt::table_name_path not accessed)";
  }
  if ((accessed_ & (1<<2)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedCreateIndexStmt::is_unique not accessed)";
  }
  if ((accessed_ & (1<<3)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedCreateIndexStmt::index_item_list not accessed)";
  }
  if ((accessed_ & (1<<4)) == 0 &&
      !IsDefaultValue(storing_expression_list_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedCreateIndexStmt::storing_expression_list not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<5)) == 0 &&
      !IsDefaultValue(option_list_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedCreateIndexStmt::option_list not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<6)) == 0 &&
      !IsDefaultValue(computed_columns_list_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedCreateIndexStmt::computed_columns_list not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<7)) == 0 &&
      !IsDefaultValue(unnest_expressions_list_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedCreateIndexStmt::unnest_expressions_list not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<1)) != 0) {
    if (table_scan_ != nullptr) {
      ZETASQL_RETURN_IF_ERROR(table_scan_->CheckFieldsAccessed());
    }
  }
  if ((accessed_ & (1<<3)) != 0) {
    for (const auto& it : index_item_list_) ZETASQL_RETURN_IF_ERROR(it->CheckFieldsAccessed());
  }
  if ((accessed_ & (1<<4)) != 0) {
    for (const auto& it : storing_expression_list_) ZETASQL_RETURN_IF_ERROR(it->CheckFieldsAccessed());
  }
  if ((accessed_ & (1<<5)) != 0) {
    for (const auto& it : option_list_) ZETASQL_RETURN_IF_ERROR(it->CheckFieldsAccessed());
  }
  if ((accessed_ & (1<<6)) != 0) {
    for (const auto& it : computed_columns_list_) ZETASQL_RETURN_IF_ERROR(it->CheckFieldsAccessed());
  }
  if ((accessed_ & (1<<7)) != 0) {
    for (const auto& it : unnest_expressions_list_) ZETASQL_RETURN_IF_ERROR(it->CheckFieldsAccessed());
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedCreateIndexStmt::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
  if (table_scan_ != nullptr) table_scan_->ClearFieldsAccessed();
  for (const auto& it : index_item_list_) it->ClearFieldsAccessed();
  for (const auto& it : storing_expression_list_) it->ClearFieldsAccessed();
  for (const auto& it : option_list_) it->ClearFieldsAccessed();
  for (const auto& it : computed_columns_list_) it->ClearFieldsAccessed();
  for (const auto& it : unnest_expressions_list_) it->ClearFieldsAccessed();
}

ResolvedCreateTableStmtBase::~ResolvedCreateTableStmtBase() {
}

zetasql_base::Status ResolvedCreateTableStmtBase::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedCreateStatementProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_create_table_stmt_base_node());
}

zetasql_base::Status ResolvedCreateTableStmtBase::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedCreateTableStmtBaseProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  for (const auto& elem : option_list_) {
    ZETASQL_RETURN_IF_ERROR(elem->SaveTo(
      file_descriptor_set_map, proto->add_option_list()));
  }
  for (const auto& elem : column_definition_list_) {
    ZETASQL_RETURN_IF_ERROR(elem->SaveTo(
      file_descriptor_set_map, proto->add_column_definition_list()));
  }
  for (const auto& elem : pseudo_column_list_) {
    ZETASQL_RETURN_IF_ERROR(SaveToImpl(
        elem, file_descriptor_set_map, proto->add_pseudo_column_list()));
  }
  if (primary_key_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(primary_key_->SaveTo(
        file_descriptor_set_map, proto->mutable_primary_key()));
  }
  for (const auto& elem : foreign_key_list_) {
    ZETASQL_RETURN_IF_ERROR(elem->SaveTo(
      file_descriptor_set_map, proto->add_foreign_key_list()));
  }
  for (const auto& elem : check_constraint_list_) {
    ZETASQL_RETURN_IF_ERROR(elem->SaveTo(
      file_descriptor_set_map, proto->add_check_constraint_list()));
  }
  for (const auto& elem : partition_by_list_) {
    ZETASQL_RETURN_IF_ERROR(elem->SaveTo(
      file_descriptor_set_map, proto->add_partition_by_list()));
  }
  for (const auto& elem : cluster_by_list_) {
    ZETASQL_RETURN_IF_ERROR(elem->SaveTo(
      file_descriptor_set_map, proto->add_cluster_by_list()));
  }
  proto->set_is_value_table(is_value_table_);
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedCreateTableStmtBase>> ResolvedCreateTableStmtBase::RestoreFrom(
    const AnyResolvedCreateTableStmtBaseProto& proto,
    const ResolvedNode::RestoreParams& params) {
  switch (proto.node_case()) {
    case AnyResolvedCreateTableStmtBaseProto::kResolvedCreateTableAsSelectStmtNode:
      return ResolvedCreateTableAsSelectStmt::RestoreFrom(
          proto.resolved_create_table_as_select_stmt_node(), params);
    case AnyResolvedCreateTableStmtBaseProto::kResolvedCreateTableStmtNode:
      return ResolvedCreateTableStmt::RestoreFrom(
          proto.resolved_create_table_stmt_node(), params);
  case AnyResolvedCreateTableStmtBaseProto::NODE_NOT_SET:
    return ::zetasql_base::InvalidArgumentErrorBuilder(ZETASQL_LOC)
        << "No subnode types set in ResolvedCreateTableStmtBaseProto";
  }
}

void ResolvedCreateTableStmtBase::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
  for (const auto& elem : option_list_) {
    child_nodes->emplace_back(elem.get());
  }
  for (const auto& elem : column_definition_list_) {
    child_nodes->emplace_back(elem.get());
  }
  if (primary_key_ != nullptr) {
    child_nodes->emplace_back(primary_key_.get());
  }
  for (const auto& elem : foreign_key_list_) {
    child_nodes->emplace_back(elem.get());
  }
  for (const auto& elem : check_constraint_list_) {
    child_nodes->emplace_back(elem.get());
  }
  for (const auto& elem : partition_by_list_) {
    child_nodes->emplace_back(elem.get());
  }
  for (const auto& elem : cluster_by_list_) {
    child_nodes->emplace_back(elem.get());
  }
}

void ResolvedCreateTableStmtBase::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
  for (auto& elem : option_list_) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(&elem));
  }
  for (auto& elem : column_definition_list_) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(&elem));
  }
  if (primary_key_ != nullptr) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(
            &primary_key_));
    static_assert(sizeof(primary_key_) ==
                  sizeof(*(mutable_child_node_ptrs->back())),
                  "Incorrect casting of mutable child node");
  }
  for (auto& elem : foreign_key_list_) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(&elem));
  }
  for (auto& elem : check_constraint_list_) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(&elem));
  }
  for (auto& elem : partition_by_list_) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(&elem));
  }
  for (auto& elem : cluster_by_list_) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(&elem));
  }
}

zetasql_base::Status ResolvedCreateTableStmtBase::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedCreateTableStmtBase(this);
}

zetasql_base::Status ResolvedCreateTableStmtBase::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  for (const auto& elem : option_list_) {
    ZETASQL_RETURN_IF_ERROR(elem.get()->Accept(visitor));
  }
  for (const auto& elem : column_definition_list_) {
    ZETASQL_RETURN_IF_ERROR(elem.get()->Accept(visitor));
  }
  if (primary_key_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(primary_key_.get()->Accept(visitor));
  }
  for (const auto& elem : foreign_key_list_) {
    ZETASQL_RETURN_IF_ERROR(elem.get()->Accept(visitor));
  }
  for (const auto& elem : check_constraint_list_) {
    ZETASQL_RETURN_IF_ERROR(elem.get()->Accept(visitor));
  }
  for (const auto& elem : partition_by_list_) {
    ZETASQL_RETURN_IF_ERROR(elem.get()->Accept(visitor));
  }
  for (const auto& elem : cluster_by_list_) {
    ZETASQL_RETURN_IF_ERROR(elem.get()->Accept(visitor));
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedCreateTableStmtBase::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  if (!option_list_.empty()) {
    fields->emplace_back("option_list", option_list_);
  }
  if (!column_definition_list_.empty()) {
    fields->emplace_back("column_definition_list", column_definition_list_);
  }
  if (!IsDefaultValue(pseudo_column_list_)) {
    fields->emplace_back("pseudo_column_list", ToStringImpl(pseudo_column_list_));
  }
  if (primary_key_ != nullptr) {
    fields->emplace_back("primary_key", primary_key_.get());
  }
  if (!foreign_key_list_.empty()) {
    fields->emplace_back("foreign_key_list", foreign_key_list_);
  }
  if (!check_constraint_list_.empty()) {
    fields->emplace_back("check_constraint_list", check_constraint_list_);
  }
  if (!partition_by_list_.empty()) {
    fields->emplace_back("partition_by_list", partition_by_list_);
  }
  if (!cluster_by_list_.empty()) {
    fields->emplace_back("cluster_by_list", cluster_by_list_);
  }
  if (!IsDefaultValue(is_value_table_)) {
    fields->emplace_back("is_value_table", ToStringImpl(is_value_table_));
  }
}

zetasql_base::Status ResolvedCreateTableStmtBase::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0 &&
      !IsDefaultValue(option_list_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedCreateTableStmtBase::option_list not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<3)) == 0 &&
      !IsDefaultValue(primary_key_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedCreateTableStmtBase::primary_key not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<4)) == 0 &&
      !IsDefaultValue(foreign_key_list_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedCreateTableStmtBase::foreign_key_list not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<5)) == 0 &&
      !IsDefaultValue(check_constraint_list_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedCreateTableStmtBase::check_constraint_list not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<6)) == 0 &&
      !IsDefaultValue(partition_by_list_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedCreateTableStmtBase::partition_by_list not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<7)) == 0 &&
      !IsDefaultValue(cluster_by_list_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedCreateTableStmtBase::cluster_by_list not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<8)) == 0 &&
      !IsDefaultValue(is_value_table_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedCreateTableStmtBase::is_value_table not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<0)) != 0) {
    for (const auto& it : option_list_) ZETASQL_RETURN_IF_ERROR(it->CheckFieldsAccessed());
  }
  if ((accessed_ & (1<<1)) != 0) {
    for (const auto& it : column_definition_list_) ZETASQL_RETURN_IF_ERROR(it->CheckFieldsAccessed());
  }
  if ((accessed_ & (1<<3)) != 0) {
    if (primary_key_ != nullptr) {
      ZETASQL_RETURN_IF_ERROR(primary_key_->CheckFieldsAccessed());
    }
  }
  if ((accessed_ & (1<<4)) != 0) {
    for (const auto& it : foreign_key_list_) ZETASQL_RETURN_IF_ERROR(it->CheckFieldsAccessed());
  }
  if ((accessed_ & (1<<5)) != 0) {
    for (const auto& it : check_constraint_list_) ZETASQL_RETURN_IF_ERROR(it->CheckFieldsAccessed());
  }
  if ((accessed_ & (1<<6)) != 0) {
    for (const auto& it : partition_by_list_) ZETASQL_RETURN_IF_ERROR(it->CheckFieldsAccessed());
  }
  if ((accessed_ & (1<<7)) != 0) {
    for (const auto& it : cluster_by_list_) ZETASQL_RETURN_IF_ERROR(it->CheckFieldsAccessed());
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedCreateTableStmtBase::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
  for (const auto& it : option_list_) it->ClearFieldsAccessed();
  for (const auto& it : column_definition_list_) it->ClearFieldsAccessed();
  if (primary_key_ != nullptr) primary_key_->ClearFieldsAccessed();
  for (const auto& it : foreign_key_list_) it->ClearFieldsAccessed();
  for (const auto& it : check_constraint_list_) it->ClearFieldsAccessed();
  for (const auto& it : partition_by_list_) it->ClearFieldsAccessed();
  for (const auto& it : cluster_by_list_) it->ClearFieldsAccessed();
}

const ResolvedNodeKind ResolvedCreateTableStmt::TYPE;

ResolvedCreateTableStmt::~ResolvedCreateTableStmt() {
}

zetasql_base::Status ResolvedCreateTableStmt::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedCreateTableStmtBaseProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_create_table_stmt_node());
}

zetasql_base::Status ResolvedCreateTableStmt::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedCreateTableStmtProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedCreateTableStmt>> ResolvedCreateTableStmt::RestoreFrom(
    const ResolvedCreateTableStmtProto& proto,
    const ResolvedNode::RestoreParams& params) {
  std::vector<std::unique_ptr<const ResolvedOption>> hint_list;
  for (const auto& elem : proto.parent().parent().parent().hint_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedOption> elem_restored,
                     ResolvedOption::RestoreFrom(elem, params));
    hint_list.push_back(std::move(elem_restored));
  }
  std::vector<std::string> name_path;
  for (const auto& elem : proto.parent().parent().name_path()) {
    name_path.push_back(elem);
  }
  CreateScope create_scope =
      proto.parent().parent().create_scope();
  CreateMode create_mode =
      proto.parent().parent().create_mode();
  std::vector<std::unique_ptr<const ResolvedOption>> option_list;
  for (const auto& elem : proto.parent().option_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedOption> elem_restored,
                     ResolvedOption::RestoreFrom(elem, params));
    option_list.push_back(std::move(elem_restored));
  }
  std::vector<std::unique_ptr<const ResolvedColumnDefinition>> column_definition_list;
  for (const auto& elem : proto.parent().column_definition_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedColumnDefinition> elem_restored,
                     ResolvedColumnDefinition::RestoreFrom(elem, params));
    column_definition_list.push_back(std::move(elem_restored));
  }
  std::vector<ResolvedColumn> pseudo_column_list;
  for (const auto& elem : proto.parent().pseudo_column_list()) {
    ZETASQL_ASSIGN_OR_RETURN(auto elem_restored, RestoreFromImpl(elem, params));
    pseudo_column_list.push_back(std::move(elem_restored));
  }
  std::unique_ptr<const ResolvedPrimaryKey> primary_key;
  if (proto.parent().
  has_primary_key()) {
    ZETASQL_ASSIGN_OR_RETURN(primary_key,
                     ResolvedPrimaryKey::RestoreFrom(
                         proto.parent().primary_key(), params));
  }
  std::vector<std::unique_ptr<const ResolvedForeignKey>> foreign_key_list;
  for (const auto& elem : proto.parent().foreign_key_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedForeignKey> elem_restored,
                     ResolvedForeignKey::RestoreFrom(elem, params));
    foreign_key_list.push_back(std::move(elem_restored));
  }
  std::vector<std::unique_ptr<const ResolvedCheckConstraint>> check_constraint_list;
  for (const auto& elem : proto.parent().check_constraint_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedCheckConstraint> elem_restored,
                     ResolvedCheckConstraint::RestoreFrom(elem, params));
    check_constraint_list.push_back(std::move(elem_restored));
  }
  std::vector<std::unique_ptr<const ResolvedExpr>> partition_by_list;
  for (const auto& elem : proto.parent().partition_by_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedExpr> elem_restored,
                     ResolvedExpr::RestoreFrom(elem, params));
    partition_by_list.push_back(std::move(elem_restored));
  }
  std::vector<std::unique_ptr<const ResolvedExpr>> cluster_by_list;
  for (const auto& elem : proto.parent().cluster_by_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedExpr> elem_restored,
                     ResolvedExpr::RestoreFrom(elem, params));
    cluster_by_list.push_back(std::move(elem_restored));
  }
  bool is_value_table =
      proto.parent().is_value_table();
  auto node = MakeResolvedCreateTableStmt(
      std::move(name_path),
      std::move(create_scope),
      std::move(create_mode),
      std::move(option_list),
      std::move(column_definition_list),
      std::move(pseudo_column_list),
      std::move(primary_key),
      std::move(foreign_key_list),
      std::move(check_constraint_list),
      std::move(partition_by_list),
      std::move(cluster_by_list),
      std::move(is_value_table));

  node->set_hint_list(std::move(hint_list));
  return std::move(node);
}

zetasql_base::Status ResolvedCreateTableStmt::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedCreateTableStmt(this);
}

zetasql_base::Status ResolvedCreateTableStmt::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  return ::zetasql_base::OkStatus();
}

const ResolvedNodeKind ResolvedCreateTableAsSelectStmt::TYPE;

ResolvedCreateTableAsSelectStmt::~ResolvedCreateTableAsSelectStmt() {
}

zetasql_base::Status ResolvedCreateTableAsSelectStmt::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedCreateTableStmtBaseProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_create_table_as_select_stmt_node());
}

zetasql_base::Status ResolvedCreateTableAsSelectStmt::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedCreateTableAsSelectStmtProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  for (const auto& elem : output_column_list_) {
    ZETASQL_RETURN_IF_ERROR(elem->SaveTo(
      file_descriptor_set_map, proto->add_output_column_list()));
  }
  if (query_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(query_->SaveTo(
        file_descriptor_set_map, proto->mutable_query()));
  }
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedCreateTableAsSelectStmt>> ResolvedCreateTableAsSelectStmt::RestoreFrom(
    const ResolvedCreateTableAsSelectStmtProto& proto,
    const ResolvedNode::RestoreParams& params) {
  std::vector<std::unique_ptr<const ResolvedOutputColumn>> output_column_list;
  for (const auto& elem : proto.output_column_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedOutputColumn> elem_restored,
                     ResolvedOutputColumn::RestoreFrom(elem, params));
    output_column_list.push_back(std::move(elem_restored));
  }
  std::unique_ptr<const ResolvedScan> query;
  if (proto.
  has_query()) {
    ZETASQL_ASSIGN_OR_RETURN(query,
                     ResolvedScan::RestoreFrom(
                         proto.query(), params));
  }
  std::vector<std::unique_ptr<const ResolvedOption>> hint_list;
  for (const auto& elem : proto.parent().parent().parent().hint_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedOption> elem_restored,
                     ResolvedOption::RestoreFrom(elem, params));
    hint_list.push_back(std::move(elem_restored));
  }
  std::vector<std::string> name_path;
  for (const auto& elem : proto.parent().parent().name_path()) {
    name_path.push_back(elem);
  }
  CreateScope create_scope =
      proto.parent().parent().create_scope();
  CreateMode create_mode =
      proto.parent().parent().create_mode();
  std::vector<std::unique_ptr<const ResolvedOption>> option_list;
  for (const auto& elem : proto.parent().option_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedOption> elem_restored,
                     ResolvedOption::RestoreFrom(elem, params));
    option_list.push_back(std::move(elem_restored));
  }
  std::vector<std::unique_ptr<const ResolvedColumnDefinition>> column_definition_list;
  for (const auto& elem : proto.parent().column_definition_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedColumnDefinition> elem_restored,
                     ResolvedColumnDefinition::RestoreFrom(elem, params));
    column_definition_list.push_back(std::move(elem_restored));
  }
  std::vector<ResolvedColumn> pseudo_column_list;
  for (const auto& elem : proto.parent().pseudo_column_list()) {
    ZETASQL_ASSIGN_OR_RETURN(auto elem_restored, RestoreFromImpl(elem, params));
    pseudo_column_list.push_back(std::move(elem_restored));
  }
  std::unique_ptr<const ResolvedPrimaryKey> primary_key;
  if (proto.parent().
  has_primary_key()) {
    ZETASQL_ASSIGN_OR_RETURN(primary_key,
                     ResolvedPrimaryKey::RestoreFrom(
                         proto.parent().primary_key(), params));
  }
  std::vector<std::unique_ptr<const ResolvedForeignKey>> foreign_key_list;
  for (const auto& elem : proto.parent().foreign_key_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedForeignKey> elem_restored,
                     ResolvedForeignKey::RestoreFrom(elem, params));
    foreign_key_list.push_back(std::move(elem_restored));
  }
  std::vector<std::unique_ptr<const ResolvedCheckConstraint>> check_constraint_list;
  for (const auto& elem : proto.parent().check_constraint_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedCheckConstraint> elem_restored,
                     ResolvedCheckConstraint::RestoreFrom(elem, params));
    check_constraint_list.push_back(std::move(elem_restored));
  }
  std::vector<std::unique_ptr<const ResolvedExpr>> partition_by_list;
  for (const auto& elem : proto.parent().partition_by_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedExpr> elem_restored,
                     ResolvedExpr::RestoreFrom(elem, params));
    partition_by_list.push_back(std::move(elem_restored));
  }
  std::vector<std::unique_ptr<const ResolvedExpr>> cluster_by_list;
  for (const auto& elem : proto.parent().cluster_by_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedExpr> elem_restored,
                     ResolvedExpr::RestoreFrom(elem, params));
    cluster_by_list.push_back(std::move(elem_restored));
  }
  bool is_value_table =
      proto.parent().is_value_table();
  auto node = MakeResolvedCreateTableAsSelectStmt(
      std::move(name_path),
      std::move(create_scope),
      std::move(create_mode),
      std::move(option_list),
      std::move(column_definition_list),
      std::move(pseudo_column_list),
      std::move(primary_key),
      std::move(foreign_key_list),
      std::move(check_constraint_list),
      std::move(partition_by_list),
      std::move(cluster_by_list),
      std::move(is_value_table),
      std::move(output_column_list),
      std::move(query));

  node->set_hint_list(std::move(hint_list));
  return std::move(node);
}

void ResolvedCreateTableAsSelectStmt::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
  for (const auto& elem : output_column_list_) {
    child_nodes->emplace_back(elem.get());
  }
  if (query_ != nullptr) {
    child_nodes->emplace_back(query_.get());
  }
}

void ResolvedCreateTableAsSelectStmt::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
  for (auto& elem : output_column_list_) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(&elem));
  }
  if (query_ != nullptr) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(
            &query_));
    static_assert(sizeof(query_) ==
                  sizeof(*(mutable_child_node_ptrs->back())),
                  "Incorrect casting of mutable child node");
  }
}

zetasql_base::Status ResolvedCreateTableAsSelectStmt::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedCreateTableAsSelectStmt(this);
}

zetasql_base::Status ResolvedCreateTableAsSelectStmt::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  for (const auto& elem : output_column_list_) {
    ZETASQL_RETURN_IF_ERROR(elem.get()->Accept(visitor));
  }
  if (query_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(query_.get()->Accept(visitor));
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedCreateTableAsSelectStmt::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  if (!output_column_list_.empty()) {
    fields->emplace_back("output_column_list", output_column_list_);
  }
  if (query_ != nullptr) {
    fields->emplace_back("query", query_.get());
  }
}

zetasql_base::Status ResolvedCreateTableAsSelectStmt::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedCreateTableAsSelectStmt::output_column_list not accessed)";
  }
  if ((accessed_ & (1<<1)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedCreateTableAsSelectStmt::query not accessed)";
  }
  if ((accessed_ & (1<<0)) != 0) {
    for (const auto& it : output_column_list_) ZETASQL_RETURN_IF_ERROR(it->CheckFieldsAccessed());
  }
  if ((accessed_ & (1<<1)) != 0) {
    if (query_ != nullptr) {
      ZETASQL_RETURN_IF_ERROR(query_->CheckFieldsAccessed());
    }
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedCreateTableAsSelectStmt::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
  for (const auto& it : output_column_list_) it->ClearFieldsAccessed();
  if (query_ != nullptr) query_->ClearFieldsAccessed();
}

const ResolvedNodeKind ResolvedCreateModelStmt::TYPE;

ResolvedCreateModelStmt::~ResolvedCreateModelStmt() {
}

zetasql_base::Status ResolvedCreateModelStmt::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedCreateStatementProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_create_model_stmt_node());
}

zetasql_base::Status ResolvedCreateModelStmt::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedCreateModelStmtProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  for (const auto& elem : option_list_) {
    ZETASQL_RETURN_IF_ERROR(elem->SaveTo(
      file_descriptor_set_map, proto->add_option_list()));
  }
  for (const auto& elem : output_column_list_) {
    ZETASQL_RETURN_IF_ERROR(elem->SaveTo(
      file_descriptor_set_map, proto->add_output_column_list()));
  }
  if (query_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(query_->SaveTo(
        file_descriptor_set_map, proto->mutable_query()));
  }
  for (const auto& elem : transform_list_) {
    ZETASQL_RETURN_IF_ERROR(elem->SaveTo(
      file_descriptor_set_map, proto->add_transform_list()));
  }
  for (const auto& elem : transform_output_column_list_) {
    ZETASQL_RETURN_IF_ERROR(elem->SaveTo(
      file_descriptor_set_map, proto->add_transform_output_column_list()));
  }
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedCreateModelStmt>> ResolvedCreateModelStmt::RestoreFrom(
    const ResolvedCreateModelStmtProto& proto,
    const ResolvedNode::RestoreParams& params) {
  std::vector<std::unique_ptr<const ResolvedOption>> option_list;
  for (const auto& elem : proto.option_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedOption> elem_restored,
                     ResolvedOption::RestoreFrom(elem, params));
    option_list.push_back(std::move(elem_restored));
  }
  std::vector<std::unique_ptr<const ResolvedOutputColumn>> output_column_list;
  for (const auto& elem : proto.output_column_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedOutputColumn> elem_restored,
                     ResolvedOutputColumn::RestoreFrom(elem, params));
    output_column_list.push_back(std::move(elem_restored));
  }
  std::unique_ptr<const ResolvedScan> query;
  if (proto.
  has_query()) {
    ZETASQL_ASSIGN_OR_RETURN(query,
                     ResolvedScan::RestoreFrom(
                         proto.query(), params));
  }
  std::vector<std::unique_ptr<const ResolvedComputedColumn>> transform_list;
  for (const auto& elem : proto.transform_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedComputedColumn> elem_restored,
                     ResolvedComputedColumn::RestoreFrom(elem, params));
    transform_list.push_back(std::move(elem_restored));
  }
  std::vector<std::unique_ptr<const ResolvedOutputColumn>> transform_output_column_list;
  for (const auto& elem : proto.transform_output_column_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedOutputColumn> elem_restored,
                     ResolvedOutputColumn::RestoreFrom(elem, params));
    transform_output_column_list.push_back(std::move(elem_restored));
  }
  std::vector<std::unique_ptr<const ResolvedOption>> hint_list;
  for (const auto& elem : proto.parent().parent().hint_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedOption> elem_restored,
                     ResolvedOption::RestoreFrom(elem, params));
    hint_list.push_back(std::move(elem_restored));
  }
  std::vector<std::string> name_path;
  for (const auto& elem : proto.parent().name_path()) {
    name_path.push_back(elem);
  }
  CreateScope create_scope =
      proto.parent().create_scope();
  CreateMode create_mode =
      proto.parent().create_mode();
  auto node = MakeResolvedCreateModelStmt(
      std::move(name_path),
      std::move(create_scope),
      std::move(create_mode),
      std::move(option_list),
      std::move(output_column_list),
      std::move(query),
      std::move(transform_list),
      std::move(transform_output_column_list));

  node->set_hint_list(std::move(hint_list));
  return std::move(node);
}

void ResolvedCreateModelStmt::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
  for (const auto& elem : option_list_) {
    child_nodes->emplace_back(elem.get());
  }
  for (const auto& elem : output_column_list_) {
    child_nodes->emplace_back(elem.get());
  }
  if (query_ != nullptr) {
    child_nodes->emplace_back(query_.get());
  }
  for (const auto& elem : transform_list_) {
    child_nodes->emplace_back(elem.get());
  }
  for (const auto& elem : transform_output_column_list_) {
    child_nodes->emplace_back(elem.get());
  }
}

void ResolvedCreateModelStmt::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
  for (auto& elem : option_list_) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(&elem));
  }
  for (auto& elem : output_column_list_) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(&elem));
  }
  if (query_ != nullptr) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(
            &query_));
    static_assert(sizeof(query_) ==
                  sizeof(*(mutable_child_node_ptrs->back())),
                  "Incorrect casting of mutable child node");
  }
  for (auto& elem : transform_list_) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(&elem));
  }
  for (auto& elem : transform_output_column_list_) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(&elem));
  }
}

zetasql_base::Status ResolvedCreateModelStmt::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedCreateModelStmt(this);
}

zetasql_base::Status ResolvedCreateModelStmt::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  for (const auto& elem : option_list_) {
    ZETASQL_RETURN_IF_ERROR(elem.get()->Accept(visitor));
  }
  for (const auto& elem : output_column_list_) {
    ZETASQL_RETURN_IF_ERROR(elem.get()->Accept(visitor));
  }
  if (query_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(query_.get()->Accept(visitor));
  }
  for (const auto& elem : transform_list_) {
    ZETASQL_RETURN_IF_ERROR(elem.get()->Accept(visitor));
  }
  for (const auto& elem : transform_output_column_list_) {
    ZETASQL_RETURN_IF_ERROR(elem.get()->Accept(visitor));
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedCreateModelStmt::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  if (!option_list_.empty()) {
    fields->emplace_back("option_list", option_list_);
  }
  if (!output_column_list_.empty()) {
    fields->emplace_back("output_column_list", output_column_list_);
  }
  if (query_ != nullptr) {
    fields->emplace_back("query", query_.get());
  }
  if (!transform_list_.empty()) {
    fields->emplace_back("transform_list", transform_list_);
  }
  if (!transform_output_column_list_.empty()) {
    fields->emplace_back("transform_output_column_list", transform_output_column_list_);
  }
}

zetasql_base::Status ResolvedCreateModelStmt::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0 &&
      !IsDefaultValue(option_list_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedCreateModelStmt::option_list not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<1)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedCreateModelStmt::output_column_list not accessed)";
  }
  if ((accessed_ & (1<<2)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedCreateModelStmt::query not accessed)";
  }
  if ((accessed_ & (1<<0)) != 0) {
    for (const auto& it : option_list_) ZETASQL_RETURN_IF_ERROR(it->CheckFieldsAccessed());
  }
  if ((accessed_ & (1<<1)) != 0) {
    for (const auto& it : output_column_list_) ZETASQL_RETURN_IF_ERROR(it->CheckFieldsAccessed());
  }
  if ((accessed_ & (1<<2)) != 0) {
    if (query_ != nullptr) {
      ZETASQL_RETURN_IF_ERROR(query_->CheckFieldsAccessed());
    }
  }
  if ((accessed_ & (1<<3)) != 0) {
    for (const auto& it : transform_list_) ZETASQL_RETURN_IF_ERROR(it->CheckFieldsAccessed());
  }
  if ((accessed_ & (1<<4)) != 0) {
    for (const auto& it : transform_output_column_list_) ZETASQL_RETURN_IF_ERROR(it->CheckFieldsAccessed());
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedCreateModelStmt::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
  for (const auto& it : option_list_) it->ClearFieldsAccessed();
  for (const auto& it : output_column_list_) it->ClearFieldsAccessed();
  if (query_ != nullptr) query_->ClearFieldsAccessed();
  for (const auto& it : transform_list_) it->ClearFieldsAccessed();
  for (const auto& it : transform_output_column_list_) it->ClearFieldsAccessed();
}

ResolvedCreateViewBase::~ResolvedCreateViewBase() {
}

zetasql_base::Status ResolvedCreateViewBase::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedCreateStatementProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_create_view_base_node());
}

zetasql_base::Status ResolvedCreateViewBase::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedCreateViewBaseProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  for (const auto& elem : option_list_) {
    ZETASQL_RETURN_IF_ERROR(elem->SaveTo(
      file_descriptor_set_map, proto->add_option_list()));
  }
  for (const auto& elem : output_column_list_) {
    ZETASQL_RETURN_IF_ERROR(elem->SaveTo(
      file_descriptor_set_map, proto->add_output_column_list()));
  }
  if (query_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(query_->SaveTo(
        file_descriptor_set_map, proto->mutable_query()));
  }
  proto->set_sql(sql_);
  proto->set_sql_security(sql_security_);
  proto->set_is_value_table(is_value_table_);
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedCreateViewBase>> ResolvedCreateViewBase::RestoreFrom(
    const AnyResolvedCreateViewBaseProto& proto,
    const ResolvedNode::RestoreParams& params) {
  switch (proto.node_case()) {
    case AnyResolvedCreateViewBaseProto::kResolvedCreateViewStmtNode:
      return ResolvedCreateViewStmt::RestoreFrom(
          proto.resolved_create_view_stmt_node(), params);
    case AnyResolvedCreateViewBaseProto::kResolvedCreateMaterializedViewStmtNode:
      return ResolvedCreateMaterializedViewStmt::RestoreFrom(
          proto.resolved_create_materialized_view_stmt_node(), params);
  case AnyResolvedCreateViewBaseProto::NODE_NOT_SET:
    return ::zetasql_base::InvalidArgumentErrorBuilder(ZETASQL_LOC)
        << "No subnode types set in ResolvedCreateViewBaseProto";
  }
}

void ResolvedCreateViewBase::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
  for (const auto& elem : option_list_) {
    child_nodes->emplace_back(elem.get());
  }
  for (const auto& elem : output_column_list_) {
    child_nodes->emplace_back(elem.get());
  }
  if (query_ != nullptr) {
    child_nodes->emplace_back(query_.get());
  }
}

void ResolvedCreateViewBase::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
  for (auto& elem : option_list_) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(&elem));
  }
  for (auto& elem : output_column_list_) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(&elem));
  }
  if (query_ != nullptr) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(
            &query_));
    static_assert(sizeof(query_) ==
                  sizeof(*(mutable_child_node_ptrs->back())),
                  "Incorrect casting of mutable child node");
  }
}

zetasql_base::Status ResolvedCreateViewBase::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedCreateViewBase(this);
}

zetasql_base::Status ResolvedCreateViewBase::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  for (const auto& elem : option_list_) {
    ZETASQL_RETURN_IF_ERROR(elem.get()->Accept(visitor));
  }
  for (const auto& elem : output_column_list_) {
    ZETASQL_RETURN_IF_ERROR(elem.get()->Accept(visitor));
  }
  if (query_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(query_.get()->Accept(visitor));
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedCreateViewBase::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  if (!option_list_.empty()) {
    fields->emplace_back("option_list", option_list_);
  }
  if (!output_column_list_.empty()) {
    fields->emplace_back("output_column_list", output_column_list_);
  }
  if (query_ != nullptr) {
    fields->emplace_back("query", query_.get());
  }
  if (!IsDefaultValue(sql_)) {
    fields->emplace_back("sql", ToStringImpl(sql_));
  }
  if (!IsDefaultValue(sql_security_)) {
    fields->emplace_back("sql_security", ToStringImpl(sql_security_));
  }
  if (!IsDefaultValue(is_value_table_)) {
    fields->emplace_back("is_value_table", ToStringImpl(is_value_table_));
  }
}

zetasql_base::Status ResolvedCreateViewBase::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0 &&
      !IsDefaultValue(option_list_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedCreateViewBase::option_list not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<1)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedCreateViewBase::output_column_list not accessed)";
  }
  if ((accessed_ & (1<<4)) == 0 &&
      !IsDefaultValue(sql_security_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedCreateViewBase::sql_security not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<5)) == 0 &&
      !IsDefaultValue(is_value_table_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedCreateViewBase::is_value_table not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<0)) != 0) {
    for (const auto& it : option_list_) ZETASQL_RETURN_IF_ERROR(it->CheckFieldsAccessed());
  }
  if ((accessed_ & (1<<1)) != 0) {
    for (const auto& it : output_column_list_) ZETASQL_RETURN_IF_ERROR(it->CheckFieldsAccessed());
  }
  if ((accessed_ & (1<<2)) != 0) {
    if (query_ != nullptr) {
      ZETASQL_RETURN_IF_ERROR(query_->CheckFieldsAccessed());
    }
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedCreateViewBase::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
  for (const auto& it : option_list_) it->ClearFieldsAccessed();
  for (const auto& it : output_column_list_) it->ClearFieldsAccessed();
  if (query_ != nullptr) query_->ClearFieldsAccessed();
}

const ResolvedNodeKind ResolvedCreateViewStmt::TYPE;

ResolvedCreateViewStmt::~ResolvedCreateViewStmt() {
}

zetasql_base::Status ResolvedCreateViewStmt::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedCreateViewBaseProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_create_view_stmt_node());
}

zetasql_base::Status ResolvedCreateViewStmt::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedCreateViewStmtProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedCreateViewStmt>> ResolvedCreateViewStmt::RestoreFrom(
    const ResolvedCreateViewStmtProto& proto,
    const ResolvedNode::RestoreParams& params) {
  std::vector<std::unique_ptr<const ResolvedOption>> hint_list;
  for (const auto& elem : proto.parent().parent().parent().hint_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedOption> elem_restored,
                     ResolvedOption::RestoreFrom(elem, params));
    hint_list.push_back(std::move(elem_restored));
  }
  std::vector<std::string> name_path;
  for (const auto& elem : proto.parent().parent().name_path()) {
    name_path.push_back(elem);
  }
  CreateScope create_scope =
      proto.parent().parent().create_scope();
  CreateMode create_mode =
      proto.parent().parent().create_mode();
  std::vector<std::unique_ptr<const ResolvedOption>> option_list;
  for (const auto& elem : proto.parent().option_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedOption> elem_restored,
                     ResolvedOption::RestoreFrom(elem, params));
    option_list.push_back(std::move(elem_restored));
  }
  std::vector<std::unique_ptr<const ResolvedOutputColumn>> output_column_list;
  for (const auto& elem : proto.parent().output_column_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedOutputColumn> elem_restored,
                     ResolvedOutputColumn::RestoreFrom(elem, params));
    output_column_list.push_back(std::move(elem_restored));
  }
  std::unique_ptr<const ResolvedScan> query;
  if (proto.parent().
  has_query()) {
    ZETASQL_ASSIGN_OR_RETURN(query,
                     ResolvedScan::RestoreFrom(
                         proto.parent().query(), params));
  }
  std::string sql =
      proto.parent().sql();
  SqlSecurity sql_security =
      proto.parent().sql_security();
  bool is_value_table =
      proto.parent().is_value_table();
  auto node = MakeResolvedCreateViewStmt(
      std::move(name_path),
      std::move(create_scope),
      std::move(create_mode),
      std::move(option_list),
      std::move(output_column_list),
      std::move(query),
      std::move(sql),
      std::move(sql_security),
      std::move(is_value_table));

  node->set_hint_list(std::move(hint_list));
  return std::move(node);
}

zetasql_base::Status ResolvedCreateViewStmt::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedCreateViewStmt(this);
}

zetasql_base::Status ResolvedCreateViewStmt::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  return ::zetasql_base::OkStatus();
}

const ResolvedNodeKind ResolvedCreateExternalTableStmt::TYPE;

ResolvedCreateExternalTableStmt::~ResolvedCreateExternalTableStmt() {
}

zetasql_base::Status ResolvedCreateExternalTableStmt::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedCreateStatementProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_create_external_table_stmt_node());
}

zetasql_base::Status ResolvedCreateExternalTableStmt::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedCreateExternalTableStmtProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  for (const auto& elem : option_list_) {
    ZETASQL_RETURN_IF_ERROR(elem->SaveTo(
      file_descriptor_set_map, proto->add_option_list()));
  }
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedCreateExternalTableStmt>> ResolvedCreateExternalTableStmt::RestoreFrom(
    const ResolvedCreateExternalTableStmtProto& proto,
    const ResolvedNode::RestoreParams& params) {
  std::vector<std::unique_ptr<const ResolvedOption>> option_list;
  for (const auto& elem : proto.option_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedOption> elem_restored,
                     ResolvedOption::RestoreFrom(elem, params));
    option_list.push_back(std::move(elem_restored));
  }
  std::vector<std::unique_ptr<const ResolvedOption>> hint_list;
  for (const auto& elem : proto.parent().parent().hint_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedOption> elem_restored,
                     ResolvedOption::RestoreFrom(elem, params));
    hint_list.push_back(std::move(elem_restored));
  }
  std::vector<std::string> name_path;
  for (const auto& elem : proto.parent().name_path()) {
    name_path.push_back(elem);
  }
  CreateScope create_scope =
      proto.parent().create_scope();
  CreateMode create_mode =
      proto.parent().create_mode();
  auto node = MakeResolvedCreateExternalTableStmt(
      std::move(name_path),
      std::move(create_scope),
      std::move(create_mode),
      std::move(option_list));

  node->set_hint_list(std::move(hint_list));
  return std::move(node);
}

void ResolvedCreateExternalTableStmt::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
  for (const auto& elem : option_list_) {
    child_nodes->emplace_back(elem.get());
  }
}

void ResolvedCreateExternalTableStmt::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
  for (auto& elem : option_list_) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(&elem));
  }
}

zetasql_base::Status ResolvedCreateExternalTableStmt::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedCreateExternalTableStmt(this);
}

zetasql_base::Status ResolvedCreateExternalTableStmt::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  for (const auto& elem : option_list_) {
    ZETASQL_RETURN_IF_ERROR(elem.get()->Accept(visitor));
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedCreateExternalTableStmt::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  if (!option_list_.empty()) {
    fields->emplace_back("option_list", option_list_);
  }
}

zetasql_base::Status ResolvedCreateExternalTableStmt::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0 &&
      !IsDefaultValue(option_list_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedCreateExternalTableStmt::option_list not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<0)) != 0) {
    for (const auto& it : option_list_) ZETASQL_RETURN_IF_ERROR(it->CheckFieldsAccessed());
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedCreateExternalTableStmt::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
  for (const auto& it : option_list_) it->ClearFieldsAccessed();
}

const ResolvedNodeKind ResolvedExportDataStmt::TYPE;

ResolvedExportDataStmt::~ResolvedExportDataStmt() {
}

zetasql_base::Status ResolvedExportDataStmt::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedStatementProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_export_data_stmt_node());
}

zetasql_base::Status ResolvedExportDataStmt::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedExportDataStmtProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  for (const auto& elem : option_list_) {
    ZETASQL_RETURN_IF_ERROR(elem->SaveTo(
      file_descriptor_set_map, proto->add_option_list()));
  }
  for (const auto& elem : output_column_list_) {
    ZETASQL_RETURN_IF_ERROR(elem->SaveTo(
      file_descriptor_set_map, proto->add_output_column_list()));
  }
  proto->set_is_value_table(is_value_table_);
  if (query_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(query_->SaveTo(
        file_descriptor_set_map, proto->mutable_query()));
  }
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedExportDataStmt>> ResolvedExportDataStmt::RestoreFrom(
    const ResolvedExportDataStmtProto& proto,
    const ResolvedNode::RestoreParams& params) {
  std::vector<std::unique_ptr<const ResolvedOption>> option_list;
  for (const auto& elem : proto.option_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedOption> elem_restored,
                     ResolvedOption::RestoreFrom(elem, params));
    option_list.push_back(std::move(elem_restored));
  }
  std::vector<std::unique_ptr<const ResolvedOutputColumn>> output_column_list;
  for (const auto& elem : proto.output_column_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedOutputColumn> elem_restored,
                     ResolvedOutputColumn::RestoreFrom(elem, params));
    output_column_list.push_back(std::move(elem_restored));
  }
  bool is_value_table =
      proto.is_value_table();
  std::unique_ptr<const ResolvedScan> query;
  if (proto.
  has_query()) {
    ZETASQL_ASSIGN_OR_RETURN(query,
                     ResolvedScan::RestoreFrom(
                         proto.query(), params));
  }
  std::vector<std::unique_ptr<const ResolvedOption>> hint_list;
  for (const auto& elem : proto.parent().hint_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedOption> elem_restored,
                     ResolvedOption::RestoreFrom(elem, params));
    hint_list.push_back(std::move(elem_restored));
  }
  auto node = MakeResolvedExportDataStmt(
      std::move(option_list),
      std::move(output_column_list),
      std::move(is_value_table),
      std::move(query));

  node->set_hint_list(std::move(hint_list));
  return std::move(node);
}

void ResolvedExportDataStmt::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
  for (const auto& elem : option_list_) {
    child_nodes->emplace_back(elem.get());
  }
  for (const auto& elem : output_column_list_) {
    child_nodes->emplace_back(elem.get());
  }
  if (query_ != nullptr) {
    child_nodes->emplace_back(query_.get());
  }
}

void ResolvedExportDataStmt::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
  for (auto& elem : option_list_) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(&elem));
  }
  for (auto& elem : output_column_list_) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(&elem));
  }
  if (query_ != nullptr) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(
            &query_));
    static_assert(sizeof(query_) ==
                  sizeof(*(mutable_child_node_ptrs->back())),
                  "Incorrect casting of mutable child node");
  }
}

zetasql_base::Status ResolvedExportDataStmt::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedExportDataStmt(this);
}

zetasql_base::Status ResolvedExportDataStmt::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  for (const auto& elem : option_list_) {
    ZETASQL_RETURN_IF_ERROR(elem.get()->Accept(visitor));
  }
  for (const auto& elem : output_column_list_) {
    ZETASQL_RETURN_IF_ERROR(elem.get()->Accept(visitor));
  }
  if (query_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(query_.get()->Accept(visitor));
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedExportDataStmt::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  if (!option_list_.empty()) {
    fields->emplace_back("option_list", option_list_);
  }
  if (!output_column_list_.empty()) {
    fields->emplace_back("output_column_list", output_column_list_);
  }
  if (!IsDefaultValue(is_value_table_)) {
    fields->emplace_back("is_value_table", ToStringImpl(is_value_table_));
  }
  if (query_ != nullptr) {
    fields->emplace_back("query", query_.get());
  }
}

zetasql_base::Status ResolvedExportDataStmt::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0 &&
      !IsDefaultValue(option_list_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedExportDataStmt::option_list not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<1)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedExportDataStmt::output_column_list not accessed)";
  }
  if ((accessed_ & (1<<2)) == 0 &&
      !IsDefaultValue(is_value_table_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedExportDataStmt::is_value_table not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<3)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedExportDataStmt::query not accessed)";
  }
  if ((accessed_ & (1<<0)) != 0) {
    for (const auto& it : option_list_) ZETASQL_RETURN_IF_ERROR(it->CheckFieldsAccessed());
  }
  if ((accessed_ & (1<<1)) != 0) {
    for (const auto& it : output_column_list_) ZETASQL_RETURN_IF_ERROR(it->CheckFieldsAccessed());
  }
  if ((accessed_ & (1<<3)) != 0) {
    if (query_ != nullptr) {
      ZETASQL_RETURN_IF_ERROR(query_->CheckFieldsAccessed());
    }
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedExportDataStmt::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
  for (const auto& it : option_list_) it->ClearFieldsAccessed();
  for (const auto& it : output_column_list_) it->ClearFieldsAccessed();
  if (query_ != nullptr) query_->ClearFieldsAccessed();
}

const ResolvedNodeKind ResolvedDefineTableStmt::TYPE;

ResolvedDefineTableStmt::~ResolvedDefineTableStmt() {
}

zetasql_base::Status ResolvedDefineTableStmt::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedStatementProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_define_table_stmt_node());
}

zetasql_base::Status ResolvedDefineTableStmt::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedDefineTableStmtProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  for (const auto& elem : name_path_) {
    proto->add_name_path(elem);
  }
  for (const auto& elem : option_list_) {
    ZETASQL_RETURN_IF_ERROR(elem->SaveTo(
      file_descriptor_set_map, proto->add_option_list()));
  }
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedDefineTableStmt>> ResolvedDefineTableStmt::RestoreFrom(
    const ResolvedDefineTableStmtProto& proto,
    const ResolvedNode::RestoreParams& params) {
  std::vector<std::string> name_path;
  for (const auto& elem : proto.name_path()) {
    name_path.push_back(elem);
  }
  std::vector<std::unique_ptr<const ResolvedOption>> option_list;
  for (const auto& elem : proto.option_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedOption> elem_restored,
                     ResolvedOption::RestoreFrom(elem, params));
    option_list.push_back(std::move(elem_restored));
  }
  std::vector<std::unique_ptr<const ResolvedOption>> hint_list;
  for (const auto& elem : proto.parent().hint_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedOption> elem_restored,
                     ResolvedOption::RestoreFrom(elem, params));
    hint_list.push_back(std::move(elem_restored));
  }
  auto node = MakeResolvedDefineTableStmt(
      std::move(name_path),
      std::move(option_list));

  node->set_hint_list(std::move(hint_list));
  return std::move(node);
}

void ResolvedDefineTableStmt::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
  for (const auto& elem : option_list_) {
    child_nodes->emplace_back(elem.get());
  }
}

void ResolvedDefineTableStmt::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
  for (auto& elem : option_list_) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(&elem));
  }
}

zetasql_base::Status ResolvedDefineTableStmt::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedDefineTableStmt(this);
}

zetasql_base::Status ResolvedDefineTableStmt::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  for (const auto& elem : option_list_) {
    ZETASQL_RETURN_IF_ERROR(elem.get()->Accept(visitor));
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedDefineTableStmt::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  {
    fields->emplace_back("name_path", ToStringImpl(name_path_));
  }
  if (!option_list_.empty()) {
    fields->emplace_back("option_list", option_list_);
  }
}

zetasql_base::Status ResolvedDefineTableStmt::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedDefineTableStmt::name_path not accessed)";
  }
  if ((accessed_ & (1<<1)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedDefineTableStmt::option_list not accessed)";
  }
  if ((accessed_ & (1<<1)) != 0) {
    for (const auto& it : option_list_) ZETASQL_RETURN_IF_ERROR(it->CheckFieldsAccessed());
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedDefineTableStmt::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
  for (const auto& it : option_list_) it->ClearFieldsAccessed();
}

const ResolvedNodeKind ResolvedDescribeStmt::TYPE;

ResolvedDescribeStmt::~ResolvedDescribeStmt() {
}

zetasql_base::Status ResolvedDescribeStmt::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedStatementProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_describe_stmt_node());
}

zetasql_base::Status ResolvedDescribeStmt::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedDescribeStmtProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  proto->set_object_type(object_type_);
  for (const auto& elem : name_path_) {
    proto->add_name_path(elem);
  }
  for (const auto& elem : from_name_path_) {
    proto->add_from_name_path(elem);
  }
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedDescribeStmt>> ResolvedDescribeStmt::RestoreFrom(
    const ResolvedDescribeStmtProto& proto,
    const ResolvedNode::RestoreParams& params) {
  std::string object_type =
      proto.object_type();
  std::vector<std::string> name_path;
  for (const auto& elem : proto.name_path()) {
    name_path.push_back(elem);
  }
  std::vector<std::string> from_name_path;
  for (const auto& elem : proto.from_name_path()) {
    from_name_path.push_back(elem);
  }
  std::vector<std::unique_ptr<const ResolvedOption>> hint_list;
  for (const auto& elem : proto.parent().hint_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedOption> elem_restored,
                     ResolvedOption::RestoreFrom(elem, params));
    hint_list.push_back(std::move(elem_restored));
  }
  auto node = MakeResolvedDescribeStmt(
      std::move(object_type),
      std::move(name_path),
      std::move(from_name_path));

  node->set_hint_list(std::move(hint_list));
  return std::move(node);
}

void ResolvedDescribeStmt::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
}

void ResolvedDescribeStmt::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
}

zetasql_base::Status ResolvedDescribeStmt::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedDescribeStmt(this);
}

zetasql_base::Status ResolvedDescribeStmt::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  return ::zetasql_base::OkStatus();
}

void ResolvedDescribeStmt::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  {
    fields->emplace_back("object_type", ToStringImpl(object_type_));
  }
  {
    fields->emplace_back("name_path", ToStringImpl(name_path_));
  }
  if (!IsDefaultValue(from_name_path_)) {
    fields->emplace_back("from_name_path", ToStringImpl(from_name_path_));
  }
}

zetasql_base::Status ResolvedDescribeStmt::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedDescribeStmt::object_type not accessed)";
  }
  if ((accessed_ & (1<<1)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedDescribeStmt::name_path not accessed)";
  }
  if ((accessed_ & (1<<2)) == 0 &&
      !IsDefaultValue(from_name_path_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedDescribeStmt::from_name_path not accessed "
           "and has non-default value)";
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedDescribeStmt::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
}

const ResolvedNodeKind ResolvedShowStmt::TYPE;

ResolvedShowStmt::~ResolvedShowStmt() {
}

zetasql_base::Status ResolvedShowStmt::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedStatementProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_show_stmt_node());
}

zetasql_base::Status ResolvedShowStmt::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedShowStmtProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  proto->set_identifier(identifier_);
  for (const auto& elem : name_path_) {
    proto->add_name_path(elem);
  }
  if (like_expr_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(like_expr_->SaveTo(
        file_descriptor_set_map, proto->mutable_like_expr()));
  }
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedShowStmt>> ResolvedShowStmt::RestoreFrom(
    const ResolvedShowStmtProto& proto,
    const ResolvedNode::RestoreParams& params) {
  std::string identifier =
      proto.identifier();
  std::vector<std::string> name_path;
  for (const auto& elem : proto.name_path()) {
    name_path.push_back(elem);
  }
  std::unique_ptr<const ResolvedLiteral> like_expr;
  if (proto.
  has_like_expr()) {
    ZETASQL_ASSIGN_OR_RETURN(like_expr,
                     ResolvedLiteral::RestoreFrom(
                         proto.like_expr(), params));
  }
  std::vector<std::unique_ptr<const ResolvedOption>> hint_list;
  for (const auto& elem : proto.parent().hint_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedOption> elem_restored,
                     ResolvedOption::RestoreFrom(elem, params));
    hint_list.push_back(std::move(elem_restored));
  }
  auto node = MakeResolvedShowStmt(
      std::move(identifier),
      std::move(name_path),
      std::move(like_expr));

  node->set_hint_list(std::move(hint_list));
  return std::move(node);
}

void ResolvedShowStmt::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
  if (like_expr_ != nullptr) {
    child_nodes->emplace_back(like_expr_.get());
  }
}

void ResolvedShowStmt::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
  if (like_expr_ != nullptr) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(
            &like_expr_));
    static_assert(sizeof(like_expr_) ==
                  sizeof(*(mutable_child_node_ptrs->back())),
                  "Incorrect casting of mutable child node");
  }
}

zetasql_base::Status ResolvedShowStmt::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedShowStmt(this);
}

zetasql_base::Status ResolvedShowStmt::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  if (like_expr_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(like_expr_.get()->Accept(visitor));
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedShowStmt::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  {
    fields->emplace_back("identifier", ToStringImpl(identifier_));
  }
  if (!IsDefaultValue(name_path_)) {
    fields->emplace_back("name_path", ToStringImpl(name_path_));
  }
  if (like_expr_ != nullptr) {
    fields->emplace_back("like_expr", like_expr_.get());
  }
}

zetasql_base::Status ResolvedShowStmt::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedShowStmt::identifier not accessed)";
  }
  if ((accessed_ & (1<<1)) == 0 &&
      !IsDefaultValue(name_path_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedShowStmt::name_path not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<2)) == 0 &&
      !IsDefaultValue(like_expr_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedShowStmt::like_expr not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<2)) != 0) {
    if (like_expr_ != nullptr) {
      ZETASQL_RETURN_IF_ERROR(like_expr_->CheckFieldsAccessed());
    }
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedShowStmt::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
  if (like_expr_ != nullptr) like_expr_->ClearFieldsAccessed();
}

const ResolvedNodeKind ResolvedBeginStmt::TYPE;

const ResolvedBeginStmt::ReadWriteMode ResolvedBeginStmt::MODE_UNSPECIFIED;
const ResolvedBeginStmt::ReadWriteMode ResolvedBeginStmt::MODE_READ_ONLY;
const ResolvedBeginStmt::ReadWriteMode ResolvedBeginStmt::MODE_READ_WRITE;

ResolvedBeginStmt::~ResolvedBeginStmt() {
}

zetasql_base::Status ResolvedBeginStmt::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedStatementProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_begin_stmt_node());
}

zetasql_base::Status ResolvedBeginStmt::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedBeginStmtProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  proto->set_read_write_mode(read_write_mode_);
  for (const auto& elem : isolation_level_list_) {
    proto->add_isolation_level_list(elem);
  }
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedBeginStmt>> ResolvedBeginStmt::RestoreFrom(
    const ResolvedBeginStmtProto& proto,
    const ResolvedNode::RestoreParams& params) {
  ReadWriteMode read_write_mode =
      proto.read_write_mode();
  std::vector<std::string> isolation_level_list;
  for (const auto& elem : proto.isolation_level_list()) {
    isolation_level_list.push_back(elem);
  }
  std::vector<std::unique_ptr<const ResolvedOption>> hint_list;
  for (const auto& elem : proto.parent().hint_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedOption> elem_restored,
                     ResolvedOption::RestoreFrom(elem, params));
    hint_list.push_back(std::move(elem_restored));
  }
  auto node = MakeResolvedBeginStmt(
      std::move(read_write_mode),
      std::move(isolation_level_list));

  node->set_hint_list(std::move(hint_list));
  return std::move(node);
}

void ResolvedBeginStmt::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
}

void ResolvedBeginStmt::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
}

zetasql_base::Status ResolvedBeginStmt::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedBeginStmt(this);
}

zetasql_base::Status ResolvedBeginStmt::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  return ::zetasql_base::OkStatus();
}

void ResolvedBeginStmt::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  if (!IsDefaultValue(read_write_mode_)) {
    fields->emplace_back("read_write_mode", ToStringImpl(read_write_mode_));
  }
  if (!IsDefaultValue(isolation_level_list_)) {
    fields->emplace_back("isolation_level_list", ToStringImpl(isolation_level_list_));
  }
}

zetasql_base::Status ResolvedBeginStmt::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0 &&
      !IsDefaultValue(read_write_mode_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedBeginStmt::read_write_mode not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<1)) == 0 &&
      !IsDefaultValue(isolation_level_list_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedBeginStmt::isolation_level_list not accessed "
           "and has non-default value)";
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedBeginStmt::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
}

const ResolvedNodeKind ResolvedSetTransactionStmt::TYPE;

ResolvedSetTransactionStmt::~ResolvedSetTransactionStmt() {
}

zetasql_base::Status ResolvedSetTransactionStmt::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedStatementProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_set_transaction_stmt_node());
}

zetasql_base::Status ResolvedSetTransactionStmt::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedSetTransactionStmtProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  proto->set_read_write_mode(read_write_mode_);
  for (const auto& elem : isolation_level_list_) {
    proto->add_isolation_level_list(elem);
  }
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedSetTransactionStmt>> ResolvedSetTransactionStmt::RestoreFrom(
    const ResolvedSetTransactionStmtProto& proto,
    const ResolvedNode::RestoreParams& params) {
  ReadWriteMode read_write_mode =
      proto.read_write_mode();
  std::vector<std::string> isolation_level_list;
  for (const auto& elem : proto.isolation_level_list()) {
    isolation_level_list.push_back(elem);
  }
  std::vector<std::unique_ptr<const ResolvedOption>> hint_list;
  for (const auto& elem : proto.parent().hint_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedOption> elem_restored,
                     ResolvedOption::RestoreFrom(elem, params));
    hint_list.push_back(std::move(elem_restored));
  }
  auto node = MakeResolvedSetTransactionStmt(
      std::move(read_write_mode),
      std::move(isolation_level_list));

  node->set_hint_list(std::move(hint_list));
  return std::move(node);
}

void ResolvedSetTransactionStmt::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
}

void ResolvedSetTransactionStmt::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
}

zetasql_base::Status ResolvedSetTransactionStmt::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedSetTransactionStmt(this);
}

zetasql_base::Status ResolvedSetTransactionStmt::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  return ::zetasql_base::OkStatus();
}

void ResolvedSetTransactionStmt::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  if (!IsDefaultValue(read_write_mode_)) {
    fields->emplace_back("read_write_mode", ToStringImpl(read_write_mode_));
  }
  if (!IsDefaultValue(isolation_level_list_)) {
    fields->emplace_back("isolation_level_list", ToStringImpl(isolation_level_list_));
  }
}

zetasql_base::Status ResolvedSetTransactionStmt::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0 &&
      !IsDefaultValue(read_write_mode_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedSetTransactionStmt::read_write_mode not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<1)) == 0 &&
      !IsDefaultValue(isolation_level_list_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedSetTransactionStmt::isolation_level_list not accessed "
           "and has non-default value)";
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedSetTransactionStmt::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
}

const ResolvedNodeKind ResolvedCommitStmt::TYPE;

ResolvedCommitStmt::~ResolvedCommitStmt() {
}

zetasql_base::Status ResolvedCommitStmt::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedStatementProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_commit_stmt_node());
}

zetasql_base::Status ResolvedCommitStmt::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedCommitStmtProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedCommitStmt>> ResolvedCommitStmt::RestoreFrom(
    const ResolvedCommitStmtProto& proto,
    const ResolvedNode::RestoreParams& params) {
  std::vector<std::unique_ptr<const ResolvedOption>> hint_list;
  for (const auto& elem : proto.parent().hint_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedOption> elem_restored,
                     ResolvedOption::RestoreFrom(elem, params));
    hint_list.push_back(std::move(elem_restored));
  }
  auto node = MakeResolvedCommitStmt(
);

  node->set_hint_list(std::move(hint_list));
  return std::move(node);
}

zetasql_base::Status ResolvedCommitStmt::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedCommitStmt(this);
}

zetasql_base::Status ResolvedCommitStmt::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  return ::zetasql_base::OkStatus();
}

const ResolvedNodeKind ResolvedRollbackStmt::TYPE;

ResolvedRollbackStmt::~ResolvedRollbackStmt() {
}

zetasql_base::Status ResolvedRollbackStmt::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedStatementProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_rollback_stmt_node());
}

zetasql_base::Status ResolvedRollbackStmt::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedRollbackStmtProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedRollbackStmt>> ResolvedRollbackStmt::RestoreFrom(
    const ResolvedRollbackStmtProto& proto,
    const ResolvedNode::RestoreParams& params) {
  std::vector<std::unique_ptr<const ResolvedOption>> hint_list;
  for (const auto& elem : proto.parent().hint_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedOption> elem_restored,
                     ResolvedOption::RestoreFrom(elem, params));
    hint_list.push_back(std::move(elem_restored));
  }
  auto node = MakeResolvedRollbackStmt(
);

  node->set_hint_list(std::move(hint_list));
  return std::move(node);
}

zetasql_base::Status ResolvedRollbackStmt::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedRollbackStmt(this);
}

zetasql_base::Status ResolvedRollbackStmt::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  return ::zetasql_base::OkStatus();
}

const ResolvedNodeKind ResolvedStartBatchStmt::TYPE;

ResolvedStartBatchStmt::~ResolvedStartBatchStmt() {
}

zetasql_base::Status ResolvedStartBatchStmt::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedStatementProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_start_batch_stmt_node());
}

zetasql_base::Status ResolvedStartBatchStmt::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedStartBatchStmtProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  proto->set_batch_type(batch_type_);
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedStartBatchStmt>> ResolvedStartBatchStmt::RestoreFrom(
    const ResolvedStartBatchStmtProto& proto,
    const ResolvedNode::RestoreParams& params) {
  std::string batch_type =
      proto.batch_type();
  std::vector<std::unique_ptr<const ResolvedOption>> hint_list;
  for (const auto& elem : proto.parent().hint_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedOption> elem_restored,
                     ResolvedOption::RestoreFrom(elem, params));
    hint_list.push_back(std::move(elem_restored));
  }
  auto node = MakeResolvedStartBatchStmt(
      std::move(batch_type));

  node->set_hint_list(std::move(hint_list));
  return std::move(node);
}

void ResolvedStartBatchStmt::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
}

void ResolvedStartBatchStmt::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
}

zetasql_base::Status ResolvedStartBatchStmt::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedStartBatchStmt(this);
}

zetasql_base::Status ResolvedStartBatchStmt::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  return ::zetasql_base::OkStatus();
}

void ResolvedStartBatchStmt::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  if (!IsDefaultValue(batch_type_)) {
    fields->emplace_back("batch_type", ToStringImpl(batch_type_));
  }
}

zetasql_base::Status ResolvedStartBatchStmt::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0 &&
      !IsDefaultValue(batch_type_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedStartBatchStmt::batch_type not accessed "
           "and has non-default value)";
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedStartBatchStmt::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
}

const ResolvedNodeKind ResolvedRunBatchStmt::TYPE;

ResolvedRunBatchStmt::~ResolvedRunBatchStmt() {
}

zetasql_base::Status ResolvedRunBatchStmt::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedStatementProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_run_batch_stmt_node());
}

zetasql_base::Status ResolvedRunBatchStmt::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedRunBatchStmtProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedRunBatchStmt>> ResolvedRunBatchStmt::RestoreFrom(
    const ResolvedRunBatchStmtProto& proto,
    const ResolvedNode::RestoreParams& params) {
  std::vector<std::unique_ptr<const ResolvedOption>> hint_list;
  for (const auto& elem : proto.parent().hint_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedOption> elem_restored,
                     ResolvedOption::RestoreFrom(elem, params));
    hint_list.push_back(std::move(elem_restored));
  }
  auto node = MakeResolvedRunBatchStmt(
);

  node->set_hint_list(std::move(hint_list));
  return std::move(node);
}

zetasql_base::Status ResolvedRunBatchStmt::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedRunBatchStmt(this);
}

zetasql_base::Status ResolvedRunBatchStmt::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  return ::zetasql_base::OkStatus();
}

const ResolvedNodeKind ResolvedAbortBatchStmt::TYPE;

ResolvedAbortBatchStmt::~ResolvedAbortBatchStmt() {
}

zetasql_base::Status ResolvedAbortBatchStmt::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedStatementProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_abort_batch_stmt_node());
}

zetasql_base::Status ResolvedAbortBatchStmt::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedAbortBatchStmtProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedAbortBatchStmt>> ResolvedAbortBatchStmt::RestoreFrom(
    const ResolvedAbortBatchStmtProto& proto,
    const ResolvedNode::RestoreParams& params) {
  std::vector<std::unique_ptr<const ResolvedOption>> hint_list;
  for (const auto& elem : proto.parent().hint_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedOption> elem_restored,
                     ResolvedOption::RestoreFrom(elem, params));
    hint_list.push_back(std::move(elem_restored));
  }
  auto node = MakeResolvedAbortBatchStmt(
);

  node->set_hint_list(std::move(hint_list));
  return std::move(node);
}

zetasql_base::Status ResolvedAbortBatchStmt::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedAbortBatchStmt(this);
}

zetasql_base::Status ResolvedAbortBatchStmt::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  return ::zetasql_base::OkStatus();
}

const ResolvedNodeKind ResolvedDropStmt::TYPE;

ResolvedDropStmt::~ResolvedDropStmt() {
}

zetasql_base::Status ResolvedDropStmt::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedStatementProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_drop_stmt_node());
}

zetasql_base::Status ResolvedDropStmt::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedDropStmtProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  proto->set_object_type(object_type_);
  proto->set_is_if_exists(is_if_exists_);
  for (const auto& elem : name_path_) {
    proto->add_name_path(elem);
  }
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedDropStmt>> ResolvedDropStmt::RestoreFrom(
    const ResolvedDropStmtProto& proto,
    const ResolvedNode::RestoreParams& params) {
  std::string object_type =
      proto.object_type();
  bool is_if_exists =
      proto.is_if_exists();
  std::vector<std::string> name_path;
  for (const auto& elem : proto.name_path()) {
    name_path.push_back(elem);
  }
  std::vector<std::unique_ptr<const ResolvedOption>> hint_list;
  for (const auto& elem : proto.parent().hint_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedOption> elem_restored,
                     ResolvedOption::RestoreFrom(elem, params));
    hint_list.push_back(std::move(elem_restored));
  }
  auto node = MakeResolvedDropStmt(
      std::move(object_type),
      std::move(is_if_exists),
      std::move(name_path));

  node->set_hint_list(std::move(hint_list));
  return std::move(node);
}

void ResolvedDropStmt::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
}

void ResolvedDropStmt::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
}

zetasql_base::Status ResolvedDropStmt::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedDropStmt(this);
}

zetasql_base::Status ResolvedDropStmt::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  return ::zetasql_base::OkStatus();
}

void ResolvedDropStmt::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  {
    fields->emplace_back("object_type", ToStringImpl(object_type_));
  }
  {
    fields->emplace_back("is_if_exists", ToStringImpl(is_if_exists_));
  }
  {
    fields->emplace_back("name_path", ToStringImpl(name_path_));
  }
}

zetasql_base::Status ResolvedDropStmt::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedDropStmt::object_type not accessed)";
  }
  if ((accessed_ & (1<<1)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedDropStmt::is_if_exists not accessed)";
  }
  if ((accessed_ & (1<<2)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedDropStmt::name_path not accessed)";
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedDropStmt::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
}

const ResolvedNodeKind ResolvedDropMaterializedViewStmt::TYPE;

ResolvedDropMaterializedViewStmt::~ResolvedDropMaterializedViewStmt() {
}

zetasql_base::Status ResolvedDropMaterializedViewStmt::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedStatementProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_drop_materialized_view_stmt_node());
}

zetasql_base::Status ResolvedDropMaterializedViewStmt::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedDropMaterializedViewStmtProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  proto->set_is_if_exists(is_if_exists_);
  for (const auto& elem : name_path_) {
    proto->add_name_path(elem);
  }
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedDropMaterializedViewStmt>> ResolvedDropMaterializedViewStmt::RestoreFrom(
    const ResolvedDropMaterializedViewStmtProto& proto,
    const ResolvedNode::RestoreParams& params) {
  bool is_if_exists =
      proto.is_if_exists();
  std::vector<std::string> name_path;
  for (const auto& elem : proto.name_path()) {
    name_path.push_back(elem);
  }
  std::vector<std::unique_ptr<const ResolvedOption>> hint_list;
  for (const auto& elem : proto.parent().hint_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedOption> elem_restored,
                     ResolvedOption::RestoreFrom(elem, params));
    hint_list.push_back(std::move(elem_restored));
  }
  auto node = MakeResolvedDropMaterializedViewStmt(
      std::move(is_if_exists),
      std::move(name_path));

  node->set_hint_list(std::move(hint_list));
  return std::move(node);
}

void ResolvedDropMaterializedViewStmt::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
}

void ResolvedDropMaterializedViewStmt::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
}

zetasql_base::Status ResolvedDropMaterializedViewStmt::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedDropMaterializedViewStmt(this);
}

zetasql_base::Status ResolvedDropMaterializedViewStmt::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  return ::zetasql_base::OkStatus();
}

void ResolvedDropMaterializedViewStmt::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  {
    fields->emplace_back("is_if_exists", ToStringImpl(is_if_exists_));
  }
  {
    fields->emplace_back("name_path", ToStringImpl(name_path_));
  }
}

zetasql_base::Status ResolvedDropMaterializedViewStmt::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedDropMaterializedViewStmt::is_if_exists not accessed)";
  }
  if ((accessed_ & (1<<1)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedDropMaterializedViewStmt::name_path not accessed)";
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedDropMaterializedViewStmt::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
}

const ResolvedNodeKind ResolvedWithScan::TYPE;

ResolvedWithScan::~ResolvedWithScan() {
}

zetasql_base::Status ResolvedWithScan::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedScanProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_with_scan_node());
}

zetasql_base::Status ResolvedWithScan::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedWithScanProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  for (const auto& elem : with_entry_list_) {
    ZETASQL_RETURN_IF_ERROR(elem->SaveTo(
      file_descriptor_set_map, proto->add_with_entry_list()));
  }
  if (query_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(query_->SaveTo(
        file_descriptor_set_map, proto->mutable_query()));
  }
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedWithScan>> ResolvedWithScan::RestoreFrom(
    const ResolvedWithScanProto& proto,
    const ResolvedNode::RestoreParams& params) {
  std::vector<std::unique_ptr<const ResolvedWithEntry>> with_entry_list;
  for (const auto& elem : proto.with_entry_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedWithEntry> elem_restored,
                     ResolvedWithEntry::RestoreFrom(elem, params));
    with_entry_list.push_back(std::move(elem_restored));
  }
  std::unique_ptr<const ResolvedScan> query;
  if (proto.
  has_query()) {
    ZETASQL_ASSIGN_OR_RETURN(query,
                     ResolvedScan::RestoreFrom(
                         proto.query(), params));
  }
  std::vector<ResolvedColumn> column_list;
  for (const auto& elem : proto.parent().column_list()) {
    ZETASQL_ASSIGN_OR_RETURN(auto elem_restored, RestoreFromImpl(elem, params));
    column_list.push_back(std::move(elem_restored));
  }
  std::vector<std::unique_ptr<const ResolvedOption>> hint_list;
  for (const auto& elem : proto.parent().hint_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedOption> elem_restored,
                     ResolvedOption::RestoreFrom(elem, params));
    hint_list.push_back(std::move(elem_restored));
  }
  bool is_ordered =
      proto.parent().is_ordered();
  auto node = MakeResolvedWithScan(
      std::move(column_list),
      std::move(with_entry_list),
      std::move(query));

  node->set_hint_list(std::move(hint_list));
  node->set_is_ordered(std::move(is_ordered));
  return std::move(node);
}

void ResolvedWithScan::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
  for (const auto& elem : with_entry_list_) {
    child_nodes->emplace_back(elem.get());
  }
  if (query_ != nullptr) {
    child_nodes->emplace_back(query_.get());
  }
}

void ResolvedWithScan::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
  for (auto& elem : with_entry_list_) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(&elem));
  }
  if (query_ != nullptr) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(
            &query_));
    static_assert(sizeof(query_) ==
                  sizeof(*(mutable_child_node_ptrs->back())),
                  "Incorrect casting of mutable child node");
  }
}

zetasql_base::Status ResolvedWithScan::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedWithScan(this);
}

zetasql_base::Status ResolvedWithScan::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  for (const auto& elem : with_entry_list_) {
    ZETASQL_RETURN_IF_ERROR(elem.get()->Accept(visitor));
  }
  if (query_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(query_.get()->Accept(visitor));
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedWithScan::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  if (!with_entry_list_.empty()) {
    fields->emplace_back("with_entry_list", with_entry_list_);
  }
  if (query_ != nullptr) {
    fields->emplace_back("query", query_.get());
  }
}

zetasql_base::Status ResolvedWithScan::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedWithScan::with_entry_list not accessed)";
  }
  if ((accessed_ & (1<<1)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedWithScan::query not accessed)";
  }
  if ((accessed_ & (1<<0)) != 0) {
    for (const auto& it : with_entry_list_) ZETASQL_RETURN_IF_ERROR(it->CheckFieldsAccessed());
  }
  if ((accessed_ & (1<<1)) != 0) {
    if (query_ != nullptr) {
      ZETASQL_RETURN_IF_ERROR(query_->CheckFieldsAccessed());
    }
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedWithScan::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
  for (const auto& it : with_entry_list_) it->ClearFieldsAccessed();
  if (query_ != nullptr) query_->ClearFieldsAccessed();
}

const ResolvedNodeKind ResolvedWithEntry::TYPE;

ResolvedWithEntry::~ResolvedWithEntry() {
}

zetasql_base::Status ResolvedWithEntry::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedArgumentProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_with_entry_node());
}

zetasql_base::Status ResolvedWithEntry::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedWithEntryProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  proto->set_with_query_name(with_query_name_);
  if (with_subquery_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(with_subquery_->SaveTo(
        file_descriptor_set_map, proto->mutable_with_subquery()));
  }
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedWithEntry>> ResolvedWithEntry::RestoreFrom(
    const ResolvedWithEntryProto& proto,
    const ResolvedNode::RestoreParams& params) {
  std::string with_query_name =
      proto.with_query_name();
  std::unique_ptr<const ResolvedScan> with_subquery;
  if (proto.
  has_with_subquery()) {
    ZETASQL_ASSIGN_OR_RETURN(with_subquery,
                     ResolvedScan::RestoreFrom(
                         proto.with_subquery(), params));
  }
  auto node = MakeResolvedWithEntry(
      std::move(with_query_name),
      std::move(with_subquery));

  return std::move(node);
}

void ResolvedWithEntry::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
  if (with_subquery_ != nullptr) {
    child_nodes->emplace_back(with_subquery_.get());
  }
}

void ResolvedWithEntry::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
  if (with_subquery_ != nullptr) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(
            &with_subquery_));
    static_assert(sizeof(with_subquery_) ==
                  sizeof(*(mutable_child_node_ptrs->back())),
                  "Incorrect casting of mutable child node");
  }
}

zetasql_base::Status ResolvedWithEntry::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedWithEntry(this);
}

zetasql_base::Status ResolvedWithEntry::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  if (with_subquery_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(with_subquery_.get()->Accept(visitor));
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedWithEntry::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  {
    fields->emplace_back("with_query_name", ToStringImpl(with_query_name_));
  }
  if (with_subquery_ != nullptr) {
    fields->emplace_back("with_subquery", with_subquery_.get());
  }
}

zetasql_base::Status ResolvedWithEntry::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedWithEntry::with_query_name not accessed)";
  }
  if ((accessed_ & (1<<1)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedWithEntry::with_subquery not accessed)";
  }
  if ((accessed_ & (1<<1)) != 0) {
    if (with_subquery_ != nullptr) {
      ZETASQL_RETURN_IF_ERROR(with_subquery_->CheckFieldsAccessed());
    }
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedWithEntry::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
  if (with_subquery_ != nullptr) with_subquery_->ClearFieldsAccessed();
}

const ResolvedNodeKind ResolvedOption::TYPE;

ResolvedOption::~ResolvedOption() {
}

zetasql_base::Status ResolvedOption::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedArgumentProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_option_node());
}

zetasql_base::Status ResolvedOption::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedOptionProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  proto->set_qualifier(qualifier_);
  proto->set_name(name_);
  if (value_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(value_->SaveTo(
        file_descriptor_set_map, proto->mutable_value()));
  }
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedOption>> ResolvedOption::RestoreFrom(
    const ResolvedOptionProto& proto,
    const ResolvedNode::RestoreParams& params) {
  std::string qualifier =
      proto.qualifier();
  std::string name =
      proto.name();
  std::unique_ptr<const ResolvedExpr> value;
  if (proto.
  has_value()) {
    ZETASQL_ASSIGN_OR_RETURN(value,
                     ResolvedExpr::RestoreFrom(
                         proto.value(), params));
  }
  auto node = MakeResolvedOption(
      std::move(qualifier),
      std::move(name),
      std::move(value));

  return std::move(node);
}

void ResolvedOption::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
  if (value_ != nullptr) {
    child_nodes->emplace_back(value_.get());
  }
}

void ResolvedOption::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
  if (value_ != nullptr) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(
            &value_));
    static_assert(sizeof(value_) ==
                  sizeof(*(mutable_child_node_ptrs->back())),
                  "Incorrect casting of mutable child node");
  }
}

zetasql_base::Status ResolvedOption::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedOption(this);
}

zetasql_base::Status ResolvedOption::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  if (value_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(value_.get()->Accept(visitor));
  }
  return ::zetasql_base::OkStatus();
}

zetasql_base::Status ResolvedOption::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedOption::qualifier not accessed)";
  }
  if ((accessed_ & (1<<2)) != 0) {
    if (value_ != nullptr) {
      ZETASQL_RETURN_IF_ERROR(value_->CheckFieldsAccessed());
    }
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedOption::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
  if (value_ != nullptr) value_->ClearFieldsAccessed();
}

const ResolvedNodeKind ResolvedWindowPartitioning::TYPE;

ResolvedWindowPartitioning::~ResolvedWindowPartitioning() {
}

zetasql_base::Status ResolvedWindowPartitioning::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedArgumentProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_window_partitioning_node());
}

zetasql_base::Status ResolvedWindowPartitioning::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedWindowPartitioningProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  for (const auto& elem : partition_by_list_) {
    ZETASQL_RETURN_IF_ERROR(elem->SaveTo(
      file_descriptor_set_map, proto->add_partition_by_list()));
  }
  for (const auto& elem : hint_list_) {
    ZETASQL_RETURN_IF_ERROR(elem->SaveTo(
      file_descriptor_set_map, proto->add_hint_list()));
  }
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedWindowPartitioning>> ResolvedWindowPartitioning::RestoreFrom(
    const ResolvedWindowPartitioningProto& proto,
    const ResolvedNode::RestoreParams& params) {
  std::vector<std::unique_ptr<const ResolvedColumnRef>> partition_by_list;
  for (const auto& elem : proto.partition_by_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedColumnRef> elem_restored,
                     ResolvedColumnRef::RestoreFrom(elem, params));
    partition_by_list.push_back(std::move(elem_restored));
  }
  std::vector<std::unique_ptr<const ResolvedOption>> hint_list;
  for (const auto& elem : proto.hint_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedOption> elem_restored,
                     ResolvedOption::RestoreFrom(elem, params));
    hint_list.push_back(std::move(elem_restored));
  }
  auto node = MakeResolvedWindowPartitioning(
      std::move(partition_by_list));

  node->set_hint_list(std::move(hint_list));
  return std::move(node);
}

void ResolvedWindowPartitioning::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
  for (const auto& elem : partition_by_list_) {
    child_nodes->emplace_back(elem.get());
  }
  for (const auto& elem : hint_list_) {
    child_nodes->emplace_back(elem.get());
  }
}

void ResolvedWindowPartitioning::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
  for (auto& elem : partition_by_list_) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(&elem));
  }
  for (auto& elem : hint_list_) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(&elem));
  }
}

zetasql_base::Status ResolvedWindowPartitioning::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedWindowPartitioning(this);
}

zetasql_base::Status ResolvedWindowPartitioning::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  for (const auto& elem : partition_by_list_) {
    ZETASQL_RETURN_IF_ERROR(elem.get()->Accept(visitor));
  }
  for (const auto& elem : hint_list_) {
    ZETASQL_RETURN_IF_ERROR(elem.get()->Accept(visitor));
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedWindowPartitioning::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  if (!partition_by_list_.empty()) {
    fields->emplace_back("partition_by_list", partition_by_list_);
  }
  if (!hint_list_.empty()) {
    fields->emplace_back("hint_list", hint_list_);
  }
}

zetasql_base::Status ResolvedWindowPartitioning::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedWindowPartitioning::partition_by_list not accessed)";
  }
  if ((accessed_ & (1<<0)) != 0) {
    for (const auto& it : partition_by_list_) ZETASQL_RETURN_IF_ERROR(it->CheckFieldsAccessed());
  }
  if ((accessed_ & (1<<1)) != 0) {
    for (const auto& it : hint_list_) ZETASQL_RETURN_IF_ERROR(it->CheckFieldsAccessed());
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedWindowPartitioning::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
  for (const auto& it : partition_by_list_) it->ClearFieldsAccessed();
  for (const auto& it : hint_list_) it->ClearFieldsAccessed();
}

const ResolvedNodeKind ResolvedWindowOrdering::TYPE;

ResolvedWindowOrdering::~ResolvedWindowOrdering() {
}

zetasql_base::Status ResolvedWindowOrdering::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedArgumentProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_window_ordering_node());
}

zetasql_base::Status ResolvedWindowOrdering::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedWindowOrderingProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  for (const auto& elem : order_by_item_list_) {
    ZETASQL_RETURN_IF_ERROR(elem->SaveTo(
      file_descriptor_set_map, proto->add_order_by_item_list()));
  }
  for (const auto& elem : hint_list_) {
    ZETASQL_RETURN_IF_ERROR(elem->SaveTo(
      file_descriptor_set_map, proto->add_hint_list()));
  }
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedWindowOrdering>> ResolvedWindowOrdering::RestoreFrom(
    const ResolvedWindowOrderingProto& proto,
    const ResolvedNode::RestoreParams& params) {
  std::vector<std::unique_ptr<const ResolvedOrderByItem>> order_by_item_list;
  for (const auto& elem : proto.order_by_item_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedOrderByItem> elem_restored,
                     ResolvedOrderByItem::RestoreFrom(elem, params));
    order_by_item_list.push_back(std::move(elem_restored));
  }
  std::vector<std::unique_ptr<const ResolvedOption>> hint_list;
  for (const auto& elem : proto.hint_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedOption> elem_restored,
                     ResolvedOption::RestoreFrom(elem, params));
    hint_list.push_back(std::move(elem_restored));
  }
  auto node = MakeResolvedWindowOrdering(
      std::move(order_by_item_list));

  node->set_hint_list(std::move(hint_list));
  return std::move(node);
}

void ResolvedWindowOrdering::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
  for (const auto& elem : order_by_item_list_) {
    child_nodes->emplace_back(elem.get());
  }
  for (const auto& elem : hint_list_) {
    child_nodes->emplace_back(elem.get());
  }
}

void ResolvedWindowOrdering::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
  for (auto& elem : order_by_item_list_) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(&elem));
  }
  for (auto& elem : hint_list_) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(&elem));
  }
}

zetasql_base::Status ResolvedWindowOrdering::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedWindowOrdering(this);
}

zetasql_base::Status ResolvedWindowOrdering::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  for (const auto& elem : order_by_item_list_) {
    ZETASQL_RETURN_IF_ERROR(elem.get()->Accept(visitor));
  }
  for (const auto& elem : hint_list_) {
    ZETASQL_RETURN_IF_ERROR(elem.get()->Accept(visitor));
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedWindowOrdering::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  if (!order_by_item_list_.empty()) {
    fields->emplace_back("order_by_item_list", order_by_item_list_);
  }
  if (!hint_list_.empty()) {
    fields->emplace_back("hint_list", hint_list_);
  }
}

zetasql_base::Status ResolvedWindowOrdering::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedWindowOrdering::order_by_item_list not accessed)";
  }
  if ((accessed_ & (1<<0)) != 0) {
    for (const auto& it : order_by_item_list_) ZETASQL_RETURN_IF_ERROR(it->CheckFieldsAccessed());
  }
  if ((accessed_ & (1<<1)) != 0) {
    for (const auto& it : hint_list_) ZETASQL_RETURN_IF_ERROR(it->CheckFieldsAccessed());
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedWindowOrdering::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
  for (const auto& it : order_by_item_list_) it->ClearFieldsAccessed();
  for (const auto& it : hint_list_) it->ClearFieldsAccessed();
}

const ResolvedNodeKind ResolvedWindowFrame::TYPE;

const ResolvedWindowFrame::FrameUnit ResolvedWindowFrame::ROWS;
const ResolvedWindowFrame::FrameUnit ResolvedWindowFrame::RANGE;

ResolvedWindowFrame::~ResolvedWindowFrame() {
}

zetasql_base::Status ResolvedWindowFrame::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedArgumentProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_window_frame_node());
}

zetasql_base::Status ResolvedWindowFrame::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedWindowFrameProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  proto->set_frame_unit(frame_unit_);
  if (start_expr_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(start_expr_->SaveTo(
        file_descriptor_set_map, proto->mutable_start_expr()));
  }
  if (end_expr_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(end_expr_->SaveTo(
        file_descriptor_set_map, proto->mutable_end_expr()));
  }
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedWindowFrame>> ResolvedWindowFrame::RestoreFrom(
    const ResolvedWindowFrameProto& proto,
    const ResolvedNode::RestoreParams& params) {
  FrameUnit frame_unit =
      proto.frame_unit();
  std::unique_ptr<const ResolvedWindowFrameExpr> start_expr;
  if (proto.
  has_start_expr()) {
    ZETASQL_ASSIGN_OR_RETURN(start_expr,
                     ResolvedWindowFrameExpr::RestoreFrom(
                         proto.start_expr(), params));
  }
  std::unique_ptr<const ResolvedWindowFrameExpr> end_expr;
  if (proto.
  has_end_expr()) {
    ZETASQL_ASSIGN_OR_RETURN(end_expr,
                     ResolvedWindowFrameExpr::RestoreFrom(
                         proto.end_expr(), params));
  }
  auto node = MakeResolvedWindowFrame(
      std::move(frame_unit),
      std::move(start_expr),
      std::move(end_expr));

  return std::move(node);
}

void ResolvedWindowFrame::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
  if (start_expr_ != nullptr) {
    child_nodes->emplace_back(start_expr_.get());
  }
  if (end_expr_ != nullptr) {
    child_nodes->emplace_back(end_expr_.get());
  }
}

void ResolvedWindowFrame::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
  if (start_expr_ != nullptr) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(
            &start_expr_));
    static_assert(sizeof(start_expr_) ==
                  sizeof(*(mutable_child_node_ptrs->back())),
                  "Incorrect casting of mutable child node");
  }
  if (end_expr_ != nullptr) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(
            &end_expr_));
    static_assert(sizeof(end_expr_) ==
                  sizeof(*(mutable_child_node_ptrs->back())),
                  "Incorrect casting of mutable child node");
  }
}

zetasql_base::Status ResolvedWindowFrame::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedWindowFrame(this);
}

zetasql_base::Status ResolvedWindowFrame::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  if (start_expr_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(start_expr_.get()->Accept(visitor));
  }
  if (end_expr_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(end_expr_.get()->Accept(visitor));
  }
  return ::zetasql_base::OkStatus();
}

zetasql_base::Status ResolvedWindowFrame::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedWindowFrame::frame_unit not accessed)";
  }
  if ((accessed_ & (1<<1)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedWindowFrame::start_expr not accessed)";
  }
  if ((accessed_ & (1<<2)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedWindowFrame::end_expr not accessed)";
  }
  if ((accessed_ & (1<<1)) != 0) {
    if (start_expr_ != nullptr) {
      ZETASQL_RETURN_IF_ERROR(start_expr_->CheckFieldsAccessed());
    }
  }
  if ((accessed_ & (1<<2)) != 0) {
    if (end_expr_ != nullptr) {
      ZETASQL_RETURN_IF_ERROR(end_expr_->CheckFieldsAccessed());
    }
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedWindowFrame::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
  if (start_expr_ != nullptr) start_expr_->ClearFieldsAccessed();
  if (end_expr_ != nullptr) end_expr_->ClearFieldsAccessed();
}

const ResolvedNodeKind ResolvedAnalyticFunctionGroup::TYPE;

ResolvedAnalyticFunctionGroup::~ResolvedAnalyticFunctionGroup() {
}

zetasql_base::Status ResolvedAnalyticFunctionGroup::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedArgumentProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_analytic_function_group_node());
}

zetasql_base::Status ResolvedAnalyticFunctionGroup::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedAnalyticFunctionGroupProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  if (partition_by_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(partition_by_->SaveTo(
        file_descriptor_set_map, proto->mutable_partition_by()));
  }
  if (order_by_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(order_by_->SaveTo(
        file_descriptor_set_map, proto->mutable_order_by()));
  }
  for (const auto& elem : analytic_function_list_) {
    ZETASQL_RETURN_IF_ERROR(elem->SaveTo(
      file_descriptor_set_map, proto->add_analytic_function_list()));
  }
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedAnalyticFunctionGroup>> ResolvedAnalyticFunctionGroup::RestoreFrom(
    const ResolvedAnalyticFunctionGroupProto& proto,
    const ResolvedNode::RestoreParams& params) {
  std::unique_ptr<const ResolvedWindowPartitioning> partition_by;
  if (proto.
  has_partition_by()) {
    ZETASQL_ASSIGN_OR_RETURN(partition_by,
                     ResolvedWindowPartitioning::RestoreFrom(
                         proto.partition_by(), params));
  }
  std::unique_ptr<const ResolvedWindowOrdering> order_by;
  if (proto.
  has_order_by()) {
    ZETASQL_ASSIGN_OR_RETURN(order_by,
                     ResolvedWindowOrdering::RestoreFrom(
                         proto.order_by(), params));
  }
  std::vector<std::unique_ptr<const ResolvedComputedColumn>> analytic_function_list;
  for (const auto& elem : proto.analytic_function_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedComputedColumn> elem_restored,
                     ResolvedComputedColumn::RestoreFrom(elem, params));
    analytic_function_list.push_back(std::move(elem_restored));
  }
  auto node = MakeResolvedAnalyticFunctionGroup(
      std::move(partition_by),
      std::move(order_by),
      std::move(analytic_function_list));

  return std::move(node);
}

void ResolvedAnalyticFunctionGroup::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
  if (partition_by_ != nullptr) {
    child_nodes->emplace_back(partition_by_.get());
  }
  if (order_by_ != nullptr) {
    child_nodes->emplace_back(order_by_.get());
  }
  for (const auto& elem : analytic_function_list_) {
    child_nodes->emplace_back(elem.get());
  }
}

void ResolvedAnalyticFunctionGroup::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
  if (partition_by_ != nullptr) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(
            &partition_by_));
    static_assert(sizeof(partition_by_) ==
                  sizeof(*(mutable_child_node_ptrs->back())),
                  "Incorrect casting of mutable child node");
  }
  if (order_by_ != nullptr) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(
            &order_by_));
    static_assert(sizeof(order_by_) ==
                  sizeof(*(mutable_child_node_ptrs->back())),
                  "Incorrect casting of mutable child node");
  }
  for (auto& elem : analytic_function_list_) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(&elem));
  }
}

zetasql_base::Status ResolvedAnalyticFunctionGroup::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedAnalyticFunctionGroup(this);
}

zetasql_base::Status ResolvedAnalyticFunctionGroup::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  if (partition_by_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(partition_by_.get()->Accept(visitor));
  }
  if (order_by_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(order_by_.get()->Accept(visitor));
  }
  for (const auto& elem : analytic_function_list_) {
    ZETASQL_RETURN_IF_ERROR(elem.get()->Accept(visitor));
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedAnalyticFunctionGroup::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  if (partition_by_ != nullptr) {
    fields->emplace_back("partition_by", partition_by_.get());
  }
  if (order_by_ != nullptr) {
    fields->emplace_back("order_by", order_by_.get());
  }
  if (!analytic_function_list_.empty()) {
    fields->emplace_back("analytic_function_list", analytic_function_list_);
  }
}

zetasql_base::Status ResolvedAnalyticFunctionGroup::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedAnalyticFunctionGroup::partition_by not accessed)";
  }
  if ((accessed_ & (1<<1)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedAnalyticFunctionGroup::order_by not accessed)";
  }
  if ((accessed_ & (1<<2)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedAnalyticFunctionGroup::analytic_function_list not accessed)";
  }
  if ((accessed_ & (1<<0)) != 0) {
    if (partition_by_ != nullptr) {
      ZETASQL_RETURN_IF_ERROR(partition_by_->CheckFieldsAccessed());
    }
  }
  if ((accessed_ & (1<<1)) != 0) {
    if (order_by_ != nullptr) {
      ZETASQL_RETURN_IF_ERROR(order_by_->CheckFieldsAccessed());
    }
  }
  if ((accessed_ & (1<<2)) != 0) {
    for (const auto& it : analytic_function_list_) ZETASQL_RETURN_IF_ERROR(it->CheckFieldsAccessed());
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedAnalyticFunctionGroup::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
  if (partition_by_ != nullptr) partition_by_->ClearFieldsAccessed();
  if (order_by_ != nullptr) order_by_->ClearFieldsAccessed();
  for (const auto& it : analytic_function_list_) it->ClearFieldsAccessed();
}

const ResolvedNodeKind ResolvedWindowFrameExpr::TYPE;

const ResolvedWindowFrameExpr::BoundaryType ResolvedWindowFrameExpr::UNBOUNDED_PRECEDING;
const ResolvedWindowFrameExpr::BoundaryType ResolvedWindowFrameExpr::OFFSET_PRECEDING;
const ResolvedWindowFrameExpr::BoundaryType ResolvedWindowFrameExpr::CURRENT_ROW;
const ResolvedWindowFrameExpr::BoundaryType ResolvedWindowFrameExpr::OFFSET_FOLLOWING;
const ResolvedWindowFrameExpr::BoundaryType ResolvedWindowFrameExpr::UNBOUNDED_FOLLOWING;

ResolvedWindowFrameExpr::~ResolvedWindowFrameExpr() {
}

zetasql_base::Status ResolvedWindowFrameExpr::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedArgumentProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_window_frame_expr_node());
}

zetasql_base::Status ResolvedWindowFrameExpr::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedWindowFrameExprProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  proto->set_boundary_type(boundary_type_);
  if (expression_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(expression_->SaveTo(
        file_descriptor_set_map, proto->mutable_expression()));
  }
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedWindowFrameExpr>> ResolvedWindowFrameExpr::RestoreFrom(
    const ResolvedWindowFrameExprProto& proto,
    const ResolvedNode::RestoreParams& params) {
  BoundaryType boundary_type =
      proto.boundary_type();
  std::unique_ptr<const ResolvedExpr> expression;
  if (proto.
  has_expression()) {
    ZETASQL_ASSIGN_OR_RETURN(expression,
                     ResolvedExpr::RestoreFrom(
                         proto.expression(), params));
  }
  auto node = MakeResolvedWindowFrameExpr(
      std::move(boundary_type),
      std::move(expression));

  return std::move(node);
}

void ResolvedWindowFrameExpr::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
  if (expression_ != nullptr) {
    child_nodes->emplace_back(expression_.get());
  }
}

void ResolvedWindowFrameExpr::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
  if (expression_ != nullptr) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(
            &expression_));
    static_assert(sizeof(expression_) ==
                  sizeof(*(mutable_child_node_ptrs->back())),
                  "Incorrect casting of mutable child node");
  }
}

zetasql_base::Status ResolvedWindowFrameExpr::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedWindowFrameExpr(this);
}

zetasql_base::Status ResolvedWindowFrameExpr::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  if (expression_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(expression_.get()->Accept(visitor));
  }
  return ::zetasql_base::OkStatus();
}

zetasql_base::Status ResolvedWindowFrameExpr::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedWindowFrameExpr::boundary_type not accessed)";
  }
  if ((accessed_ & (1<<1)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedWindowFrameExpr::expression not accessed)";
  }
  if ((accessed_ & (1<<1)) != 0) {
    if (expression_ != nullptr) {
      ZETASQL_RETURN_IF_ERROR(expression_->CheckFieldsAccessed());
    }
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedWindowFrameExpr::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
  if (expression_ != nullptr) expression_->ClearFieldsAccessed();
}

const ResolvedNodeKind ResolvedDMLValue::TYPE;

ResolvedDMLValue::~ResolvedDMLValue() {
}

zetasql_base::Status ResolvedDMLValue::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedArgumentProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_dmlvalue_node());
}

zetasql_base::Status ResolvedDMLValue::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedDMLValueProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  if (value_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(value_->SaveTo(
        file_descriptor_set_map, proto->mutable_value()));
  }
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedDMLValue>> ResolvedDMLValue::RestoreFrom(
    const ResolvedDMLValueProto& proto,
    const ResolvedNode::RestoreParams& params) {
  std::unique_ptr<const ResolvedExpr> value;
  if (proto.
  has_value()) {
    ZETASQL_ASSIGN_OR_RETURN(value,
                     ResolvedExpr::RestoreFrom(
                         proto.value(), params));
  }
  auto node = MakeResolvedDMLValue(
      std::move(value));

  return std::move(node);
}

void ResolvedDMLValue::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
  if (value_ != nullptr) {
    child_nodes->emplace_back(value_.get());
  }
}

void ResolvedDMLValue::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
  if (value_ != nullptr) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(
            &value_));
    static_assert(sizeof(value_) ==
                  sizeof(*(mutable_child_node_ptrs->back())),
                  "Incorrect casting of mutable child node");
  }
}

zetasql_base::Status ResolvedDMLValue::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedDMLValue(this);
}

zetasql_base::Status ResolvedDMLValue::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  if (value_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(value_.get()->Accept(visitor));
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedDMLValue::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  if (value_ != nullptr) {
    fields->emplace_back("value", value_.get());
  }
}

zetasql_base::Status ResolvedDMLValue::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedDMLValue::value not accessed)";
  }
  if ((accessed_ & (1<<0)) != 0) {
    if (value_ != nullptr) {
      ZETASQL_RETURN_IF_ERROR(value_->CheckFieldsAccessed());
    }
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedDMLValue::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
  if (value_ != nullptr) value_->ClearFieldsAccessed();
}

const ResolvedNodeKind ResolvedDMLDefault::TYPE;

ResolvedDMLDefault::~ResolvedDMLDefault() {
}

zetasql_base::Status ResolvedDMLDefault::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedExprProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_dmldefault_node());
}

zetasql_base::Status ResolvedDMLDefault::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedDMLDefaultProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedDMLDefault>> ResolvedDMLDefault::RestoreFrom(
    const ResolvedDMLDefaultProto& proto,
    const ResolvedNode::RestoreParams& params) {
  ZETASQL_ASSIGN_OR_RETURN(const Type* type,
                   RestoreFromImpl(proto.parent().type(),
                                   params));
  auto node = MakeResolvedDMLDefault(
      std::move(type));

  return std::move(node);
}

zetasql_base::Status ResolvedDMLDefault::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedDMLDefault(this);
}

zetasql_base::Status ResolvedDMLDefault::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  return ::zetasql_base::OkStatus();
}

const ResolvedNodeKind ResolvedAssertStmt::TYPE;

ResolvedAssertStmt::~ResolvedAssertStmt() {
}

zetasql_base::Status ResolvedAssertStmt::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedStatementProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_assert_stmt_node());
}

zetasql_base::Status ResolvedAssertStmt::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedAssertStmtProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  if (expression_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(expression_->SaveTo(
        file_descriptor_set_map, proto->mutable_expression()));
  }
  proto->set_description(description_);
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedAssertStmt>> ResolvedAssertStmt::RestoreFrom(
    const ResolvedAssertStmtProto& proto,
    const ResolvedNode::RestoreParams& params) {
  std::unique_ptr<const ResolvedExpr> expression;
  if (proto.
  has_expression()) {
    ZETASQL_ASSIGN_OR_RETURN(expression,
                     ResolvedExpr::RestoreFrom(
                         proto.expression(), params));
  }
  std::string description =
      proto.description();
  std::vector<std::unique_ptr<const ResolvedOption>> hint_list;
  for (const auto& elem : proto.parent().hint_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedOption> elem_restored,
                     ResolvedOption::RestoreFrom(elem, params));
    hint_list.push_back(std::move(elem_restored));
  }
  auto node = MakeResolvedAssertStmt(
      std::move(expression),
      std::move(description));

  node->set_hint_list(std::move(hint_list));
  return std::move(node);
}

void ResolvedAssertStmt::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
  if (expression_ != nullptr) {
    child_nodes->emplace_back(expression_.get());
  }
}

void ResolvedAssertStmt::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
  if (expression_ != nullptr) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(
            &expression_));
    static_assert(sizeof(expression_) ==
                  sizeof(*(mutable_child_node_ptrs->back())),
                  "Incorrect casting of mutable child node");
  }
}

zetasql_base::Status ResolvedAssertStmt::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedAssertStmt(this);
}

zetasql_base::Status ResolvedAssertStmt::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  if (expression_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(expression_.get()->Accept(visitor));
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedAssertStmt::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  if (expression_ != nullptr) {
    fields->emplace_back("expression", expression_.get());
  }
  if (!IsDefaultValue(description_)) {
    fields->emplace_back("description", ToStringImpl(description_));
  }
}

zetasql_base::Status ResolvedAssertStmt::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedAssertStmt::expression not accessed)";
  }
  if ((accessed_ & (1<<1)) == 0 &&
      !IsDefaultValue(description_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedAssertStmt::description not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<0)) != 0) {
    if (expression_ != nullptr) {
      ZETASQL_RETURN_IF_ERROR(expression_->CheckFieldsAccessed());
    }
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedAssertStmt::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
  if (expression_ != nullptr) expression_->ClearFieldsAccessed();
}

const ResolvedNodeKind ResolvedAssertRowsModified::TYPE;

ResolvedAssertRowsModified::~ResolvedAssertRowsModified() {
}

zetasql_base::Status ResolvedAssertRowsModified::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedArgumentProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_assert_rows_modified_node());
}

zetasql_base::Status ResolvedAssertRowsModified::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedAssertRowsModifiedProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  if (rows_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(rows_->SaveTo(
        file_descriptor_set_map, proto->mutable_rows()));
  }
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedAssertRowsModified>> ResolvedAssertRowsModified::RestoreFrom(
    const ResolvedAssertRowsModifiedProto& proto,
    const ResolvedNode::RestoreParams& params) {
  std::unique_ptr<const ResolvedExpr> rows;
  if (proto.
  has_rows()) {
    ZETASQL_ASSIGN_OR_RETURN(rows,
                     ResolvedExpr::RestoreFrom(
                         proto.rows(), params));
  }
  auto node = MakeResolvedAssertRowsModified(
      std::move(rows));

  return std::move(node);
}

void ResolvedAssertRowsModified::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
  if (rows_ != nullptr) {
    child_nodes->emplace_back(rows_.get());
  }
}

void ResolvedAssertRowsModified::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
  if (rows_ != nullptr) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(
            &rows_));
    static_assert(sizeof(rows_) ==
                  sizeof(*(mutable_child_node_ptrs->back())),
                  "Incorrect casting of mutable child node");
  }
}

zetasql_base::Status ResolvedAssertRowsModified::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedAssertRowsModified(this);
}

zetasql_base::Status ResolvedAssertRowsModified::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  if (rows_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(rows_.get()->Accept(visitor));
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedAssertRowsModified::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  if (rows_ != nullptr) {
    fields->emplace_back("rows", rows_.get());
  }
}

zetasql_base::Status ResolvedAssertRowsModified::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedAssertRowsModified::rows not accessed)";
  }
  if ((accessed_ & (1<<0)) != 0) {
    if (rows_ != nullptr) {
      ZETASQL_RETURN_IF_ERROR(rows_->CheckFieldsAccessed());
    }
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedAssertRowsModified::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
  if (rows_ != nullptr) rows_->ClearFieldsAccessed();
}

const ResolvedNodeKind ResolvedInsertRow::TYPE;

ResolvedInsertRow::~ResolvedInsertRow() {
}

zetasql_base::Status ResolvedInsertRow::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedArgumentProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_insert_row_node());
}

zetasql_base::Status ResolvedInsertRow::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedInsertRowProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  for (const auto& elem : value_list_) {
    ZETASQL_RETURN_IF_ERROR(elem->SaveTo(
      file_descriptor_set_map, proto->add_value_list()));
  }
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedInsertRow>> ResolvedInsertRow::RestoreFrom(
    const ResolvedInsertRowProto& proto,
    const ResolvedNode::RestoreParams& params) {
  std::vector<std::unique_ptr<const ResolvedDMLValue>> value_list;
  for (const auto& elem : proto.value_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedDMLValue> elem_restored,
                     ResolvedDMLValue::RestoreFrom(elem, params));
    value_list.push_back(std::move(elem_restored));
  }
  auto node = MakeResolvedInsertRow(
      std::move(value_list));

  return std::move(node);
}

void ResolvedInsertRow::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
  for (const auto& elem : value_list_) {
    child_nodes->emplace_back(elem.get());
  }
}

void ResolvedInsertRow::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
  for (auto& elem : value_list_) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(&elem));
  }
}

zetasql_base::Status ResolvedInsertRow::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedInsertRow(this);
}

zetasql_base::Status ResolvedInsertRow::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  for (const auto& elem : value_list_) {
    ZETASQL_RETURN_IF_ERROR(elem.get()->Accept(visitor));
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedInsertRow::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  if (!value_list_.empty()) {
    fields->emplace_back("value_list", value_list_);
  }
}

zetasql_base::Status ResolvedInsertRow::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedInsertRow::value_list not accessed)";
  }
  if ((accessed_ & (1<<0)) != 0) {
    for (const auto& it : value_list_) ZETASQL_RETURN_IF_ERROR(it->CheckFieldsAccessed());
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedInsertRow::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
  for (const auto& it : value_list_) it->ClearFieldsAccessed();
}

const ResolvedNodeKind ResolvedInsertStmt::TYPE;

const ResolvedInsertStmt::InsertMode ResolvedInsertStmt::OR_ERROR;
const ResolvedInsertStmt::InsertMode ResolvedInsertStmt::OR_IGNORE;
const ResolvedInsertStmt::InsertMode ResolvedInsertStmt::OR_REPLACE;
const ResolvedInsertStmt::InsertMode ResolvedInsertStmt::OR_UPDATE;

ResolvedInsertStmt::~ResolvedInsertStmt() {
}

zetasql_base::Status ResolvedInsertStmt::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedStatementProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_insert_stmt_node());
}

zetasql_base::Status ResolvedInsertStmt::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedInsertStmtProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  if (table_scan_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(table_scan_->SaveTo(
        file_descriptor_set_map, proto->mutable_table_scan()));
  }
  proto->set_insert_mode(insert_mode_);
  if (assert_rows_modified_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(assert_rows_modified_->SaveTo(
        file_descriptor_set_map, proto->mutable_assert_rows_modified()));
  }
  for (const auto& elem : insert_column_list_) {
    ZETASQL_RETURN_IF_ERROR(SaveToImpl(
        elem, file_descriptor_set_map, proto->add_insert_column_list()));
  }
  for (const auto& elem : query_parameter_list_) {
    ZETASQL_RETURN_IF_ERROR(elem->SaveTo(
      file_descriptor_set_map, proto->add_query_parameter_list()));
  }
  if (query_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(query_->SaveTo(
        file_descriptor_set_map, proto->mutable_query()));
  }
  for (const auto& elem : query_output_column_list_) {
    ZETASQL_RETURN_IF_ERROR(SaveToImpl(
        elem, file_descriptor_set_map, proto->add_query_output_column_list()));
  }
  for (const auto& elem : row_list_) {
    ZETASQL_RETURN_IF_ERROR(elem->SaveTo(
      file_descriptor_set_map, proto->add_row_list()));
  }
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedInsertStmt>> ResolvedInsertStmt::RestoreFrom(
    const ResolvedInsertStmtProto& proto,
    const ResolvedNode::RestoreParams& params) {
  std::unique_ptr<const ResolvedTableScan> table_scan;
  if (proto.
  has_table_scan()) {
    ZETASQL_ASSIGN_OR_RETURN(table_scan,
                     ResolvedTableScan::RestoreFrom(
                         proto.table_scan(), params));
  }
  InsertMode insert_mode =
      proto.insert_mode();
  std::unique_ptr<const ResolvedAssertRowsModified> assert_rows_modified;
  if (proto.
  has_assert_rows_modified()) {
    ZETASQL_ASSIGN_OR_RETURN(assert_rows_modified,
                     ResolvedAssertRowsModified::RestoreFrom(
                         proto.assert_rows_modified(), params));
  }
  std::vector<ResolvedColumn> insert_column_list;
  for (const auto& elem : proto.insert_column_list()) {
    ZETASQL_ASSIGN_OR_RETURN(auto elem_restored, RestoreFromImpl(elem, params));
    insert_column_list.push_back(std::move(elem_restored));
  }
  std::vector<std::unique_ptr<const ResolvedColumnRef>> query_parameter_list;
  for (const auto& elem : proto.query_parameter_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedColumnRef> elem_restored,
                     ResolvedColumnRef::RestoreFrom(elem, params));
    query_parameter_list.push_back(std::move(elem_restored));
  }
  std::unique_ptr<const ResolvedScan> query;
  if (proto.
  has_query()) {
    ZETASQL_ASSIGN_OR_RETURN(query,
                     ResolvedScan::RestoreFrom(
                         proto.query(), params));
  }
  std::vector<ResolvedColumn> query_output_column_list;
  for (const auto& elem : proto.query_output_column_list()) {
    ZETASQL_ASSIGN_OR_RETURN(auto elem_restored, RestoreFromImpl(elem, params));
    query_output_column_list.push_back(std::move(elem_restored));
  }
  std::vector<std::unique_ptr<const ResolvedInsertRow>> row_list;
  for (const auto& elem : proto.row_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedInsertRow> elem_restored,
                     ResolvedInsertRow::RestoreFrom(elem, params));
    row_list.push_back(std::move(elem_restored));
  }
  std::vector<std::unique_ptr<const ResolvedOption>> hint_list;
  for (const auto& elem : proto.parent().hint_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedOption> elem_restored,
                     ResolvedOption::RestoreFrom(elem, params));
    hint_list.push_back(std::move(elem_restored));
  }
  auto node = MakeResolvedInsertStmt(
      std::move(table_scan),
      std::move(insert_mode),
      std::move(assert_rows_modified),
      std::move(insert_column_list),
      std::move(query_parameter_list),
      std::move(query),
      std::move(query_output_column_list),
      std::move(row_list));

  node->set_hint_list(std::move(hint_list));
  return std::move(node);
}

void ResolvedInsertStmt::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
  if (table_scan_ != nullptr) {
    child_nodes->emplace_back(table_scan_.get());
  }
  if (assert_rows_modified_ != nullptr) {
    child_nodes->emplace_back(assert_rows_modified_.get());
  }
  for (const auto& elem : query_parameter_list_) {
    child_nodes->emplace_back(elem.get());
  }
  if (query_ != nullptr) {
    child_nodes->emplace_back(query_.get());
  }
  for (const auto& elem : row_list_) {
    child_nodes->emplace_back(elem.get());
  }
}

void ResolvedInsertStmt::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
  if (table_scan_ != nullptr) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(
            &table_scan_));
    static_assert(sizeof(table_scan_) ==
                  sizeof(*(mutable_child_node_ptrs->back())),
                  "Incorrect casting of mutable child node");
  }
  if (assert_rows_modified_ != nullptr) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(
            &assert_rows_modified_));
    static_assert(sizeof(assert_rows_modified_) ==
                  sizeof(*(mutable_child_node_ptrs->back())),
                  "Incorrect casting of mutable child node");
  }
  for (auto& elem : query_parameter_list_) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(&elem));
  }
  if (query_ != nullptr) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(
            &query_));
    static_assert(sizeof(query_) ==
                  sizeof(*(mutable_child_node_ptrs->back())),
                  "Incorrect casting of mutable child node");
  }
  for (auto& elem : row_list_) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(&elem));
  }
}

zetasql_base::Status ResolvedInsertStmt::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedInsertStmt(this);
}

zetasql_base::Status ResolvedInsertStmt::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  if (table_scan_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(table_scan_.get()->Accept(visitor));
  }
  if (assert_rows_modified_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(assert_rows_modified_.get()->Accept(visitor));
  }
  for (const auto& elem : query_parameter_list_) {
    ZETASQL_RETURN_IF_ERROR(elem.get()->Accept(visitor));
  }
  if (query_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(query_.get()->Accept(visitor));
  }
  for (const auto& elem : row_list_) {
    ZETASQL_RETURN_IF_ERROR(elem.get()->Accept(visitor));
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedInsertStmt::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  if (table_scan_ != nullptr) {
    fields->emplace_back("table_scan", table_scan_.get());
  }
  if (!IsDefaultValue(insert_mode_)) {
    fields->emplace_back("insert_mode", ToStringImpl(insert_mode_));
  }
  if (assert_rows_modified_ != nullptr) {
    fields->emplace_back("assert_rows_modified", assert_rows_modified_.get());
  }
  if (!IsDefaultValue(insert_column_list_)) {
    fields->emplace_back("insert_column_list", ToStringImpl(insert_column_list_));
  }
  if (!query_parameter_list_.empty()) {
    fields->emplace_back("query_parameter_list", query_parameter_list_);
  }
  if (query_ != nullptr) {
    fields->emplace_back("query", query_.get());
  }
  if (!IsDefaultValue(query_output_column_list_)) {
    fields->emplace_back("query_output_column_list", ToStringImpl(query_output_column_list_));
  }
  if (!row_list_.empty()) {
    fields->emplace_back("row_list", row_list_);
  }
}

zetasql_base::Status ResolvedInsertStmt::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0 &&
      !IsDefaultValue(table_scan_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedInsertStmt::table_scan not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<1)) == 0 &&
      !IsDefaultValue(insert_mode_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedInsertStmt::insert_mode not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<2)) == 0 &&
      !IsDefaultValue(assert_rows_modified_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedInsertStmt::assert_rows_modified not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<3)) == 0 &&
      !IsDefaultValue(insert_column_list_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedInsertStmt::insert_column_list not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<4)) == 0 &&
      !IsDefaultValue(query_parameter_list_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedInsertStmt::query_parameter_list not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<5)) == 0 &&
      !IsDefaultValue(query_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedInsertStmt::query not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<6)) == 0 &&
      !IsDefaultValue(query_output_column_list_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedInsertStmt::query_output_column_list not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<7)) == 0 &&
      !IsDefaultValue(row_list_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedInsertStmt::row_list not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<0)) != 0) {
    if (table_scan_ != nullptr) {
      ZETASQL_RETURN_IF_ERROR(table_scan_->CheckFieldsAccessed());
    }
  }
  if ((accessed_ & (1<<2)) != 0) {
    if (assert_rows_modified_ != nullptr) {
      ZETASQL_RETURN_IF_ERROR(assert_rows_modified_->CheckFieldsAccessed());
    }
  }
  if ((accessed_ & (1<<4)) != 0) {
    for (const auto& it : query_parameter_list_) ZETASQL_RETURN_IF_ERROR(it->CheckFieldsAccessed());
  }
  if ((accessed_ & (1<<5)) != 0) {
    if (query_ != nullptr) {
      ZETASQL_RETURN_IF_ERROR(query_->CheckFieldsAccessed());
    }
  }
  if ((accessed_ & (1<<7)) != 0) {
    for (const auto& it : row_list_) ZETASQL_RETURN_IF_ERROR(it->CheckFieldsAccessed());
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedInsertStmt::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
  if (table_scan_ != nullptr) table_scan_->ClearFieldsAccessed();
  if (assert_rows_modified_ != nullptr) assert_rows_modified_->ClearFieldsAccessed();
  for (const auto& it : query_parameter_list_) it->ClearFieldsAccessed();
  if (query_ != nullptr) query_->ClearFieldsAccessed();
  for (const auto& it : row_list_) it->ClearFieldsAccessed();
}

const ResolvedNodeKind ResolvedDeleteStmt::TYPE;

ResolvedDeleteStmt::~ResolvedDeleteStmt() {
}

zetasql_base::Status ResolvedDeleteStmt::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedStatementProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_delete_stmt_node());
}

zetasql_base::Status ResolvedDeleteStmt::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedDeleteStmtProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  if (table_scan_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(table_scan_->SaveTo(
        file_descriptor_set_map, proto->mutable_table_scan()));
  }
  if (assert_rows_modified_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(assert_rows_modified_->SaveTo(
        file_descriptor_set_map, proto->mutable_assert_rows_modified()));
  }
  if (array_offset_column_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(array_offset_column_->SaveTo(
        file_descriptor_set_map, proto->mutable_array_offset_column()));
  }
  if (where_expr_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(where_expr_->SaveTo(
        file_descriptor_set_map, proto->mutable_where_expr()));
  }
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedDeleteStmt>> ResolvedDeleteStmt::RestoreFrom(
    const ResolvedDeleteStmtProto& proto,
    const ResolvedNode::RestoreParams& params) {
  std::unique_ptr<const ResolvedTableScan> table_scan;
  if (proto.
  has_table_scan()) {
    ZETASQL_ASSIGN_OR_RETURN(table_scan,
                     ResolvedTableScan::RestoreFrom(
                         proto.table_scan(), params));
  }
  std::unique_ptr<const ResolvedAssertRowsModified> assert_rows_modified;
  if (proto.
  has_assert_rows_modified()) {
    ZETASQL_ASSIGN_OR_RETURN(assert_rows_modified,
                     ResolvedAssertRowsModified::RestoreFrom(
                         proto.assert_rows_modified(), params));
  }
  std::unique_ptr<const ResolvedColumnHolder> array_offset_column;
  if (proto.
  has_array_offset_column()) {
    ZETASQL_ASSIGN_OR_RETURN(array_offset_column,
                     ResolvedColumnHolder::RestoreFrom(
                         proto.array_offset_column(), params));
  }
  std::unique_ptr<const ResolvedExpr> where_expr;
  if (proto.
  has_where_expr()) {
    ZETASQL_ASSIGN_OR_RETURN(where_expr,
                     ResolvedExpr::RestoreFrom(
                         proto.where_expr(), params));
  }
  std::vector<std::unique_ptr<const ResolvedOption>> hint_list;
  for (const auto& elem : proto.parent().hint_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedOption> elem_restored,
                     ResolvedOption::RestoreFrom(elem, params));
    hint_list.push_back(std::move(elem_restored));
  }
  auto node = MakeResolvedDeleteStmt(
      std::move(table_scan),
      std::move(assert_rows_modified),
      std::move(array_offset_column),
      std::move(where_expr));

  node->set_hint_list(std::move(hint_list));
  return std::move(node);
}

void ResolvedDeleteStmt::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
  if (table_scan_ != nullptr) {
    child_nodes->emplace_back(table_scan_.get());
  }
  if (assert_rows_modified_ != nullptr) {
    child_nodes->emplace_back(assert_rows_modified_.get());
  }
  if (array_offset_column_ != nullptr) {
    child_nodes->emplace_back(array_offset_column_.get());
  }
  if (where_expr_ != nullptr) {
    child_nodes->emplace_back(where_expr_.get());
  }
}

void ResolvedDeleteStmt::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
  if (table_scan_ != nullptr) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(
            &table_scan_));
    static_assert(sizeof(table_scan_) ==
                  sizeof(*(mutable_child_node_ptrs->back())),
                  "Incorrect casting of mutable child node");
  }
  if (assert_rows_modified_ != nullptr) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(
            &assert_rows_modified_));
    static_assert(sizeof(assert_rows_modified_) ==
                  sizeof(*(mutable_child_node_ptrs->back())),
                  "Incorrect casting of mutable child node");
  }
  if (array_offset_column_ != nullptr) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(
            &array_offset_column_));
    static_assert(sizeof(array_offset_column_) ==
                  sizeof(*(mutable_child_node_ptrs->back())),
                  "Incorrect casting of mutable child node");
  }
  if (where_expr_ != nullptr) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(
            &where_expr_));
    static_assert(sizeof(where_expr_) ==
                  sizeof(*(mutable_child_node_ptrs->back())),
                  "Incorrect casting of mutable child node");
  }
}

zetasql_base::Status ResolvedDeleteStmt::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedDeleteStmt(this);
}

zetasql_base::Status ResolvedDeleteStmt::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  if (table_scan_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(table_scan_.get()->Accept(visitor));
  }
  if (assert_rows_modified_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(assert_rows_modified_.get()->Accept(visitor));
  }
  if (array_offset_column_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(array_offset_column_.get()->Accept(visitor));
  }
  if (where_expr_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(where_expr_.get()->Accept(visitor));
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedDeleteStmt::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  if (table_scan_ != nullptr) {
    fields->emplace_back("table_scan", table_scan_.get());
  }
  if (assert_rows_modified_ != nullptr) {
    fields->emplace_back("assert_rows_modified", assert_rows_modified_.get());
  }
  if (array_offset_column_ != nullptr) {
    fields->emplace_back("array_offset_column", array_offset_column_.get());
  }
  if (where_expr_ != nullptr) {
    fields->emplace_back("where_expr", where_expr_.get());
  }
}

zetasql_base::Status ResolvedDeleteStmt::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0 &&
      !IsDefaultValue(table_scan_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedDeleteStmt::table_scan not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<1)) == 0 &&
      !IsDefaultValue(assert_rows_modified_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedDeleteStmt::assert_rows_modified not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<2)) == 0 &&
      !IsDefaultValue(array_offset_column_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedDeleteStmt::array_offset_column not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<3)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedDeleteStmt::where_expr not accessed)";
  }
  if ((accessed_ & (1<<0)) != 0) {
    if (table_scan_ != nullptr) {
      ZETASQL_RETURN_IF_ERROR(table_scan_->CheckFieldsAccessed());
    }
  }
  if ((accessed_ & (1<<1)) != 0) {
    if (assert_rows_modified_ != nullptr) {
      ZETASQL_RETURN_IF_ERROR(assert_rows_modified_->CheckFieldsAccessed());
    }
  }
  if ((accessed_ & (1<<2)) != 0) {
    if (array_offset_column_ != nullptr) {
      ZETASQL_RETURN_IF_ERROR(array_offset_column_->CheckFieldsAccessed());
    }
  }
  if ((accessed_ & (1<<3)) != 0) {
    if (where_expr_ != nullptr) {
      ZETASQL_RETURN_IF_ERROR(where_expr_->CheckFieldsAccessed());
    }
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedDeleteStmt::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
  if (table_scan_ != nullptr) table_scan_->ClearFieldsAccessed();
  if (assert_rows_modified_ != nullptr) assert_rows_modified_->ClearFieldsAccessed();
  if (array_offset_column_ != nullptr) array_offset_column_->ClearFieldsAccessed();
  if (where_expr_ != nullptr) where_expr_->ClearFieldsAccessed();
}

const ResolvedNodeKind ResolvedUpdateItem::TYPE;

ResolvedUpdateItem::~ResolvedUpdateItem() {
}

zetasql_base::Status ResolvedUpdateItem::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedArgumentProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_update_item_node());
}

zetasql_base::Status ResolvedUpdateItem::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedUpdateItemProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  if (target_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(target_->SaveTo(
        file_descriptor_set_map, proto->mutable_target()));
  }
  if (set_value_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(set_value_->SaveTo(
        file_descriptor_set_map, proto->mutable_set_value()));
  }
  if (element_column_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(element_column_->SaveTo(
        file_descriptor_set_map, proto->mutable_element_column()));
  }
  for (const auto& elem : array_update_list_) {
    ZETASQL_RETURN_IF_ERROR(elem->SaveTo(
      file_descriptor_set_map, proto->add_array_update_list()));
  }
  for (const auto& elem : delete_list_) {
    ZETASQL_RETURN_IF_ERROR(elem->SaveTo(
      file_descriptor_set_map, proto->add_delete_list()));
  }
  for (const auto& elem : update_list_) {
    ZETASQL_RETURN_IF_ERROR(elem->SaveTo(
      file_descriptor_set_map, proto->add_update_list()));
  }
  for (const auto& elem : insert_list_) {
    ZETASQL_RETURN_IF_ERROR(elem->SaveTo(
      file_descriptor_set_map, proto->add_insert_list()));
  }
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedUpdateItem>> ResolvedUpdateItem::RestoreFrom(
    const ResolvedUpdateItemProto& proto,
    const ResolvedNode::RestoreParams& params) {
  std::unique_ptr<const ResolvedExpr> target;
  if (proto.
  has_target()) {
    ZETASQL_ASSIGN_OR_RETURN(target,
                     ResolvedExpr::RestoreFrom(
                         proto.target(), params));
  }
  std::unique_ptr<const ResolvedDMLValue> set_value;
  if (proto.
  has_set_value()) {
    ZETASQL_ASSIGN_OR_RETURN(set_value,
                     ResolvedDMLValue::RestoreFrom(
                         proto.set_value(), params));
  }
  std::unique_ptr<const ResolvedColumnHolder> element_column;
  if (proto.
  has_element_column()) {
    ZETASQL_ASSIGN_OR_RETURN(element_column,
                     ResolvedColumnHolder::RestoreFrom(
                         proto.element_column(), params));
  }
  std::vector<std::unique_ptr<const ResolvedUpdateArrayItem>> array_update_list;
  for (const auto& elem : proto.array_update_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedUpdateArrayItem> elem_restored,
                     ResolvedUpdateArrayItem::RestoreFrom(elem, params));
    array_update_list.push_back(std::move(elem_restored));
  }
  std::vector<std::unique_ptr<const ResolvedDeleteStmt>> delete_list;
  for (const auto& elem : proto.delete_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedDeleteStmt> elem_restored,
                     ResolvedDeleteStmt::RestoreFrom(elem, params));
    delete_list.push_back(std::move(elem_restored));
  }
  std::vector<std::unique_ptr<const ResolvedUpdateStmt>> update_list;
  for (const auto& elem : proto.update_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedUpdateStmt> elem_restored,
                     ResolvedUpdateStmt::RestoreFrom(elem, params));
    update_list.push_back(std::move(elem_restored));
  }
  std::vector<std::unique_ptr<const ResolvedInsertStmt>> insert_list;
  for (const auto& elem : proto.insert_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedInsertStmt> elem_restored,
                     ResolvedInsertStmt::RestoreFrom(elem, params));
    insert_list.push_back(std::move(elem_restored));
  }
  auto node = MakeResolvedUpdateItem(
      std::move(target),
      std::move(set_value),
      std::move(element_column),
      std::move(array_update_list),
      std::move(delete_list),
      std::move(update_list),
      std::move(insert_list));

  return std::move(node);
}

void ResolvedUpdateItem::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
  if (target_ != nullptr) {
    child_nodes->emplace_back(target_.get());
  }
  if (set_value_ != nullptr) {
    child_nodes->emplace_back(set_value_.get());
  }
  if (element_column_ != nullptr) {
    child_nodes->emplace_back(element_column_.get());
  }
  for (const auto& elem : array_update_list_) {
    child_nodes->emplace_back(elem.get());
  }
  for (const auto& elem : delete_list_) {
    child_nodes->emplace_back(elem.get());
  }
  for (const auto& elem : update_list_) {
    child_nodes->emplace_back(elem.get());
  }
  for (const auto& elem : insert_list_) {
    child_nodes->emplace_back(elem.get());
  }
}

void ResolvedUpdateItem::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
  if (target_ != nullptr) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(
            &target_));
    static_assert(sizeof(target_) ==
                  sizeof(*(mutable_child_node_ptrs->back())),
                  "Incorrect casting of mutable child node");
  }
  if (set_value_ != nullptr) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(
            &set_value_));
    static_assert(sizeof(set_value_) ==
                  sizeof(*(mutable_child_node_ptrs->back())),
                  "Incorrect casting of mutable child node");
  }
  if (element_column_ != nullptr) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(
            &element_column_));
    static_assert(sizeof(element_column_) ==
                  sizeof(*(mutable_child_node_ptrs->back())),
                  "Incorrect casting of mutable child node");
  }
  for (auto& elem : array_update_list_) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(&elem));
  }
  for (auto& elem : delete_list_) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(&elem));
  }
  for (auto& elem : update_list_) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(&elem));
  }
  for (auto& elem : insert_list_) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(&elem));
  }
}

zetasql_base::Status ResolvedUpdateItem::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedUpdateItem(this);
}

zetasql_base::Status ResolvedUpdateItem::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  if (target_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(target_.get()->Accept(visitor));
  }
  if (set_value_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(set_value_.get()->Accept(visitor));
  }
  if (element_column_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(element_column_.get()->Accept(visitor));
  }
  for (const auto& elem : array_update_list_) {
    ZETASQL_RETURN_IF_ERROR(elem.get()->Accept(visitor));
  }
  for (const auto& elem : delete_list_) {
    ZETASQL_RETURN_IF_ERROR(elem.get()->Accept(visitor));
  }
  for (const auto& elem : update_list_) {
    ZETASQL_RETURN_IF_ERROR(elem.get()->Accept(visitor));
  }
  for (const auto& elem : insert_list_) {
    ZETASQL_RETURN_IF_ERROR(elem.get()->Accept(visitor));
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedUpdateItem::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  if (target_ != nullptr) {
    fields->emplace_back("target", target_.get());
  }
  if (set_value_ != nullptr) {
    fields->emplace_back("set_value", set_value_.get());
  }
  if (element_column_ != nullptr) {
    fields->emplace_back("element_column", element_column_.get());
  }
  if (!array_update_list_.empty()) {
    fields->emplace_back("array_update_list", array_update_list_);
  }
  if (!delete_list_.empty()) {
    fields->emplace_back("delete_list", delete_list_);
  }
  if (!update_list_.empty()) {
    fields->emplace_back("update_list", update_list_);
  }
  if (!insert_list_.empty()) {
    fields->emplace_back("insert_list", insert_list_);
  }
}

zetasql_base::Status ResolvedUpdateItem::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedUpdateItem::target not accessed)";
  }
  if ((accessed_ & (1<<1)) == 0 &&
      !IsDefaultValue(set_value_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedUpdateItem::set_value not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<2)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedUpdateItem::element_column not accessed)";
  }
  if ((accessed_ & (1<<3)) == 0 &&
      !IsDefaultValue(array_update_list_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedUpdateItem::array_update_list not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<4)) == 0 &&
      !IsDefaultValue(delete_list_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedUpdateItem::delete_list not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<5)) == 0 &&
      !IsDefaultValue(update_list_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedUpdateItem::update_list not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<6)) == 0 &&
      !IsDefaultValue(insert_list_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedUpdateItem::insert_list not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<0)) != 0) {
    if (target_ != nullptr) {
      ZETASQL_RETURN_IF_ERROR(target_->CheckFieldsAccessed());
    }
  }
  if ((accessed_ & (1<<1)) != 0) {
    if (set_value_ != nullptr) {
      ZETASQL_RETURN_IF_ERROR(set_value_->CheckFieldsAccessed());
    }
  }
  if ((accessed_ & (1<<2)) != 0) {
    if (element_column_ != nullptr) {
      ZETASQL_RETURN_IF_ERROR(element_column_->CheckFieldsAccessed());
    }
  }
  if ((accessed_ & (1<<3)) != 0) {
    for (const auto& it : array_update_list_) ZETASQL_RETURN_IF_ERROR(it->CheckFieldsAccessed());
  }
  if ((accessed_ & (1<<4)) != 0) {
    for (const auto& it : delete_list_) ZETASQL_RETURN_IF_ERROR(it->CheckFieldsAccessed());
  }
  if ((accessed_ & (1<<5)) != 0) {
    for (const auto& it : update_list_) ZETASQL_RETURN_IF_ERROR(it->CheckFieldsAccessed());
  }
  if ((accessed_ & (1<<6)) != 0) {
    for (const auto& it : insert_list_) ZETASQL_RETURN_IF_ERROR(it->CheckFieldsAccessed());
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedUpdateItem::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
  if (target_ != nullptr) target_->ClearFieldsAccessed();
  if (set_value_ != nullptr) set_value_->ClearFieldsAccessed();
  if (element_column_ != nullptr) element_column_->ClearFieldsAccessed();
  for (const auto& it : array_update_list_) it->ClearFieldsAccessed();
  for (const auto& it : delete_list_) it->ClearFieldsAccessed();
  for (const auto& it : update_list_) it->ClearFieldsAccessed();
  for (const auto& it : insert_list_) it->ClearFieldsAccessed();
}

const ResolvedNodeKind ResolvedUpdateArrayItem::TYPE;

ResolvedUpdateArrayItem::~ResolvedUpdateArrayItem() {
}

zetasql_base::Status ResolvedUpdateArrayItem::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedArgumentProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_update_array_item_node());
}

zetasql_base::Status ResolvedUpdateArrayItem::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedUpdateArrayItemProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  if (offset_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(offset_->SaveTo(
        file_descriptor_set_map, proto->mutable_offset()));
  }
  if (update_item_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(update_item_->SaveTo(
        file_descriptor_set_map, proto->mutable_update_item()));
  }
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedUpdateArrayItem>> ResolvedUpdateArrayItem::RestoreFrom(
    const ResolvedUpdateArrayItemProto& proto,
    const ResolvedNode::RestoreParams& params) {
  std::unique_ptr<const ResolvedExpr> offset;
  if (proto.
  has_offset()) {
    ZETASQL_ASSIGN_OR_RETURN(offset,
                     ResolvedExpr::RestoreFrom(
                         proto.offset(), params));
  }
  std::unique_ptr<const ResolvedUpdateItem> update_item;
  if (proto.
  has_update_item()) {
    ZETASQL_ASSIGN_OR_RETURN(update_item,
                     ResolvedUpdateItem::RestoreFrom(
                         proto.update_item(), params));
  }
  auto node = MakeResolvedUpdateArrayItem(
      std::move(offset),
      std::move(update_item));

  return std::move(node);
}

void ResolvedUpdateArrayItem::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
  if (offset_ != nullptr) {
    child_nodes->emplace_back(offset_.get());
  }
  if (update_item_ != nullptr) {
    child_nodes->emplace_back(update_item_.get());
  }
}

void ResolvedUpdateArrayItem::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
  if (offset_ != nullptr) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(
            &offset_));
    static_assert(sizeof(offset_) ==
                  sizeof(*(mutable_child_node_ptrs->back())),
                  "Incorrect casting of mutable child node");
  }
  if (update_item_ != nullptr) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(
            &update_item_));
    static_assert(sizeof(update_item_) ==
                  sizeof(*(mutable_child_node_ptrs->back())),
                  "Incorrect casting of mutable child node");
  }
}

zetasql_base::Status ResolvedUpdateArrayItem::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedUpdateArrayItem(this);
}

zetasql_base::Status ResolvedUpdateArrayItem::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  if (offset_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(offset_.get()->Accept(visitor));
  }
  if (update_item_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(update_item_.get()->Accept(visitor));
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedUpdateArrayItem::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  if (offset_ != nullptr) {
    fields->emplace_back("offset", offset_.get());
  }
  if (update_item_ != nullptr) {
    fields->emplace_back("update_item", update_item_.get());
  }
}

zetasql_base::Status ResolvedUpdateArrayItem::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedUpdateArrayItem::offset not accessed)";
  }
  if ((accessed_ & (1<<1)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedUpdateArrayItem::update_item not accessed)";
  }
  if ((accessed_ & (1<<0)) != 0) {
    if (offset_ != nullptr) {
      ZETASQL_RETURN_IF_ERROR(offset_->CheckFieldsAccessed());
    }
  }
  if ((accessed_ & (1<<1)) != 0) {
    if (update_item_ != nullptr) {
      ZETASQL_RETURN_IF_ERROR(update_item_->CheckFieldsAccessed());
    }
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedUpdateArrayItem::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
  if (offset_ != nullptr) offset_->ClearFieldsAccessed();
  if (update_item_ != nullptr) update_item_->ClearFieldsAccessed();
}

const ResolvedNodeKind ResolvedUpdateStmt::TYPE;

ResolvedUpdateStmt::~ResolvedUpdateStmt() {
}

zetasql_base::Status ResolvedUpdateStmt::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedStatementProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_update_stmt_node());
}

zetasql_base::Status ResolvedUpdateStmt::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedUpdateStmtProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  if (table_scan_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(table_scan_->SaveTo(
        file_descriptor_set_map, proto->mutable_table_scan()));
  }
  for (const auto& elem : column_access_list_) {
    proto->add_column_access_list(elem);
  }
  if (assert_rows_modified_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(assert_rows_modified_->SaveTo(
        file_descriptor_set_map, proto->mutable_assert_rows_modified()));
  }
  if (array_offset_column_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(array_offset_column_->SaveTo(
        file_descriptor_set_map, proto->mutable_array_offset_column()));
  }
  if (where_expr_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(where_expr_->SaveTo(
        file_descriptor_set_map, proto->mutable_where_expr()));
  }
  for (const auto& elem : update_item_list_) {
    ZETASQL_RETURN_IF_ERROR(elem->SaveTo(
      file_descriptor_set_map, proto->add_update_item_list()));
  }
  if (from_scan_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(from_scan_->SaveTo(
        file_descriptor_set_map, proto->mutable_from_scan()));
  }
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedUpdateStmt>> ResolvedUpdateStmt::RestoreFrom(
    const ResolvedUpdateStmtProto& proto,
    const ResolvedNode::RestoreParams& params) {
  std::unique_ptr<const ResolvedTableScan> table_scan;
  if (proto.
  has_table_scan()) {
    ZETASQL_ASSIGN_OR_RETURN(table_scan,
                     ResolvedTableScan::RestoreFrom(
                         proto.table_scan(), params));
  }
  std::vector<ObjectAccess> column_access_list;
  for (const auto& elem : proto.column_access_list()) {
    // We need a static cast because the proto getter returns a
    // RepeatedField<int>, not RepeatedField<enum>.
    column_access_list.push_back(static_cast<ObjectAccess>(elem));
  }
  std::unique_ptr<const ResolvedAssertRowsModified> assert_rows_modified;
  if (proto.
  has_assert_rows_modified()) {
    ZETASQL_ASSIGN_OR_RETURN(assert_rows_modified,
                     ResolvedAssertRowsModified::RestoreFrom(
                         proto.assert_rows_modified(), params));
  }
  std::unique_ptr<const ResolvedColumnHolder> array_offset_column;
  if (proto.
  has_array_offset_column()) {
    ZETASQL_ASSIGN_OR_RETURN(array_offset_column,
                     ResolvedColumnHolder::RestoreFrom(
                         proto.array_offset_column(), params));
  }
  std::unique_ptr<const ResolvedExpr> where_expr;
  if (proto.
  has_where_expr()) {
    ZETASQL_ASSIGN_OR_RETURN(where_expr,
                     ResolvedExpr::RestoreFrom(
                         proto.where_expr(), params));
  }
  std::vector<std::unique_ptr<const ResolvedUpdateItem>> update_item_list;
  for (const auto& elem : proto.update_item_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedUpdateItem> elem_restored,
                     ResolvedUpdateItem::RestoreFrom(elem, params));
    update_item_list.push_back(std::move(elem_restored));
  }
  std::unique_ptr<const ResolvedScan> from_scan;
  if (proto.
  has_from_scan()) {
    ZETASQL_ASSIGN_OR_RETURN(from_scan,
                     ResolvedScan::RestoreFrom(
                         proto.from_scan(), params));
  }
  std::vector<std::unique_ptr<const ResolvedOption>> hint_list;
  for (const auto& elem : proto.parent().hint_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedOption> elem_restored,
                     ResolvedOption::RestoreFrom(elem, params));
    hint_list.push_back(std::move(elem_restored));
  }
  auto node = MakeResolvedUpdateStmt(
      std::move(table_scan),
      std::move(assert_rows_modified),
      std::move(array_offset_column),
      std::move(where_expr),
      std::move(update_item_list),
      std::move(from_scan));

  node->set_hint_list(std::move(hint_list));
  node->set_column_access_list(std::move(column_access_list));
  return std::move(node);
}

void ResolvedUpdateStmt::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
  if (table_scan_ != nullptr) {
    child_nodes->emplace_back(table_scan_.get());
  }
  if (assert_rows_modified_ != nullptr) {
    child_nodes->emplace_back(assert_rows_modified_.get());
  }
  if (array_offset_column_ != nullptr) {
    child_nodes->emplace_back(array_offset_column_.get());
  }
  if (where_expr_ != nullptr) {
    child_nodes->emplace_back(where_expr_.get());
  }
  for (const auto& elem : update_item_list_) {
    child_nodes->emplace_back(elem.get());
  }
  if (from_scan_ != nullptr) {
    child_nodes->emplace_back(from_scan_.get());
  }
}

void ResolvedUpdateStmt::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
  if (table_scan_ != nullptr) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(
            &table_scan_));
    static_assert(sizeof(table_scan_) ==
                  sizeof(*(mutable_child_node_ptrs->back())),
                  "Incorrect casting of mutable child node");
  }
  if (assert_rows_modified_ != nullptr) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(
            &assert_rows_modified_));
    static_assert(sizeof(assert_rows_modified_) ==
                  sizeof(*(mutable_child_node_ptrs->back())),
                  "Incorrect casting of mutable child node");
  }
  if (array_offset_column_ != nullptr) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(
            &array_offset_column_));
    static_assert(sizeof(array_offset_column_) ==
                  sizeof(*(mutable_child_node_ptrs->back())),
                  "Incorrect casting of mutable child node");
  }
  if (where_expr_ != nullptr) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(
            &where_expr_));
    static_assert(sizeof(where_expr_) ==
                  sizeof(*(mutable_child_node_ptrs->back())),
                  "Incorrect casting of mutable child node");
  }
  for (auto& elem : update_item_list_) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(&elem));
  }
  if (from_scan_ != nullptr) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(
            &from_scan_));
    static_assert(sizeof(from_scan_) ==
                  sizeof(*(mutable_child_node_ptrs->back())),
                  "Incorrect casting of mutable child node");
  }
}

zetasql_base::Status ResolvedUpdateStmt::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedUpdateStmt(this);
}

zetasql_base::Status ResolvedUpdateStmt::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  if (table_scan_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(table_scan_.get()->Accept(visitor));
  }
  if (assert_rows_modified_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(assert_rows_modified_.get()->Accept(visitor));
  }
  if (array_offset_column_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(array_offset_column_.get()->Accept(visitor));
  }
  if (where_expr_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(where_expr_.get()->Accept(visitor));
  }
  for (const auto& elem : update_item_list_) {
    ZETASQL_RETURN_IF_ERROR(elem.get()->Accept(visitor));
  }
  if (from_scan_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(from_scan_.get()->Accept(visitor));
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedUpdateStmt::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  if (table_scan_ != nullptr) {
    fields->emplace_back("table_scan", table_scan_.get());
  }
  if (!IsDefaultValue(column_access_list_)) {
    fields->emplace_back("column_access_list", ToStringImpl(column_access_list_));
  }
  if (assert_rows_modified_ != nullptr) {
    fields->emplace_back("assert_rows_modified", assert_rows_modified_.get());
  }
  if (array_offset_column_ != nullptr) {
    fields->emplace_back("array_offset_column", array_offset_column_.get());
  }
  if (where_expr_ != nullptr) {
    fields->emplace_back("where_expr", where_expr_.get());
  }
  if (!update_item_list_.empty()) {
    fields->emplace_back("update_item_list", update_item_list_);
  }
  if (from_scan_ != nullptr) {
    fields->emplace_back("from_scan", from_scan_.get());
  }
}

zetasql_base::Status ResolvedUpdateStmt::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0 &&
      !IsDefaultValue(table_scan_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedUpdateStmt::table_scan not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<2)) == 0 &&
      !IsDefaultValue(assert_rows_modified_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedUpdateStmt::assert_rows_modified not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<3)) == 0 &&
      !IsDefaultValue(array_offset_column_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedUpdateStmt::array_offset_column not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<4)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedUpdateStmt::where_expr not accessed)";
  }
  if ((accessed_ & (1<<5)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedUpdateStmt::update_item_list not accessed)";
  }
  if ((accessed_ & (1<<6)) == 0 &&
      !IsDefaultValue(from_scan_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedUpdateStmt::from_scan not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<0)) != 0) {
    if (table_scan_ != nullptr) {
      ZETASQL_RETURN_IF_ERROR(table_scan_->CheckFieldsAccessed());
    }
  }
  if ((accessed_ & (1<<2)) != 0) {
    if (assert_rows_modified_ != nullptr) {
      ZETASQL_RETURN_IF_ERROR(assert_rows_modified_->CheckFieldsAccessed());
    }
  }
  if ((accessed_ & (1<<3)) != 0) {
    if (array_offset_column_ != nullptr) {
      ZETASQL_RETURN_IF_ERROR(array_offset_column_->CheckFieldsAccessed());
    }
  }
  if ((accessed_ & (1<<4)) != 0) {
    if (where_expr_ != nullptr) {
      ZETASQL_RETURN_IF_ERROR(where_expr_->CheckFieldsAccessed());
    }
  }
  if ((accessed_ & (1<<5)) != 0) {
    for (const auto& it : update_item_list_) ZETASQL_RETURN_IF_ERROR(it->CheckFieldsAccessed());
  }
  if ((accessed_ & (1<<6)) != 0) {
    if (from_scan_ != nullptr) {
      ZETASQL_RETURN_IF_ERROR(from_scan_->CheckFieldsAccessed());
    }
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedUpdateStmt::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
  if (table_scan_ != nullptr) table_scan_->ClearFieldsAccessed();
  if (assert_rows_modified_ != nullptr) assert_rows_modified_->ClearFieldsAccessed();
  if (array_offset_column_ != nullptr) array_offset_column_->ClearFieldsAccessed();
  if (where_expr_ != nullptr) where_expr_->ClearFieldsAccessed();
  for (const auto& it : update_item_list_) it->ClearFieldsAccessed();
  if (from_scan_ != nullptr) from_scan_->ClearFieldsAccessed();
}

const ResolvedNodeKind ResolvedMergeWhen::TYPE;

const ResolvedMergeWhen::MatchType ResolvedMergeWhen::MATCHED;
const ResolvedMergeWhen::MatchType ResolvedMergeWhen::NOT_MATCHED_BY_SOURCE;
const ResolvedMergeWhen::MatchType ResolvedMergeWhen::NOT_MATCHED_BY_TARGET;
const ResolvedMergeWhen::ActionType ResolvedMergeWhen::INSERT;
const ResolvedMergeWhen::ActionType ResolvedMergeWhen::UPDATE;
const ResolvedMergeWhen::ActionType ResolvedMergeWhen::DELETE;

ResolvedMergeWhen::~ResolvedMergeWhen() {
}

zetasql_base::Status ResolvedMergeWhen::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedArgumentProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_merge_when_node());
}

zetasql_base::Status ResolvedMergeWhen::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedMergeWhenProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  proto->set_match_type(match_type_);
  if (match_expr_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(match_expr_->SaveTo(
        file_descriptor_set_map, proto->mutable_match_expr()));
  }
  proto->set_action_type(action_type_);
  for (const auto& elem : insert_column_list_) {
    ZETASQL_RETURN_IF_ERROR(SaveToImpl(
        elem, file_descriptor_set_map, proto->add_insert_column_list()));
  }
  if (insert_row_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(insert_row_->SaveTo(
        file_descriptor_set_map, proto->mutable_insert_row()));
  }
  for (const auto& elem : update_item_list_) {
    ZETASQL_RETURN_IF_ERROR(elem->SaveTo(
      file_descriptor_set_map, proto->add_update_item_list()));
  }
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedMergeWhen>> ResolvedMergeWhen::RestoreFrom(
    const ResolvedMergeWhenProto& proto,
    const ResolvedNode::RestoreParams& params) {
  MatchType match_type =
      proto.match_type();
  std::unique_ptr<const ResolvedExpr> match_expr;
  if (proto.
  has_match_expr()) {
    ZETASQL_ASSIGN_OR_RETURN(match_expr,
                     ResolvedExpr::RestoreFrom(
                         proto.match_expr(), params));
  }
  ActionType action_type =
      proto.action_type();
  std::vector<ResolvedColumn> insert_column_list;
  for (const auto& elem : proto.insert_column_list()) {
    ZETASQL_ASSIGN_OR_RETURN(auto elem_restored, RestoreFromImpl(elem, params));
    insert_column_list.push_back(std::move(elem_restored));
  }
  std::unique_ptr<const ResolvedInsertRow> insert_row;
  if (proto.
  has_insert_row()) {
    ZETASQL_ASSIGN_OR_RETURN(insert_row,
                     ResolvedInsertRow::RestoreFrom(
                         proto.insert_row(), params));
  }
  std::vector<std::unique_ptr<const ResolvedUpdateItem>> update_item_list;
  for (const auto& elem : proto.update_item_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedUpdateItem> elem_restored,
                     ResolvedUpdateItem::RestoreFrom(elem, params));
    update_item_list.push_back(std::move(elem_restored));
  }
  auto node = MakeResolvedMergeWhen(
      std::move(match_type),
      std::move(match_expr),
      std::move(action_type),
      std::move(insert_column_list),
      std::move(insert_row),
      std::move(update_item_list));

  return std::move(node);
}

void ResolvedMergeWhen::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
  if (match_expr_ != nullptr) {
    child_nodes->emplace_back(match_expr_.get());
  }
  if (insert_row_ != nullptr) {
    child_nodes->emplace_back(insert_row_.get());
  }
  for (const auto& elem : update_item_list_) {
    child_nodes->emplace_back(elem.get());
  }
}

void ResolvedMergeWhen::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
  if (match_expr_ != nullptr) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(
            &match_expr_));
    static_assert(sizeof(match_expr_) ==
                  sizeof(*(mutable_child_node_ptrs->back())),
                  "Incorrect casting of mutable child node");
  }
  if (insert_row_ != nullptr) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(
            &insert_row_));
    static_assert(sizeof(insert_row_) ==
                  sizeof(*(mutable_child_node_ptrs->back())),
                  "Incorrect casting of mutable child node");
  }
  for (auto& elem : update_item_list_) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(&elem));
  }
}

zetasql_base::Status ResolvedMergeWhen::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedMergeWhen(this);
}

zetasql_base::Status ResolvedMergeWhen::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  if (match_expr_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(match_expr_.get()->Accept(visitor));
  }
  if (insert_row_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(insert_row_.get()->Accept(visitor));
  }
  for (const auto& elem : update_item_list_) {
    ZETASQL_RETURN_IF_ERROR(elem.get()->Accept(visitor));
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedMergeWhen::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  {
    fields->emplace_back("match_type", ToStringImpl(match_type_));
  }
  if (match_expr_ != nullptr) {
    fields->emplace_back("match_expr", match_expr_.get());
  }
  {
    fields->emplace_back("action_type", ToStringImpl(action_type_));
  }
  if (!IsDefaultValue(insert_column_list_)) {
    fields->emplace_back("insert_column_list", ToStringImpl(insert_column_list_));
  }
  if (insert_row_ != nullptr) {
    fields->emplace_back("insert_row", insert_row_.get());
  }
  if (!update_item_list_.empty()) {
    fields->emplace_back("update_item_list", update_item_list_);
  }
}

zetasql_base::Status ResolvedMergeWhen::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedMergeWhen::match_type not accessed)";
  }
  if ((accessed_ & (1<<1)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedMergeWhen::match_expr not accessed)";
  }
  if ((accessed_ & (1<<2)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedMergeWhen::action_type not accessed)";
  }
  if ((accessed_ & (1<<3)) == 0 &&
      !IsDefaultValue(insert_column_list_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedMergeWhen::insert_column_list not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<4)) == 0 &&
      !IsDefaultValue(insert_row_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedMergeWhen::insert_row not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<5)) == 0 &&
      !IsDefaultValue(update_item_list_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedMergeWhen::update_item_list not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<1)) != 0) {
    if (match_expr_ != nullptr) {
      ZETASQL_RETURN_IF_ERROR(match_expr_->CheckFieldsAccessed());
    }
  }
  if ((accessed_ & (1<<4)) != 0) {
    if (insert_row_ != nullptr) {
      ZETASQL_RETURN_IF_ERROR(insert_row_->CheckFieldsAccessed());
    }
  }
  if ((accessed_ & (1<<5)) != 0) {
    for (const auto& it : update_item_list_) ZETASQL_RETURN_IF_ERROR(it->CheckFieldsAccessed());
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedMergeWhen::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
  if (match_expr_ != nullptr) match_expr_->ClearFieldsAccessed();
  if (insert_row_ != nullptr) insert_row_->ClearFieldsAccessed();
  for (const auto& it : update_item_list_) it->ClearFieldsAccessed();
}

const ResolvedNodeKind ResolvedMergeStmt::TYPE;

ResolvedMergeStmt::~ResolvedMergeStmt() {
}

zetasql_base::Status ResolvedMergeStmt::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedStatementProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_merge_stmt_node());
}

zetasql_base::Status ResolvedMergeStmt::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedMergeStmtProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  if (table_scan_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(table_scan_->SaveTo(
        file_descriptor_set_map, proto->mutable_table_scan()));
  }
  for (const auto& elem : column_access_list_) {
    proto->add_column_access_list(elem);
  }
  if (from_scan_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(from_scan_->SaveTo(
        file_descriptor_set_map, proto->mutable_from_scan()));
  }
  if (merge_expr_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(merge_expr_->SaveTo(
        file_descriptor_set_map, proto->mutable_merge_expr()));
  }
  for (const auto& elem : when_clause_list_) {
    ZETASQL_RETURN_IF_ERROR(elem->SaveTo(
      file_descriptor_set_map, proto->add_when_clause_list()));
  }
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedMergeStmt>> ResolvedMergeStmt::RestoreFrom(
    const ResolvedMergeStmtProto& proto,
    const ResolvedNode::RestoreParams& params) {
  std::unique_ptr<const ResolvedTableScan> table_scan;
  if (proto.
  has_table_scan()) {
    ZETASQL_ASSIGN_OR_RETURN(table_scan,
                     ResolvedTableScan::RestoreFrom(
                         proto.table_scan(), params));
  }
  std::vector<ObjectAccess> column_access_list;
  for (const auto& elem : proto.column_access_list()) {
    // We need a static cast because the proto getter returns a
    // RepeatedField<int>, not RepeatedField<enum>.
    column_access_list.push_back(static_cast<ObjectAccess>(elem));
  }
  std::unique_ptr<const ResolvedScan> from_scan;
  if (proto.
  has_from_scan()) {
    ZETASQL_ASSIGN_OR_RETURN(from_scan,
                     ResolvedScan::RestoreFrom(
                         proto.from_scan(), params));
  }
  std::unique_ptr<const ResolvedExpr> merge_expr;
  if (proto.
  has_merge_expr()) {
    ZETASQL_ASSIGN_OR_RETURN(merge_expr,
                     ResolvedExpr::RestoreFrom(
                         proto.merge_expr(), params));
  }
  std::vector<std::unique_ptr<const ResolvedMergeWhen>> when_clause_list;
  for (const auto& elem : proto.when_clause_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedMergeWhen> elem_restored,
                     ResolvedMergeWhen::RestoreFrom(elem, params));
    when_clause_list.push_back(std::move(elem_restored));
  }
  std::vector<std::unique_ptr<const ResolvedOption>> hint_list;
  for (const auto& elem : proto.parent().hint_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedOption> elem_restored,
                     ResolvedOption::RestoreFrom(elem, params));
    hint_list.push_back(std::move(elem_restored));
  }
  auto node = MakeResolvedMergeStmt(
      std::move(table_scan),
      std::move(from_scan),
      std::move(merge_expr),
      std::move(when_clause_list));

  node->set_hint_list(std::move(hint_list));
  node->set_column_access_list(std::move(column_access_list));
  return std::move(node);
}

void ResolvedMergeStmt::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
  if (table_scan_ != nullptr) {
    child_nodes->emplace_back(table_scan_.get());
  }
  if (from_scan_ != nullptr) {
    child_nodes->emplace_back(from_scan_.get());
  }
  if (merge_expr_ != nullptr) {
    child_nodes->emplace_back(merge_expr_.get());
  }
  for (const auto& elem : when_clause_list_) {
    child_nodes->emplace_back(elem.get());
  }
}

void ResolvedMergeStmt::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
  if (table_scan_ != nullptr) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(
            &table_scan_));
    static_assert(sizeof(table_scan_) ==
                  sizeof(*(mutable_child_node_ptrs->back())),
                  "Incorrect casting of mutable child node");
  }
  if (from_scan_ != nullptr) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(
            &from_scan_));
    static_assert(sizeof(from_scan_) ==
                  sizeof(*(mutable_child_node_ptrs->back())),
                  "Incorrect casting of mutable child node");
  }
  if (merge_expr_ != nullptr) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(
            &merge_expr_));
    static_assert(sizeof(merge_expr_) ==
                  sizeof(*(mutable_child_node_ptrs->back())),
                  "Incorrect casting of mutable child node");
  }
  for (auto& elem : when_clause_list_) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(&elem));
  }
}

zetasql_base::Status ResolvedMergeStmt::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedMergeStmt(this);
}

zetasql_base::Status ResolvedMergeStmt::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  if (table_scan_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(table_scan_.get()->Accept(visitor));
  }
  if (from_scan_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(from_scan_.get()->Accept(visitor));
  }
  if (merge_expr_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(merge_expr_.get()->Accept(visitor));
  }
  for (const auto& elem : when_clause_list_) {
    ZETASQL_RETURN_IF_ERROR(elem.get()->Accept(visitor));
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedMergeStmt::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  if (table_scan_ != nullptr) {
    fields->emplace_back("table_scan", table_scan_.get());
  }
  if (!IsDefaultValue(column_access_list_)) {
    fields->emplace_back("column_access_list", ToStringImpl(column_access_list_));
  }
  if (from_scan_ != nullptr) {
    fields->emplace_back("from_scan", from_scan_.get());
  }
  if (merge_expr_ != nullptr) {
    fields->emplace_back("merge_expr", merge_expr_.get());
  }
  if (!when_clause_list_.empty()) {
    fields->emplace_back("when_clause_list", when_clause_list_);
  }
}

zetasql_base::Status ResolvedMergeStmt::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedMergeStmt::table_scan not accessed)";
  }
  if ((accessed_ & (1<<2)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedMergeStmt::from_scan not accessed)";
  }
  if ((accessed_ & (1<<3)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedMergeStmt::merge_expr not accessed)";
  }
  if ((accessed_ & (1<<4)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedMergeStmt::when_clause_list not accessed)";
  }
  if ((accessed_ & (1<<0)) != 0) {
    if (table_scan_ != nullptr) {
      ZETASQL_RETURN_IF_ERROR(table_scan_->CheckFieldsAccessed());
    }
  }
  if ((accessed_ & (1<<2)) != 0) {
    if (from_scan_ != nullptr) {
      ZETASQL_RETURN_IF_ERROR(from_scan_->CheckFieldsAccessed());
    }
  }
  if ((accessed_ & (1<<3)) != 0) {
    if (merge_expr_ != nullptr) {
      ZETASQL_RETURN_IF_ERROR(merge_expr_->CheckFieldsAccessed());
    }
  }
  if ((accessed_ & (1<<4)) != 0) {
    for (const auto& it : when_clause_list_) ZETASQL_RETURN_IF_ERROR(it->CheckFieldsAccessed());
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedMergeStmt::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
  if (table_scan_ != nullptr) table_scan_->ClearFieldsAccessed();
  if (from_scan_ != nullptr) from_scan_->ClearFieldsAccessed();
  if (merge_expr_ != nullptr) merge_expr_->ClearFieldsAccessed();
  for (const auto& it : when_clause_list_) it->ClearFieldsAccessed();
}

const ResolvedNodeKind ResolvedPrivilege::TYPE;

ResolvedPrivilege::~ResolvedPrivilege() {
}

zetasql_base::Status ResolvedPrivilege::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedArgumentProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_privilege_node());
}

zetasql_base::Status ResolvedPrivilege::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedPrivilegeProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  proto->set_action_type(action_type_);
  for (const auto& elem : unit_list_) {
    proto->add_unit_list(elem);
  }
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedPrivilege>> ResolvedPrivilege::RestoreFrom(
    const ResolvedPrivilegeProto& proto,
    const ResolvedNode::RestoreParams& params) {
  std::string action_type =
      proto.action_type();
  std::vector<std::string> unit_list;
  for (const auto& elem : proto.unit_list()) {
    unit_list.push_back(elem);
  }
  auto node = MakeResolvedPrivilege(
      std::move(action_type),
      std::move(unit_list));

  return std::move(node);
}

void ResolvedPrivilege::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
}

void ResolvedPrivilege::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
}

zetasql_base::Status ResolvedPrivilege::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedPrivilege(this);
}

zetasql_base::Status ResolvedPrivilege::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  return ::zetasql_base::OkStatus();
}

void ResolvedPrivilege::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  {
    fields->emplace_back("action_type", ToStringImpl(action_type_));
  }
  {
    fields->emplace_back("unit_list", ToStringImpl(unit_list_));
  }
}

zetasql_base::Status ResolvedPrivilege::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedPrivilege::action_type not accessed)";
  }
  if ((accessed_ & (1<<1)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedPrivilege::unit_list not accessed)";
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedPrivilege::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
}

ResolvedGrantOrRevokeStmt::~ResolvedGrantOrRevokeStmt() {
}

zetasql_base::Status ResolvedGrantOrRevokeStmt::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedStatementProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_grant_or_revoke_stmt_node());
}

zetasql_base::Status ResolvedGrantOrRevokeStmt::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedGrantOrRevokeStmtProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  for (const auto& elem : privilege_list_) {
    ZETASQL_RETURN_IF_ERROR(elem->SaveTo(
      file_descriptor_set_map, proto->add_privilege_list()));
  }
  proto->set_object_type(object_type_);
  for (const auto& elem : name_path_) {
    proto->add_name_path(elem);
  }
  for (const auto& elem : grantee_list_) {
    proto->add_grantee_list(elem);
  }
  for (const auto& elem : grantee_expr_list_) {
    ZETASQL_RETURN_IF_ERROR(elem->SaveTo(
      file_descriptor_set_map, proto->add_grantee_expr_list()));
  }
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedGrantOrRevokeStmt>> ResolvedGrantOrRevokeStmt::RestoreFrom(
    const AnyResolvedGrantOrRevokeStmtProto& proto,
    const ResolvedNode::RestoreParams& params) {
  switch (proto.node_case()) {
    case AnyResolvedGrantOrRevokeStmtProto::kResolvedGrantStmtNode:
      return ResolvedGrantStmt::RestoreFrom(
          proto.resolved_grant_stmt_node(), params);
    case AnyResolvedGrantOrRevokeStmtProto::kResolvedRevokeStmtNode:
      return ResolvedRevokeStmt::RestoreFrom(
          proto.resolved_revoke_stmt_node(), params);
  case AnyResolvedGrantOrRevokeStmtProto::NODE_NOT_SET:
    return ::zetasql_base::InvalidArgumentErrorBuilder(ZETASQL_LOC)
        << "No subnode types set in ResolvedGrantOrRevokeStmtProto";
  }
}

void ResolvedGrantOrRevokeStmt::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
  for (const auto& elem : privilege_list_) {
    child_nodes->emplace_back(elem.get());
  }
  for (const auto& elem : grantee_expr_list_) {
    child_nodes->emplace_back(elem.get());
  }
}

void ResolvedGrantOrRevokeStmt::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
  for (auto& elem : privilege_list_) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(&elem));
  }
  for (auto& elem : grantee_expr_list_) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(&elem));
  }
}

zetasql_base::Status ResolvedGrantOrRevokeStmt::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedGrantOrRevokeStmt(this);
}

zetasql_base::Status ResolvedGrantOrRevokeStmt::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  for (const auto& elem : privilege_list_) {
    ZETASQL_RETURN_IF_ERROR(elem.get()->Accept(visitor));
  }
  for (const auto& elem : grantee_expr_list_) {
    ZETASQL_RETURN_IF_ERROR(elem.get()->Accept(visitor));
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedGrantOrRevokeStmt::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  if (!privilege_list_.empty()) {
    fields->emplace_back("privilege_list", privilege_list_);
  }
  {
    fields->emplace_back("object_type", ToStringImpl(object_type_));
  }
  {
    fields->emplace_back("name_path", ToStringImpl(name_path_));
  }
  if (!IsDefaultValue(grantee_list_)) {
    fields->emplace_back("grantee_list", ToStringCommaSeparated(grantee_list_));
  }
  if (!grantee_expr_list_.empty()) {
    fields->emplace_back("grantee_expr_list", grantee_expr_list_);
  }
}

zetasql_base::Status ResolvedGrantOrRevokeStmt::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedGrantOrRevokeStmt::privilege_list not accessed)";
  }
  if ((accessed_ & (1<<1)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedGrantOrRevokeStmt::object_type not accessed)";
  }
  if ((accessed_ & (1<<2)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedGrantOrRevokeStmt::name_path not accessed)";
  }
  if ((accessed_ & (1<<3)) == 0 &&
      !IsDefaultValue(grantee_list_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedGrantOrRevokeStmt::grantee_list not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<4)) == 0 &&
      !IsDefaultValue(grantee_expr_list_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedGrantOrRevokeStmt::grantee_expr_list not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<0)) != 0) {
    for (const auto& it : privilege_list_) ZETASQL_RETURN_IF_ERROR(it->CheckFieldsAccessed());
  }
  if ((accessed_ & (1<<4)) != 0) {
    for (const auto& it : grantee_expr_list_) ZETASQL_RETURN_IF_ERROR(it->CheckFieldsAccessed());
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedGrantOrRevokeStmt::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
  for (const auto& it : privilege_list_) it->ClearFieldsAccessed();
  for (const auto& it : grantee_expr_list_) it->ClearFieldsAccessed();
}

const ResolvedNodeKind ResolvedGrantStmt::TYPE;

ResolvedGrantStmt::~ResolvedGrantStmt() {
}

zetasql_base::Status ResolvedGrantStmt::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedGrantOrRevokeStmtProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_grant_stmt_node());
}

zetasql_base::Status ResolvedGrantStmt::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedGrantStmtProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedGrantStmt>> ResolvedGrantStmt::RestoreFrom(
    const ResolvedGrantStmtProto& proto,
    const ResolvedNode::RestoreParams& params) {
  std::vector<std::unique_ptr<const ResolvedOption>> hint_list;
  for (const auto& elem : proto.parent().parent().hint_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedOption> elem_restored,
                     ResolvedOption::RestoreFrom(elem, params));
    hint_list.push_back(std::move(elem_restored));
  }
  std::vector<std::unique_ptr<const ResolvedPrivilege>> privilege_list;
  for (const auto& elem : proto.parent().privilege_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedPrivilege> elem_restored,
                     ResolvedPrivilege::RestoreFrom(elem, params));
    privilege_list.push_back(std::move(elem_restored));
  }
  std::string object_type =
      proto.parent().object_type();
  std::vector<std::string> name_path;
  for (const auto& elem : proto.parent().name_path()) {
    name_path.push_back(elem);
  }
  std::vector<std::string> grantee_list;
  for (const auto& elem : proto.parent().grantee_list()) {
    grantee_list.push_back(elem);
  }
  std::vector<std::unique_ptr<const ResolvedExpr>> grantee_expr_list;
  for (const auto& elem : proto.parent().grantee_expr_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedExpr> elem_restored,
                     ResolvedExpr::RestoreFrom(elem, params));
    grantee_expr_list.push_back(std::move(elem_restored));
  }
  auto node = MakeResolvedGrantStmt(
      std::move(privilege_list),
      std::move(object_type),
      std::move(name_path),
      std::move(grantee_list),
      std::move(grantee_expr_list));

  node->set_hint_list(std::move(hint_list));
  return std::move(node);
}

zetasql_base::Status ResolvedGrantStmt::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedGrantStmt(this);
}

zetasql_base::Status ResolvedGrantStmt::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  return ::zetasql_base::OkStatus();
}

const ResolvedNodeKind ResolvedRevokeStmt::TYPE;

ResolvedRevokeStmt::~ResolvedRevokeStmt() {
}

zetasql_base::Status ResolvedRevokeStmt::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedGrantOrRevokeStmtProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_revoke_stmt_node());
}

zetasql_base::Status ResolvedRevokeStmt::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedRevokeStmtProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedRevokeStmt>> ResolvedRevokeStmt::RestoreFrom(
    const ResolvedRevokeStmtProto& proto,
    const ResolvedNode::RestoreParams& params) {
  std::vector<std::unique_ptr<const ResolvedOption>> hint_list;
  for (const auto& elem : proto.parent().parent().hint_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedOption> elem_restored,
                     ResolvedOption::RestoreFrom(elem, params));
    hint_list.push_back(std::move(elem_restored));
  }
  std::vector<std::unique_ptr<const ResolvedPrivilege>> privilege_list;
  for (const auto& elem : proto.parent().privilege_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedPrivilege> elem_restored,
                     ResolvedPrivilege::RestoreFrom(elem, params));
    privilege_list.push_back(std::move(elem_restored));
  }
  std::string object_type =
      proto.parent().object_type();
  std::vector<std::string> name_path;
  for (const auto& elem : proto.parent().name_path()) {
    name_path.push_back(elem);
  }
  std::vector<std::string> grantee_list;
  for (const auto& elem : proto.parent().grantee_list()) {
    grantee_list.push_back(elem);
  }
  std::vector<std::unique_ptr<const ResolvedExpr>> grantee_expr_list;
  for (const auto& elem : proto.parent().grantee_expr_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedExpr> elem_restored,
                     ResolvedExpr::RestoreFrom(elem, params));
    grantee_expr_list.push_back(std::move(elem_restored));
  }
  auto node = MakeResolvedRevokeStmt(
      std::move(privilege_list),
      std::move(object_type),
      std::move(name_path),
      std::move(grantee_list),
      std::move(grantee_expr_list));

  node->set_hint_list(std::move(hint_list));
  return std::move(node);
}

zetasql_base::Status ResolvedRevokeStmt::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedRevokeStmt(this);
}

zetasql_base::Status ResolvedRevokeStmt::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  return ::zetasql_base::OkStatus();
}

ResolvedAlterObjectStmt::~ResolvedAlterObjectStmt() {
}

zetasql_base::Status ResolvedAlterObjectStmt::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedStatementProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_alter_object_stmt_node());
}

zetasql_base::Status ResolvedAlterObjectStmt::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedAlterObjectStmtProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  for (const auto& elem : name_path_) {
    proto->add_name_path(elem);
  }
  for (const auto& elem : alter_action_list_) {
    ZETASQL_RETURN_IF_ERROR(elem->SaveTo(
      file_descriptor_set_map, proto->add_alter_action_list()));
  }
  proto->set_is_if_exists(is_if_exists_);
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedAlterObjectStmt>> ResolvedAlterObjectStmt::RestoreFrom(
    const AnyResolvedAlterObjectStmtProto& proto,
    const ResolvedNode::RestoreParams& params) {
  switch (proto.node_case()) {
    case AnyResolvedAlterObjectStmtProto::kResolvedAlterTableStmtNode:
      return ResolvedAlterTableStmt::RestoreFrom(
          proto.resolved_alter_table_stmt_node(), params);
    case AnyResolvedAlterObjectStmtProto::kResolvedAlterViewStmtNode:
      return ResolvedAlterViewStmt::RestoreFrom(
          proto.resolved_alter_view_stmt_node(), params);
    case AnyResolvedAlterObjectStmtProto::kResolvedAlterMaterializedViewStmtNode:
      return ResolvedAlterMaterializedViewStmt::RestoreFrom(
          proto.resolved_alter_materialized_view_stmt_node(), params);
  case AnyResolvedAlterObjectStmtProto::NODE_NOT_SET:
    return ::zetasql_base::InvalidArgumentErrorBuilder(ZETASQL_LOC)
        << "No subnode types set in ResolvedAlterObjectStmtProto";
  }
}

void ResolvedAlterObjectStmt::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
  for (const auto& elem : alter_action_list_) {
    child_nodes->emplace_back(elem.get());
  }
}

void ResolvedAlterObjectStmt::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
  for (auto& elem : alter_action_list_) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(&elem));
  }
}

zetasql_base::Status ResolvedAlterObjectStmt::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedAlterObjectStmt(this);
}

zetasql_base::Status ResolvedAlterObjectStmt::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  for (const auto& elem : alter_action_list_) {
    ZETASQL_RETURN_IF_ERROR(elem.get()->Accept(visitor));
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedAlterObjectStmt::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  {
    fields->emplace_back("name_path", ToStringImpl(name_path_));
  }
  if (!alter_action_list_.empty()) {
    fields->emplace_back("alter_action_list", alter_action_list_);
  }
  if (!IsDefaultValue(is_if_exists_)) {
    fields->emplace_back("is_if_exists", ToStringImpl(is_if_exists_));
  }
}

zetasql_base::Status ResolvedAlterObjectStmt::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedAlterObjectStmt::name_path not accessed)";
  }
  if ((accessed_ & (1<<1)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedAlterObjectStmt::alter_action_list not accessed)";
  }
  if ((accessed_ & (1<<2)) == 0 &&
      !IsDefaultValue(is_if_exists_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedAlterObjectStmt::is_if_exists not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<1)) != 0) {
    for (const auto& it : alter_action_list_) ZETASQL_RETURN_IF_ERROR(it->CheckFieldsAccessed());
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedAlterObjectStmt::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
  for (const auto& it : alter_action_list_) it->ClearFieldsAccessed();
}

const ResolvedNodeKind ResolvedAlterMaterializedViewStmt::TYPE;

ResolvedAlterMaterializedViewStmt::~ResolvedAlterMaterializedViewStmt() {
}

zetasql_base::Status ResolvedAlterMaterializedViewStmt::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedAlterObjectStmtProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_alter_materialized_view_stmt_node());
}

zetasql_base::Status ResolvedAlterMaterializedViewStmt::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedAlterMaterializedViewStmtProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedAlterMaterializedViewStmt>> ResolvedAlterMaterializedViewStmt::RestoreFrom(
    const ResolvedAlterMaterializedViewStmtProto& proto,
    const ResolvedNode::RestoreParams& params) {
  std::vector<std::unique_ptr<const ResolvedOption>> hint_list;
  for (const auto& elem : proto.parent().parent().hint_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedOption> elem_restored,
                     ResolvedOption::RestoreFrom(elem, params));
    hint_list.push_back(std::move(elem_restored));
  }
  std::vector<std::string> name_path;
  for (const auto& elem : proto.parent().name_path()) {
    name_path.push_back(elem);
  }
  std::vector<std::unique_ptr<const ResolvedAlterAction>> alter_action_list;
  for (const auto& elem : proto.parent().alter_action_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedAlterAction> elem_restored,
                     ResolvedAlterAction::RestoreFrom(elem, params));
    alter_action_list.push_back(std::move(elem_restored));
  }
  bool is_if_exists =
      proto.parent().is_if_exists();
  auto node = MakeResolvedAlterMaterializedViewStmt(
      std::move(name_path),
      std::move(alter_action_list),
      std::move(is_if_exists));

  node->set_hint_list(std::move(hint_list));
  return std::move(node);
}

zetasql_base::Status ResolvedAlterMaterializedViewStmt::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedAlterMaterializedViewStmt(this);
}

zetasql_base::Status ResolvedAlterMaterializedViewStmt::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  return ::zetasql_base::OkStatus();
}

const ResolvedNodeKind ResolvedAlterTableStmt::TYPE;

ResolvedAlterTableStmt::~ResolvedAlterTableStmt() {
}

zetasql_base::Status ResolvedAlterTableStmt::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedAlterObjectStmtProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_alter_table_stmt_node());
}

zetasql_base::Status ResolvedAlterTableStmt::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedAlterTableStmtProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedAlterTableStmt>> ResolvedAlterTableStmt::RestoreFrom(
    const ResolvedAlterTableStmtProto& proto,
    const ResolvedNode::RestoreParams& params) {
  std::vector<std::unique_ptr<const ResolvedOption>> hint_list;
  for (const auto& elem : proto.parent().parent().hint_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedOption> elem_restored,
                     ResolvedOption::RestoreFrom(elem, params));
    hint_list.push_back(std::move(elem_restored));
  }
  std::vector<std::string> name_path;
  for (const auto& elem : proto.parent().name_path()) {
    name_path.push_back(elem);
  }
  std::vector<std::unique_ptr<const ResolvedAlterAction>> alter_action_list;
  for (const auto& elem : proto.parent().alter_action_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedAlterAction> elem_restored,
                     ResolvedAlterAction::RestoreFrom(elem, params));
    alter_action_list.push_back(std::move(elem_restored));
  }
  bool is_if_exists =
      proto.parent().is_if_exists();
  auto node = MakeResolvedAlterTableStmt(
      std::move(name_path),
      std::move(alter_action_list),
      std::move(is_if_exists));

  node->set_hint_list(std::move(hint_list));
  return std::move(node);
}

zetasql_base::Status ResolvedAlterTableStmt::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedAlterTableStmt(this);
}

zetasql_base::Status ResolvedAlterTableStmt::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  return ::zetasql_base::OkStatus();
}

const ResolvedNodeKind ResolvedAlterViewStmt::TYPE;

ResolvedAlterViewStmt::~ResolvedAlterViewStmt() {
}

zetasql_base::Status ResolvedAlterViewStmt::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedAlterObjectStmtProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_alter_view_stmt_node());
}

zetasql_base::Status ResolvedAlterViewStmt::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedAlterViewStmtProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedAlterViewStmt>> ResolvedAlterViewStmt::RestoreFrom(
    const ResolvedAlterViewStmtProto& proto,
    const ResolvedNode::RestoreParams& params) {
  std::vector<std::unique_ptr<const ResolvedOption>> hint_list;
  for (const auto& elem : proto.parent().parent().hint_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedOption> elem_restored,
                     ResolvedOption::RestoreFrom(elem, params));
    hint_list.push_back(std::move(elem_restored));
  }
  std::vector<std::string> name_path;
  for (const auto& elem : proto.parent().name_path()) {
    name_path.push_back(elem);
  }
  std::vector<std::unique_ptr<const ResolvedAlterAction>> alter_action_list;
  for (const auto& elem : proto.parent().alter_action_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedAlterAction> elem_restored,
                     ResolvedAlterAction::RestoreFrom(elem, params));
    alter_action_list.push_back(std::move(elem_restored));
  }
  bool is_if_exists =
      proto.parent().is_if_exists();
  auto node = MakeResolvedAlterViewStmt(
      std::move(name_path),
      std::move(alter_action_list),
      std::move(is_if_exists));

  node->set_hint_list(std::move(hint_list));
  return std::move(node);
}

zetasql_base::Status ResolvedAlterViewStmt::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedAlterViewStmt(this);
}

zetasql_base::Status ResolvedAlterViewStmt::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  return ::zetasql_base::OkStatus();
}

ResolvedAlterAction::~ResolvedAlterAction() {
}

zetasql_base::Status ResolvedAlterAction::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedArgumentProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_alter_action_node());
}

zetasql_base::Status ResolvedAlterAction::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedAlterActionProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedAlterAction>> ResolvedAlterAction::RestoreFrom(
    const AnyResolvedAlterActionProto& proto,
    const ResolvedNode::RestoreParams& params) {
  switch (proto.node_case()) {
    case AnyResolvedAlterActionProto::kResolvedSetOptionsActionNode:
      return ResolvedSetOptionsAction::RestoreFrom(
          proto.resolved_set_options_action_node(), params);
  case AnyResolvedAlterActionProto::NODE_NOT_SET:
    return ::zetasql_base::InvalidArgumentErrorBuilder(ZETASQL_LOC)
        << "No subnode types set in ResolvedAlterActionProto";
  }
}

zetasql_base::Status ResolvedAlterAction::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedAlterAction(this);
}

zetasql_base::Status ResolvedAlterAction::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  return ::zetasql_base::OkStatus();
}

const ResolvedNodeKind ResolvedSetOptionsAction::TYPE;

ResolvedSetOptionsAction::~ResolvedSetOptionsAction() {
}

zetasql_base::Status ResolvedSetOptionsAction::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedAlterActionProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_set_options_action_node());
}

zetasql_base::Status ResolvedSetOptionsAction::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedSetOptionsActionProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  for (const auto& elem : option_list_) {
    ZETASQL_RETURN_IF_ERROR(elem->SaveTo(
      file_descriptor_set_map, proto->add_option_list()));
  }
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedSetOptionsAction>> ResolvedSetOptionsAction::RestoreFrom(
    const ResolvedSetOptionsActionProto& proto,
    const ResolvedNode::RestoreParams& params) {
  std::vector<std::unique_ptr<const ResolvedOption>> option_list;
  for (const auto& elem : proto.option_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedOption> elem_restored,
                     ResolvedOption::RestoreFrom(elem, params));
    option_list.push_back(std::move(elem_restored));
  }
  auto node = MakeResolvedSetOptionsAction(
      std::move(option_list));

  return std::move(node);
}

void ResolvedSetOptionsAction::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
  for (const auto& elem : option_list_) {
    child_nodes->emplace_back(elem.get());
  }
}

void ResolvedSetOptionsAction::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
  for (auto& elem : option_list_) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(&elem));
  }
}

zetasql_base::Status ResolvedSetOptionsAction::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedSetOptionsAction(this);
}

zetasql_base::Status ResolvedSetOptionsAction::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  for (const auto& elem : option_list_) {
    ZETASQL_RETURN_IF_ERROR(elem.get()->Accept(visitor));
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedSetOptionsAction::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  if (!option_list_.empty()) {
    fields->emplace_back("option_list", option_list_);
  }
}

zetasql_base::Status ResolvedSetOptionsAction::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedSetOptionsAction::option_list not accessed)";
  }
  if ((accessed_ & (1<<0)) != 0) {
    for (const auto& it : option_list_) ZETASQL_RETURN_IF_ERROR(it->CheckFieldsAccessed());
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedSetOptionsAction::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
  for (const auto& it : option_list_) it->ClearFieldsAccessed();
}

const ResolvedNodeKind ResolvedAlterTableSetOptionsStmt::TYPE;

ResolvedAlterTableSetOptionsStmt::~ResolvedAlterTableSetOptionsStmt() {
}

zetasql_base::Status ResolvedAlterTableSetOptionsStmt::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedStatementProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_alter_table_set_options_stmt_node());
}

zetasql_base::Status ResolvedAlterTableSetOptionsStmt::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedAlterTableSetOptionsStmtProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  for (const auto& elem : name_path_) {
    proto->add_name_path(elem);
  }
  for (const auto& elem : option_list_) {
    ZETASQL_RETURN_IF_ERROR(elem->SaveTo(
      file_descriptor_set_map, proto->add_option_list()));
  }
  proto->set_is_if_exists(is_if_exists_);
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedAlterTableSetOptionsStmt>> ResolvedAlterTableSetOptionsStmt::RestoreFrom(
    const ResolvedAlterTableSetOptionsStmtProto& proto,
    const ResolvedNode::RestoreParams& params) {
  std::vector<std::string> name_path;
  for (const auto& elem : proto.name_path()) {
    name_path.push_back(elem);
  }
  std::vector<std::unique_ptr<const ResolvedOption>> option_list;
  for (const auto& elem : proto.option_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedOption> elem_restored,
                     ResolvedOption::RestoreFrom(elem, params));
    option_list.push_back(std::move(elem_restored));
  }
  bool is_if_exists =
      proto.is_if_exists();
  std::vector<std::unique_ptr<const ResolvedOption>> hint_list;
  for (const auto& elem : proto.parent().hint_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedOption> elem_restored,
                     ResolvedOption::RestoreFrom(elem, params));
    hint_list.push_back(std::move(elem_restored));
  }
  auto node = MakeResolvedAlterTableSetOptionsStmt(
      std::move(name_path),
      std::move(option_list),
      std::move(is_if_exists));

  node->set_hint_list(std::move(hint_list));
  return std::move(node);
}

void ResolvedAlterTableSetOptionsStmt::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
  for (const auto& elem : option_list_) {
    child_nodes->emplace_back(elem.get());
  }
}

void ResolvedAlterTableSetOptionsStmt::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
  for (auto& elem : option_list_) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(&elem));
  }
}

zetasql_base::Status ResolvedAlterTableSetOptionsStmt::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedAlterTableSetOptionsStmt(this);
}

zetasql_base::Status ResolvedAlterTableSetOptionsStmt::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  for (const auto& elem : option_list_) {
    ZETASQL_RETURN_IF_ERROR(elem.get()->Accept(visitor));
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedAlterTableSetOptionsStmt::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  {
    fields->emplace_back("name_path", ToStringImpl(name_path_));
  }
  if (!option_list_.empty()) {
    fields->emplace_back("option_list", option_list_);
  }
  if (!IsDefaultValue(is_if_exists_)) {
    fields->emplace_back("is_if_exists", ToStringImpl(is_if_exists_));
  }
}

zetasql_base::Status ResolvedAlterTableSetOptionsStmt::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedAlterTableSetOptionsStmt::name_path not accessed)";
  }
  if ((accessed_ & (1<<1)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedAlterTableSetOptionsStmt::option_list not accessed)";
  }
  if ((accessed_ & (1<<2)) == 0 &&
      !IsDefaultValue(is_if_exists_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedAlterTableSetOptionsStmt::is_if_exists not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<1)) != 0) {
    for (const auto& it : option_list_) ZETASQL_RETURN_IF_ERROR(it->CheckFieldsAccessed());
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedAlterTableSetOptionsStmt::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
  for (const auto& it : option_list_) it->ClearFieldsAccessed();
}

const ResolvedNodeKind ResolvedRenameStmt::TYPE;

ResolvedRenameStmt::~ResolvedRenameStmt() {
}

zetasql_base::Status ResolvedRenameStmt::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedStatementProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_rename_stmt_node());
}

zetasql_base::Status ResolvedRenameStmt::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedRenameStmtProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  proto->set_object_type(object_type_);
  for (const auto& elem : old_name_path_) {
    proto->add_old_name_path(elem);
  }
  for (const auto& elem : new_name_path_) {
    proto->add_new_name_path(elem);
  }
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedRenameStmt>> ResolvedRenameStmt::RestoreFrom(
    const ResolvedRenameStmtProto& proto,
    const ResolvedNode::RestoreParams& params) {
  std::string object_type =
      proto.object_type();
  std::vector<std::string> old_name_path;
  for (const auto& elem : proto.old_name_path()) {
    old_name_path.push_back(elem);
  }
  std::vector<std::string> new_name_path;
  for (const auto& elem : proto.new_name_path()) {
    new_name_path.push_back(elem);
  }
  std::vector<std::unique_ptr<const ResolvedOption>> hint_list;
  for (const auto& elem : proto.parent().hint_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedOption> elem_restored,
                     ResolvedOption::RestoreFrom(elem, params));
    hint_list.push_back(std::move(elem_restored));
  }
  auto node = MakeResolvedRenameStmt(
      std::move(object_type),
      std::move(old_name_path),
      std::move(new_name_path));

  node->set_hint_list(std::move(hint_list));
  return std::move(node);
}

void ResolvedRenameStmt::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
}

void ResolvedRenameStmt::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
}

zetasql_base::Status ResolvedRenameStmt::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedRenameStmt(this);
}

zetasql_base::Status ResolvedRenameStmt::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  return ::zetasql_base::OkStatus();
}

void ResolvedRenameStmt::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  {
    fields->emplace_back("object_type", ToStringImpl(object_type_));
  }
  {
    fields->emplace_back("old_name_path", ToStringImpl(old_name_path_));
  }
  {
    fields->emplace_back("new_name_path", ToStringImpl(new_name_path_));
  }
}

zetasql_base::Status ResolvedRenameStmt::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedRenameStmt::object_type not accessed)";
  }
  if ((accessed_ & (1<<1)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedRenameStmt::old_name_path not accessed)";
  }
  if ((accessed_ & (1<<2)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedRenameStmt::new_name_path not accessed)";
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedRenameStmt::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
}

const ResolvedNodeKind ResolvedCreateRowPolicyStmt::TYPE;

ResolvedCreateRowPolicyStmt::~ResolvedCreateRowPolicyStmt() {
}

zetasql_base::Status ResolvedCreateRowPolicyStmt::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedStatementProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_create_row_policy_stmt_node());
}

zetasql_base::Status ResolvedCreateRowPolicyStmt::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedCreateRowPolicyStmtProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  proto->set_create_mode(create_mode_);
  proto->set_name(name_);
  for (const auto& elem : target_name_path_) {
    proto->add_target_name_path(elem);
  }
  for (const auto& elem : grantee_list_) {
    proto->add_grantee_list(elem);
  }
  for (const auto& elem : grantee_expr_list_) {
    ZETASQL_RETURN_IF_ERROR(elem->SaveTo(
      file_descriptor_set_map, proto->add_grantee_expr_list()));
  }
  if (table_scan_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(table_scan_->SaveTo(
        file_descriptor_set_map, proto->mutable_table_scan()));
  }
  if (predicate_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(predicate_->SaveTo(
        file_descriptor_set_map, proto->mutable_predicate()));
  }
  proto->set_predicate_str(predicate_str_);
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedCreateRowPolicyStmt>> ResolvedCreateRowPolicyStmt::RestoreFrom(
    const ResolvedCreateRowPolicyStmtProto& proto,
    const ResolvedNode::RestoreParams& params) {
  CreateMode create_mode =
      proto.create_mode();
  std::string name =
      proto.name();
  std::vector<std::string> target_name_path;
  for (const auto& elem : proto.target_name_path()) {
    target_name_path.push_back(elem);
  }
  std::vector<std::string> grantee_list;
  for (const auto& elem : proto.grantee_list()) {
    grantee_list.push_back(elem);
  }
  std::vector<std::unique_ptr<const ResolvedExpr>> grantee_expr_list;
  for (const auto& elem : proto.grantee_expr_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedExpr> elem_restored,
                     ResolvedExpr::RestoreFrom(elem, params));
    grantee_expr_list.push_back(std::move(elem_restored));
  }
  std::unique_ptr<const ResolvedTableScan> table_scan;
  if (proto.
  has_table_scan()) {
    ZETASQL_ASSIGN_OR_RETURN(table_scan,
                     ResolvedTableScan::RestoreFrom(
                         proto.table_scan(), params));
  }
  std::unique_ptr<const ResolvedExpr> predicate;
  if (proto.
  has_predicate()) {
    ZETASQL_ASSIGN_OR_RETURN(predicate,
                     ResolvedExpr::RestoreFrom(
                         proto.predicate(), params));
  }
  std::string predicate_str =
      proto.predicate_str();
  std::vector<std::unique_ptr<const ResolvedOption>> hint_list;
  for (const auto& elem : proto.parent().hint_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedOption> elem_restored,
                     ResolvedOption::RestoreFrom(elem, params));
    hint_list.push_back(std::move(elem_restored));
  }
  auto node = MakeResolvedCreateRowPolicyStmt(
      std::move(create_mode),
      std::move(name),
      std::move(target_name_path),
      std::move(grantee_list),
      std::move(grantee_expr_list),
      std::move(table_scan),
      std::move(predicate),
      std::move(predicate_str));

  node->set_hint_list(std::move(hint_list));
  return std::move(node);
}

void ResolvedCreateRowPolicyStmt::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
  for (const auto& elem : grantee_expr_list_) {
    child_nodes->emplace_back(elem.get());
  }
  if (table_scan_ != nullptr) {
    child_nodes->emplace_back(table_scan_.get());
  }
  if (predicate_ != nullptr) {
    child_nodes->emplace_back(predicate_.get());
  }
}

void ResolvedCreateRowPolicyStmt::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
  for (auto& elem : grantee_expr_list_) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(&elem));
  }
  if (table_scan_ != nullptr) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(
            &table_scan_));
    static_assert(sizeof(table_scan_) ==
                  sizeof(*(mutable_child_node_ptrs->back())),
                  "Incorrect casting of mutable child node");
  }
  if (predicate_ != nullptr) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(
            &predicate_));
    static_assert(sizeof(predicate_) ==
                  sizeof(*(mutable_child_node_ptrs->back())),
                  "Incorrect casting of mutable child node");
  }
}

zetasql_base::Status ResolvedCreateRowPolicyStmt::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedCreateRowPolicyStmt(this);
}

zetasql_base::Status ResolvedCreateRowPolicyStmt::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  for (const auto& elem : grantee_expr_list_) {
    ZETASQL_RETURN_IF_ERROR(elem.get()->Accept(visitor));
  }
  if (table_scan_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(table_scan_.get()->Accept(visitor));
  }
  if (predicate_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(predicate_.get()->Accept(visitor));
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedCreateRowPolicyStmt::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  if (!IsDefaultValue(create_mode_)) {
    fields->emplace_back("create_mode", ToStringImpl(create_mode_));
  }
  if (!IsDefaultValue(name_)) {
    fields->emplace_back("name", ToStringImpl(name_));
  }
  {
    fields->emplace_back("target_name_path", ToStringImpl(target_name_path_));
  }
  if (!IsDefaultValue(grantee_list_)) {
    fields->emplace_back("grantee_list", ToStringCommaSeparated(grantee_list_));
  }
  if (!grantee_expr_list_.empty()) {
    fields->emplace_back("grantee_expr_list", grantee_expr_list_);
  }
  if (table_scan_ != nullptr) {
    fields->emplace_back("table_scan", table_scan_.get());
  }
  if (predicate_ != nullptr) {
    fields->emplace_back("predicate", predicate_.get());
  }
  if (!IsDefaultValue(predicate_str_)) {
    fields->emplace_back("predicate_str", ToStringImpl(predicate_str_));
  }
}

zetasql_base::Status ResolvedCreateRowPolicyStmt::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0 &&
      !IsDefaultValue(create_mode_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedCreateRowPolicyStmt::create_mode not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<1)) == 0 &&
      !IsDefaultValue(name_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedCreateRowPolicyStmt::name not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<2)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedCreateRowPolicyStmt::target_name_path not accessed)";
  }
  if ((accessed_ & (1<<3)) == 0 &&
      !IsDefaultValue(grantee_list_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedCreateRowPolicyStmt::grantee_list not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<4)) == 0 &&
      !IsDefaultValue(grantee_expr_list_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedCreateRowPolicyStmt::grantee_expr_list not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<4)) != 0) {
    for (const auto& it : grantee_expr_list_) ZETASQL_RETURN_IF_ERROR(it->CheckFieldsAccessed());
  }
  if ((accessed_ & (1<<5)) != 0) {
    if (table_scan_ != nullptr) {
      ZETASQL_RETURN_IF_ERROR(table_scan_->CheckFieldsAccessed());
    }
  }
  if ((accessed_ & (1<<6)) != 0) {
    if (predicate_ != nullptr) {
      ZETASQL_RETURN_IF_ERROR(predicate_->CheckFieldsAccessed());
    }
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedCreateRowPolicyStmt::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
  for (const auto& it : grantee_expr_list_) it->ClearFieldsAccessed();
  if (table_scan_ != nullptr) table_scan_->ClearFieldsAccessed();
  if (predicate_ != nullptr) predicate_->ClearFieldsAccessed();
}

const ResolvedNodeKind ResolvedDropRowPolicyStmt::TYPE;

ResolvedDropRowPolicyStmt::~ResolvedDropRowPolicyStmt() {
}

zetasql_base::Status ResolvedDropRowPolicyStmt::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedStatementProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_drop_row_policy_stmt_node());
}

zetasql_base::Status ResolvedDropRowPolicyStmt::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedDropRowPolicyStmtProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  proto->set_is_drop_all(is_drop_all_);
  proto->set_is_if_exists(is_if_exists_);
  proto->set_name(name_);
  for (const auto& elem : target_name_path_) {
    proto->add_target_name_path(elem);
  }
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedDropRowPolicyStmt>> ResolvedDropRowPolicyStmt::RestoreFrom(
    const ResolvedDropRowPolicyStmtProto& proto,
    const ResolvedNode::RestoreParams& params) {
  bool is_drop_all =
      proto.is_drop_all();
  bool is_if_exists =
      proto.is_if_exists();
  std::string name =
      proto.name();
  std::vector<std::string> target_name_path;
  for (const auto& elem : proto.target_name_path()) {
    target_name_path.push_back(elem);
  }
  std::vector<std::unique_ptr<const ResolvedOption>> hint_list;
  for (const auto& elem : proto.parent().hint_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedOption> elem_restored,
                     ResolvedOption::RestoreFrom(elem, params));
    hint_list.push_back(std::move(elem_restored));
  }
  auto node = MakeResolvedDropRowPolicyStmt(
      std::move(is_drop_all),
      std::move(is_if_exists),
      std::move(name),
      std::move(target_name_path));

  node->set_hint_list(std::move(hint_list));
  return std::move(node);
}

void ResolvedDropRowPolicyStmt::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
}

void ResolvedDropRowPolicyStmt::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
}

zetasql_base::Status ResolvedDropRowPolicyStmt::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedDropRowPolicyStmt(this);
}

zetasql_base::Status ResolvedDropRowPolicyStmt::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  return ::zetasql_base::OkStatus();
}

void ResolvedDropRowPolicyStmt::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  if (!IsDefaultValue(is_drop_all_)) {
    fields->emplace_back("is_drop_all", ToStringImpl(is_drop_all_));
  }
  if (!IsDefaultValue(is_if_exists_)) {
    fields->emplace_back("is_if_exists", ToStringImpl(is_if_exists_));
  }
  if (!IsDefaultValue(name_)) {
    fields->emplace_back("name", ToStringImpl(name_));
  }
  {
    fields->emplace_back("target_name_path", ToStringImpl(target_name_path_));
  }
}

zetasql_base::Status ResolvedDropRowPolicyStmt::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0 &&
      !IsDefaultValue(is_drop_all_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedDropRowPolicyStmt::is_drop_all not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<1)) == 0 &&
      !IsDefaultValue(is_if_exists_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedDropRowPolicyStmt::is_if_exists not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<2)) == 0 &&
      !IsDefaultValue(name_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedDropRowPolicyStmt::name not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<3)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedDropRowPolicyStmt::target_name_path not accessed)";
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedDropRowPolicyStmt::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
}

const ResolvedNodeKind ResolvedAlterRowPolicyStmt::TYPE;

ResolvedAlterRowPolicyStmt::~ResolvedAlterRowPolicyStmt() {
}

zetasql_base::Status ResolvedAlterRowPolicyStmt::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedStatementProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_alter_row_policy_stmt_node());
}

zetasql_base::Status ResolvedAlterRowPolicyStmt::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedAlterRowPolicyStmtProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  proto->set_name(name_);
  proto->set_new_name(new_name_);
  for (const auto& elem : target_name_path_) {
    proto->add_target_name_path(elem);
  }
  for (const auto& elem : grantee_list_) {
    proto->add_grantee_list(elem);
  }
  for (const auto& elem : grantee_expr_list_) {
    ZETASQL_RETURN_IF_ERROR(elem->SaveTo(
      file_descriptor_set_map, proto->add_grantee_expr_list()));
  }
  if (table_scan_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(table_scan_->SaveTo(
        file_descriptor_set_map, proto->mutable_table_scan()));
  }
  if (predicate_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(predicate_->SaveTo(
        file_descriptor_set_map, proto->mutable_predicate()));
  }
  proto->set_predicate_str(predicate_str_);
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedAlterRowPolicyStmt>> ResolvedAlterRowPolicyStmt::RestoreFrom(
    const ResolvedAlterRowPolicyStmtProto& proto,
    const ResolvedNode::RestoreParams& params) {
  std::string name =
      proto.name();
  std::string new_name =
      proto.new_name();
  std::vector<std::string> target_name_path;
  for (const auto& elem : proto.target_name_path()) {
    target_name_path.push_back(elem);
  }
  std::vector<std::string> grantee_list;
  for (const auto& elem : proto.grantee_list()) {
    grantee_list.push_back(elem);
  }
  std::vector<std::unique_ptr<const ResolvedExpr>> grantee_expr_list;
  for (const auto& elem : proto.grantee_expr_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedExpr> elem_restored,
                     ResolvedExpr::RestoreFrom(elem, params));
    grantee_expr_list.push_back(std::move(elem_restored));
  }
  std::unique_ptr<const ResolvedTableScan> table_scan;
  if (proto.
  has_table_scan()) {
    ZETASQL_ASSIGN_OR_RETURN(table_scan,
                     ResolvedTableScan::RestoreFrom(
                         proto.table_scan(), params));
  }
  std::unique_ptr<const ResolvedExpr> predicate;
  if (proto.
  has_predicate()) {
    ZETASQL_ASSIGN_OR_RETURN(predicate,
                     ResolvedExpr::RestoreFrom(
                         proto.predicate(), params));
  }
  std::string predicate_str =
      proto.predicate_str();
  std::vector<std::unique_ptr<const ResolvedOption>> hint_list;
  for (const auto& elem : proto.parent().hint_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedOption> elem_restored,
                     ResolvedOption::RestoreFrom(elem, params));
    hint_list.push_back(std::move(elem_restored));
  }
  auto node = MakeResolvedAlterRowPolicyStmt(
      std::move(name),
      std::move(new_name),
      std::move(target_name_path),
      std::move(grantee_list),
      std::move(grantee_expr_list),
      std::move(table_scan),
      std::move(predicate),
      std::move(predicate_str));

  node->set_hint_list(std::move(hint_list));
  return std::move(node);
}

void ResolvedAlterRowPolicyStmt::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
  for (const auto& elem : grantee_expr_list_) {
    child_nodes->emplace_back(elem.get());
  }
  if (table_scan_ != nullptr) {
    child_nodes->emplace_back(table_scan_.get());
  }
  if (predicate_ != nullptr) {
    child_nodes->emplace_back(predicate_.get());
  }
}

void ResolvedAlterRowPolicyStmt::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
  for (auto& elem : grantee_expr_list_) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(&elem));
  }
  if (table_scan_ != nullptr) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(
            &table_scan_));
    static_assert(sizeof(table_scan_) ==
                  sizeof(*(mutable_child_node_ptrs->back())),
                  "Incorrect casting of mutable child node");
  }
  if (predicate_ != nullptr) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(
            &predicate_));
    static_assert(sizeof(predicate_) ==
                  sizeof(*(mutable_child_node_ptrs->back())),
                  "Incorrect casting of mutable child node");
  }
}

zetasql_base::Status ResolvedAlterRowPolicyStmt::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedAlterRowPolicyStmt(this);
}

zetasql_base::Status ResolvedAlterRowPolicyStmt::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  for (const auto& elem : grantee_expr_list_) {
    ZETASQL_RETURN_IF_ERROR(elem.get()->Accept(visitor));
  }
  if (table_scan_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(table_scan_.get()->Accept(visitor));
  }
  if (predicate_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(predicate_.get()->Accept(visitor));
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedAlterRowPolicyStmt::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  {
    fields->emplace_back("name", ToStringImpl(name_));
  }
  if (!IsDefaultValue(new_name_)) {
    fields->emplace_back("new_name", ToStringImpl(new_name_));
  }
  {
    fields->emplace_back("target_name_path", ToStringImpl(target_name_path_));
  }
  if (!IsDefaultValue(grantee_list_)) {
    fields->emplace_back("grantee_list", ToStringCommaSeparated(grantee_list_));
  }
  if (!grantee_expr_list_.empty()) {
    fields->emplace_back("grantee_expr_list", grantee_expr_list_);
  }
  if (table_scan_ != nullptr) {
    fields->emplace_back("table_scan", table_scan_.get());
  }
  if (predicate_ != nullptr) {
    fields->emplace_back("predicate", predicate_.get());
  }
  if (!IsDefaultValue(predicate_str_)) {
    fields->emplace_back("predicate_str", ToStringImpl(predicate_str_));
  }
}

zetasql_base::Status ResolvedAlterRowPolicyStmt::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedAlterRowPolicyStmt::name not accessed)";
  }
  if ((accessed_ & (1<<1)) == 0 &&
      !IsDefaultValue(new_name_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedAlterRowPolicyStmt::new_name not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<2)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedAlterRowPolicyStmt::target_name_path not accessed)";
  }
  if ((accessed_ & (1<<3)) == 0 &&
      !IsDefaultValue(grantee_list_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedAlterRowPolicyStmt::grantee_list not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<4)) == 0 &&
      !IsDefaultValue(grantee_expr_list_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedAlterRowPolicyStmt::grantee_expr_list not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<4)) != 0) {
    for (const auto& it : grantee_expr_list_) ZETASQL_RETURN_IF_ERROR(it->CheckFieldsAccessed());
  }
  if ((accessed_ & (1<<5)) != 0) {
    if (table_scan_ != nullptr) {
      ZETASQL_RETURN_IF_ERROR(table_scan_->CheckFieldsAccessed());
    }
  }
  if ((accessed_ & (1<<6)) != 0) {
    if (predicate_ != nullptr) {
      ZETASQL_RETURN_IF_ERROR(predicate_->CheckFieldsAccessed());
    }
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedAlterRowPolicyStmt::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
  for (const auto& it : grantee_expr_list_) it->ClearFieldsAccessed();
  if (table_scan_ != nullptr) table_scan_->ClearFieldsAccessed();
  if (predicate_ != nullptr) predicate_->ClearFieldsAccessed();
}

const ResolvedNodeKind ResolvedCreateConstantStmt::TYPE;

ResolvedCreateConstantStmt::~ResolvedCreateConstantStmt() {
}

zetasql_base::Status ResolvedCreateConstantStmt::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedCreateStatementProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_create_constant_stmt_node());
}

zetasql_base::Status ResolvedCreateConstantStmt::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedCreateConstantStmtProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  if (expr_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(expr_->SaveTo(
        file_descriptor_set_map, proto->mutable_expr()));
  }
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedCreateConstantStmt>> ResolvedCreateConstantStmt::RestoreFrom(
    const ResolvedCreateConstantStmtProto& proto,
    const ResolvedNode::RestoreParams& params) {
  std::unique_ptr<const ResolvedExpr> expr;
  if (proto.
  has_expr()) {
    ZETASQL_ASSIGN_OR_RETURN(expr,
                     ResolvedExpr::RestoreFrom(
                         proto.expr(), params));
  }
  std::vector<std::unique_ptr<const ResolvedOption>> hint_list;
  for (const auto& elem : proto.parent().parent().hint_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedOption> elem_restored,
                     ResolvedOption::RestoreFrom(elem, params));
    hint_list.push_back(std::move(elem_restored));
  }
  std::vector<std::string> name_path;
  for (const auto& elem : proto.parent().name_path()) {
    name_path.push_back(elem);
  }
  CreateScope create_scope =
      proto.parent().create_scope();
  CreateMode create_mode =
      proto.parent().create_mode();
  auto node = MakeResolvedCreateConstantStmt(
      std::move(name_path),
      std::move(create_scope),
      std::move(create_mode),
      std::move(expr));

  node->set_hint_list(std::move(hint_list));
  return std::move(node);
}

void ResolvedCreateConstantStmt::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
  if (expr_ != nullptr) {
    child_nodes->emplace_back(expr_.get());
  }
}

void ResolvedCreateConstantStmt::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
  if (expr_ != nullptr) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(
            &expr_));
    static_assert(sizeof(expr_) ==
                  sizeof(*(mutable_child_node_ptrs->back())),
                  "Incorrect casting of mutable child node");
  }
}

zetasql_base::Status ResolvedCreateConstantStmt::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedCreateConstantStmt(this);
}

zetasql_base::Status ResolvedCreateConstantStmt::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  if (expr_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(expr_.get()->Accept(visitor));
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedCreateConstantStmt::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  if (expr_ != nullptr) {
    fields->emplace_back("expr", expr_.get());
  }
}

zetasql_base::Status ResolvedCreateConstantStmt::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedCreateConstantStmt::expr not accessed)";
  }
  if ((accessed_ & (1<<0)) != 0) {
    if (expr_ != nullptr) {
      ZETASQL_RETURN_IF_ERROR(expr_->CheckFieldsAccessed());
    }
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedCreateConstantStmt::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
  if (expr_ != nullptr) expr_->ClearFieldsAccessed();
}

const ResolvedNodeKind ResolvedCreateFunctionStmt::TYPE;

ResolvedCreateFunctionStmt::~ResolvedCreateFunctionStmt() {
}

zetasql_base::Status ResolvedCreateFunctionStmt::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedCreateStatementProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_create_function_stmt_node());
}

zetasql_base::Status ResolvedCreateFunctionStmt::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedCreateFunctionStmtProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  proto->set_has_explicit_return_type(has_explicit_return_type_);
  ZETASQL_RETURN_IF_ERROR(SaveToImpl(
      return_type_, file_descriptor_set_map,
      proto->mutable_return_type()));
  for (const auto& elem : argument_name_list_) {
    proto->add_argument_name_list(elem);
  }
  ZETASQL_RETURN_IF_ERROR(SaveToImpl(
      signature_, file_descriptor_set_map,
      proto->mutable_signature()));
  proto->set_is_aggregate(is_aggregate_);
  proto->set_language(language_);
  proto->set_code(code_);
  for (const auto& elem : aggregate_expression_list_) {
    ZETASQL_RETURN_IF_ERROR(elem->SaveTo(
      file_descriptor_set_map, proto->add_aggregate_expression_list()));
  }
  if (function_expression_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(function_expression_->SaveTo(
        file_descriptor_set_map, proto->mutable_function_expression()));
  }
  for (const auto& elem : option_list_) {
    ZETASQL_RETURN_IF_ERROR(elem->SaveTo(
      file_descriptor_set_map, proto->add_option_list()));
  }
  proto->set_sql_security(sql_security_);
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedCreateFunctionStmt>> ResolvedCreateFunctionStmt::RestoreFrom(
    const ResolvedCreateFunctionStmtProto& proto,
    const ResolvedNode::RestoreParams& params) {
  bool has_explicit_return_type =
      proto.has_explicit_return_type();
  ZETASQL_ASSIGN_OR_RETURN(const Type* return_type,
                   RestoreFromImpl(proto.return_type(),
                                   params));
  std::vector<std::string> argument_name_list;
  for (const auto& elem : proto.argument_name_list()) {
    argument_name_list.push_back(elem);
  }
  ZETASQL_ASSIGN_OR_RETURN(FunctionSignature signature,
                   RestoreFromImpl(proto.signature(),
                                   params));
  bool is_aggregate =
      proto.is_aggregate();
  std::string language =
      proto.language();
  std::string code =
      proto.code();
  std::vector<std::unique_ptr<const ResolvedComputedColumn>> aggregate_expression_list;
  for (const auto& elem : proto.aggregate_expression_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedComputedColumn> elem_restored,
                     ResolvedComputedColumn::RestoreFrom(elem, params));
    aggregate_expression_list.push_back(std::move(elem_restored));
  }
  std::unique_ptr<const ResolvedExpr> function_expression;
  if (proto.
  has_function_expression()) {
    ZETASQL_ASSIGN_OR_RETURN(function_expression,
                     ResolvedExpr::RestoreFrom(
                         proto.function_expression(), params));
  }
  std::vector<std::unique_ptr<const ResolvedOption>> option_list;
  for (const auto& elem : proto.option_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedOption> elem_restored,
                     ResolvedOption::RestoreFrom(elem, params));
    option_list.push_back(std::move(elem_restored));
  }
  SqlSecurity sql_security =
      proto.sql_security();
  std::vector<std::unique_ptr<const ResolvedOption>> hint_list;
  for (const auto& elem : proto.parent().parent().hint_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedOption> elem_restored,
                     ResolvedOption::RestoreFrom(elem, params));
    hint_list.push_back(std::move(elem_restored));
  }
  std::vector<std::string> name_path;
  for (const auto& elem : proto.parent().name_path()) {
    name_path.push_back(elem);
  }
  CreateScope create_scope =
      proto.parent().create_scope();
  CreateMode create_mode =
      proto.parent().create_mode();
  auto node = MakeResolvedCreateFunctionStmt(
      std::move(name_path),
      std::move(create_scope),
      std::move(create_mode),
      std::move(has_explicit_return_type),
      std::move(return_type),
      std::move(argument_name_list),
      std::move(signature),
      std::move(is_aggregate),
      std::move(language),
      std::move(code),
      std::move(aggregate_expression_list),
      std::move(function_expression),
      std::move(option_list),
      std::move(sql_security));

  node->set_hint_list(std::move(hint_list));
  return std::move(node);
}

void ResolvedCreateFunctionStmt::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
  for (const auto& elem : aggregate_expression_list_) {
    child_nodes->emplace_back(elem.get());
  }
  if (function_expression_ != nullptr) {
    child_nodes->emplace_back(function_expression_.get());
  }
  for (const auto& elem : option_list_) {
    child_nodes->emplace_back(elem.get());
  }
}

void ResolvedCreateFunctionStmt::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
  for (auto& elem : aggregate_expression_list_) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(&elem));
  }
  if (function_expression_ != nullptr) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(
            &function_expression_));
    static_assert(sizeof(function_expression_) ==
                  sizeof(*(mutable_child_node_ptrs->back())),
                  "Incorrect casting of mutable child node");
  }
  for (auto& elem : option_list_) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(&elem));
  }
}

zetasql_base::Status ResolvedCreateFunctionStmt::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedCreateFunctionStmt(this);
}

zetasql_base::Status ResolvedCreateFunctionStmt::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  for (const auto& elem : aggregate_expression_list_) {
    ZETASQL_RETURN_IF_ERROR(elem.get()->Accept(visitor));
  }
  if (function_expression_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(function_expression_.get()->Accept(visitor));
  }
  for (const auto& elem : option_list_) {
    ZETASQL_RETURN_IF_ERROR(elem.get()->Accept(visitor));
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedCreateFunctionStmt::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  if (!IsDefaultValue(has_explicit_return_type_)) {
    fields->emplace_back("has_explicit_return_type", ToStringImpl(has_explicit_return_type_));
  }
  if (!IsDefaultValue(return_type_)) {
    fields->emplace_back("return_type", ToStringImpl(return_type_));
  }
  if (!IsDefaultValue(argument_name_list_)) {
    fields->emplace_back("argument_name_list", ToStringCommaSeparated(argument_name_list_));
  }
  if (!IsDefaultValue(signature_)) {
    fields->emplace_back("signature", ToStringVerbose(signature_));
  }
  if (!IsDefaultValue(is_aggregate_)) {
    fields->emplace_back("is_aggregate", ToStringImpl(is_aggregate_));
  }
  if (!IsDefaultValue(language_)) {
    fields->emplace_back("language", ToStringImpl(language_));
  }
  if (!IsDefaultValue(code_)) {
    fields->emplace_back("code", ToStringImpl(code_));
  }
  if (!aggregate_expression_list_.empty()) {
    fields->emplace_back("aggregate_expression_list", aggregate_expression_list_);
  }
  if (function_expression_ != nullptr) {
    fields->emplace_back("function_expression", function_expression_.get());
  }
  if (!option_list_.empty()) {
    fields->emplace_back("option_list", option_list_);
  }
  if (!IsDefaultValue(sql_security_)) {
    fields->emplace_back("sql_security", ToStringImpl(sql_security_));
  }
}

zetasql_base::Status ResolvedCreateFunctionStmt::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<4)) == 0 &&
      !IsDefaultValue(is_aggregate_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedCreateFunctionStmt::is_aggregate not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<5)) == 0 &&
      !IsDefaultValue(language_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedCreateFunctionStmt::language not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<7)) == 0 &&
      !IsDefaultValue(aggregate_expression_list_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedCreateFunctionStmt::aggregate_expression_list not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<9)) == 0 &&
      !IsDefaultValue(option_list_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedCreateFunctionStmt::option_list not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<10)) == 0 &&
      !IsDefaultValue(sql_security_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedCreateFunctionStmt::sql_security not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<7)) != 0) {
    for (const auto& it : aggregate_expression_list_) ZETASQL_RETURN_IF_ERROR(it->CheckFieldsAccessed());
  }
  if ((accessed_ & (1<<8)) != 0) {
    if (function_expression_ != nullptr) {
      ZETASQL_RETURN_IF_ERROR(function_expression_->CheckFieldsAccessed());
    }
  }
  if ((accessed_ & (1<<9)) != 0) {
    for (const auto& it : option_list_) ZETASQL_RETURN_IF_ERROR(it->CheckFieldsAccessed());
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedCreateFunctionStmt::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
  for (const auto& it : aggregate_expression_list_) it->ClearFieldsAccessed();
  if (function_expression_ != nullptr) function_expression_->ClearFieldsAccessed();
  for (const auto& it : option_list_) it->ClearFieldsAccessed();
}

const ResolvedNodeKind ResolvedArgumentDef::TYPE;

const ResolvedArgumentDef::ArgumentKind ResolvedArgumentDef::SCALAR;
const ResolvedArgumentDef::ArgumentKind ResolvedArgumentDef::AGGREGATE;
const ResolvedArgumentDef::ArgumentKind ResolvedArgumentDef::NOT_AGGREGATE;

ResolvedArgumentDef::~ResolvedArgumentDef() {
}

zetasql_base::Status ResolvedArgumentDef::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedArgumentProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_argument_def_node());
}

zetasql_base::Status ResolvedArgumentDef::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedArgumentDefProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  proto->set_name(name_);
  ZETASQL_RETURN_IF_ERROR(SaveToImpl(
      type_, file_descriptor_set_map,
      proto->mutable_type()));
  proto->set_argument_kind(argument_kind_);
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedArgumentDef>> ResolvedArgumentDef::RestoreFrom(
    const ResolvedArgumentDefProto& proto,
    const ResolvedNode::RestoreParams& params) {
  std::string name =
      proto.name();
  ZETASQL_ASSIGN_OR_RETURN(const Type* type,
                   RestoreFromImpl(proto.type(),
                                   params));
  ArgumentKind argument_kind =
      proto.argument_kind();
  auto node = MakeResolvedArgumentDef(
      std::move(name),
      std::move(type),
      std::move(argument_kind));

  return std::move(node);
}

void ResolvedArgumentDef::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
}

void ResolvedArgumentDef::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
}

zetasql_base::Status ResolvedArgumentDef::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedArgumentDef(this);
}

zetasql_base::Status ResolvedArgumentDef::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  return ::zetasql_base::OkStatus();
}

void ResolvedArgumentDef::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  if (!IsDefaultValue(name_)) {
    fields->emplace_back("name", ToStringImpl(name_));
  }
  {
    fields->emplace_back("type", ToStringImpl(type_));
  }
  if (!IsDefaultValue(argument_kind_)) {
    fields->emplace_back("argument_kind", ToStringImpl(argument_kind_));
  }
}

zetasql_base::Status ResolvedArgumentDef::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<1)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedArgumentDef::type not accessed)";
  }
  if ((accessed_ & (1<<2)) == 0 &&
      !IsDefaultValue(argument_kind_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedArgumentDef::argument_kind not accessed "
           "and has non-default value)";
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedArgumentDef::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
}

const ResolvedNodeKind ResolvedArgumentRef::TYPE;

const ResolvedArgumentRef::ArgumentKind ResolvedArgumentRef::SCALAR;
const ResolvedArgumentRef::ArgumentKind ResolvedArgumentRef::AGGREGATE;
const ResolvedArgumentRef::ArgumentKind ResolvedArgumentRef::NOT_AGGREGATE;

ResolvedArgumentRef::~ResolvedArgumentRef() {
}

zetasql_base::Status ResolvedArgumentRef::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedExprProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_argument_ref_node());
}

zetasql_base::Status ResolvedArgumentRef::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedArgumentRefProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  proto->set_name(name_);
  proto->set_argument_kind(argument_kind_);
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedArgumentRef>> ResolvedArgumentRef::RestoreFrom(
    const ResolvedArgumentRefProto& proto,
    const ResolvedNode::RestoreParams& params) {
  std::string name =
      proto.name();
  ArgumentKind argument_kind =
      proto.argument_kind();
  ZETASQL_ASSIGN_OR_RETURN(const Type* type,
                   RestoreFromImpl(proto.parent().type(),
                                   params));
  auto node = MakeResolvedArgumentRef(
      std::move(type),
      std::move(name),
      std::move(argument_kind));

  return std::move(node);
}

void ResolvedArgumentRef::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
}

void ResolvedArgumentRef::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
}

zetasql_base::Status ResolvedArgumentRef::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedArgumentRef(this);
}

zetasql_base::Status ResolvedArgumentRef::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  return ::zetasql_base::OkStatus();
}

void ResolvedArgumentRef::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  {
    fields->emplace_back("name", ToStringImpl(name_));
  }
  if (!IsDefaultValue(argument_kind_)) {
    fields->emplace_back("argument_kind", ToStringImpl(argument_kind_));
  }
}

zetasql_base::Status ResolvedArgumentRef::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedArgumentRef::name not accessed)";
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedArgumentRef::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
}

const ResolvedNodeKind ResolvedCreateTableFunctionStmt::TYPE;

ResolvedCreateTableFunctionStmt::~ResolvedCreateTableFunctionStmt() {
}

zetasql_base::Status ResolvedCreateTableFunctionStmt::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedCreateStatementProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_create_table_function_stmt_node());
}

zetasql_base::Status ResolvedCreateTableFunctionStmt::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedCreateTableFunctionStmtProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  for (const auto& elem : argument_name_list_) {
    proto->add_argument_name_list(elem);
  }
  ZETASQL_RETURN_IF_ERROR(SaveToImpl(
      signature_, file_descriptor_set_map,
      proto->mutable_signature()));
  for (const auto& elem : option_list_) {
    ZETASQL_RETURN_IF_ERROR(elem->SaveTo(
      file_descriptor_set_map, proto->add_option_list()));
  }
  proto->set_language(language_);
  proto->set_code(code_);
  if (query_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(query_->SaveTo(
        file_descriptor_set_map, proto->mutable_query()));
  }
  for (const auto& elem : output_column_list_) {
    ZETASQL_RETURN_IF_ERROR(elem->SaveTo(
      file_descriptor_set_map, proto->add_output_column_list()));
  }
  proto->set_is_value_table(is_value_table_);
  proto->set_sql_security(sql_security_);
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedCreateTableFunctionStmt>> ResolvedCreateTableFunctionStmt::RestoreFrom(
    const ResolvedCreateTableFunctionStmtProto& proto,
    const ResolvedNode::RestoreParams& params) {
  std::vector<std::string> argument_name_list;
  for (const auto& elem : proto.argument_name_list()) {
    argument_name_list.push_back(elem);
  }
  ZETASQL_ASSIGN_OR_RETURN(FunctionSignature signature,
                   RestoreFromImpl(proto.signature(),
                                   params));
  std::vector<std::unique_ptr<const ResolvedOption>> option_list;
  for (const auto& elem : proto.option_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedOption> elem_restored,
                     ResolvedOption::RestoreFrom(elem, params));
    option_list.push_back(std::move(elem_restored));
  }
  std::string language =
      proto.language();
  std::string code =
      proto.code();
  std::unique_ptr<const ResolvedScan> query;
  if (proto.
  has_query()) {
    ZETASQL_ASSIGN_OR_RETURN(query,
                     ResolvedScan::RestoreFrom(
                         proto.query(), params));
  }
  std::vector<std::unique_ptr<const ResolvedOutputColumn>> output_column_list;
  for (const auto& elem : proto.output_column_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedOutputColumn> elem_restored,
                     ResolvedOutputColumn::RestoreFrom(elem, params));
    output_column_list.push_back(std::move(elem_restored));
  }
  bool is_value_table =
      proto.is_value_table();
  SqlSecurity sql_security =
      proto.sql_security();
  std::vector<std::unique_ptr<const ResolvedOption>> hint_list;
  for (const auto& elem : proto.parent().parent().hint_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedOption> elem_restored,
                     ResolvedOption::RestoreFrom(elem, params));
    hint_list.push_back(std::move(elem_restored));
  }
  std::vector<std::string> name_path;
  for (const auto& elem : proto.parent().name_path()) {
    name_path.push_back(elem);
  }
  CreateScope create_scope =
      proto.parent().create_scope();
  CreateMode create_mode =
      proto.parent().create_mode();
  auto node = MakeResolvedCreateTableFunctionStmt(
      std::move(name_path),
      std::move(create_scope),
      std::move(create_mode),
      std::move(argument_name_list),
      std::move(signature),
      std::move(option_list),
      std::move(language),
      std::move(code),
      std::move(query),
      std::move(output_column_list),
      std::move(is_value_table),
      std::move(sql_security));

  node->set_hint_list(std::move(hint_list));
  return std::move(node);
}

void ResolvedCreateTableFunctionStmt::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
  for (const auto& elem : option_list_) {
    child_nodes->emplace_back(elem.get());
  }
  if (query_ != nullptr) {
    child_nodes->emplace_back(query_.get());
  }
  for (const auto& elem : output_column_list_) {
    child_nodes->emplace_back(elem.get());
  }
}

void ResolvedCreateTableFunctionStmt::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
  for (auto& elem : option_list_) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(&elem));
  }
  if (query_ != nullptr) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(
            &query_));
    static_assert(sizeof(query_) ==
                  sizeof(*(mutable_child_node_ptrs->back())),
                  "Incorrect casting of mutable child node");
  }
  for (auto& elem : output_column_list_) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(&elem));
  }
}

zetasql_base::Status ResolvedCreateTableFunctionStmt::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedCreateTableFunctionStmt(this);
}

zetasql_base::Status ResolvedCreateTableFunctionStmt::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  for (const auto& elem : option_list_) {
    ZETASQL_RETURN_IF_ERROR(elem.get()->Accept(visitor));
  }
  if (query_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(query_.get()->Accept(visitor));
  }
  for (const auto& elem : output_column_list_) {
    ZETASQL_RETURN_IF_ERROR(elem.get()->Accept(visitor));
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedCreateTableFunctionStmt::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  if (!IsDefaultValue(argument_name_list_)) {
    fields->emplace_back("argument_name_list", ToStringCommaSeparated(argument_name_list_));
  }
  if (!IsDefaultValue(signature_)) {
    fields->emplace_back("signature", ToStringVerbose(signature_));
  }
  if (!option_list_.empty()) {
    fields->emplace_back("option_list", option_list_);
  }
  if (!IsDefaultValue(language_)) {
    fields->emplace_back("language", ToStringImpl(language_));
  }
  if (!IsDefaultValue(code_)) {
    fields->emplace_back("code", ToStringImpl(code_));
  }
  if (query_ != nullptr) {
    fields->emplace_back("query", query_.get());
  }
  if (!output_column_list_.empty()) {
    fields->emplace_back("output_column_list", output_column_list_);
  }
  if (!IsDefaultValue(is_value_table_)) {
    fields->emplace_back("is_value_table", ToStringImpl(is_value_table_));
  }
  if (!IsDefaultValue(sql_security_)) {
    fields->emplace_back("sql_security", ToStringImpl(sql_security_));
  }
}

zetasql_base::Status ResolvedCreateTableFunctionStmt::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<2)) == 0 &&
      !IsDefaultValue(option_list_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedCreateTableFunctionStmt::option_list not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<3)) == 0 &&
      !IsDefaultValue(language_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedCreateTableFunctionStmt::language not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<5)) == 0 &&
      !IsDefaultValue(query_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedCreateTableFunctionStmt::query not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<6)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedCreateTableFunctionStmt::output_column_list not accessed)";
  }
  if ((accessed_ & (1<<7)) == 0 &&
      !IsDefaultValue(is_value_table_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedCreateTableFunctionStmt::is_value_table not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<8)) == 0 &&
      !IsDefaultValue(sql_security_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedCreateTableFunctionStmt::sql_security not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<2)) != 0) {
    for (const auto& it : option_list_) ZETASQL_RETURN_IF_ERROR(it->CheckFieldsAccessed());
  }
  if ((accessed_ & (1<<5)) != 0) {
    if (query_ != nullptr) {
      ZETASQL_RETURN_IF_ERROR(query_->CheckFieldsAccessed());
    }
  }
  if ((accessed_ & (1<<6)) != 0) {
    for (const auto& it : output_column_list_) ZETASQL_RETURN_IF_ERROR(it->CheckFieldsAccessed());
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedCreateTableFunctionStmt::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
  for (const auto& it : option_list_) it->ClearFieldsAccessed();
  if (query_ != nullptr) query_->ClearFieldsAccessed();
  for (const auto& it : output_column_list_) it->ClearFieldsAccessed();
}

const ResolvedNodeKind ResolvedRelationArgumentScan::TYPE;

ResolvedRelationArgumentScan::~ResolvedRelationArgumentScan() {
}

zetasql_base::Status ResolvedRelationArgumentScan::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedScanProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_relation_argument_scan_node());
}

zetasql_base::Status ResolvedRelationArgumentScan::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedRelationArgumentScanProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  proto->set_name(name_);
  proto->set_is_value_table(is_value_table_);
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedRelationArgumentScan>> ResolvedRelationArgumentScan::RestoreFrom(
    const ResolvedRelationArgumentScanProto& proto,
    const ResolvedNode::RestoreParams& params) {
  std::string name =
      proto.name();
  bool is_value_table =
      proto.is_value_table();
  std::vector<ResolvedColumn> column_list;
  for (const auto& elem : proto.parent().column_list()) {
    ZETASQL_ASSIGN_OR_RETURN(auto elem_restored, RestoreFromImpl(elem, params));
    column_list.push_back(std::move(elem_restored));
  }
  std::vector<std::unique_ptr<const ResolvedOption>> hint_list;
  for (const auto& elem : proto.parent().hint_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedOption> elem_restored,
                     ResolvedOption::RestoreFrom(elem, params));
    hint_list.push_back(std::move(elem_restored));
  }
  bool is_ordered =
      proto.parent().is_ordered();
  auto node = MakeResolvedRelationArgumentScan(
      std::move(column_list),
      std::move(name),
      std::move(is_value_table));

  node->set_hint_list(std::move(hint_list));
  node->set_is_ordered(std::move(is_ordered));
  return std::move(node);
}

void ResolvedRelationArgumentScan::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
}

void ResolvedRelationArgumentScan::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
}

zetasql_base::Status ResolvedRelationArgumentScan::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedRelationArgumentScan(this);
}

zetasql_base::Status ResolvedRelationArgumentScan::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  return ::zetasql_base::OkStatus();
}

void ResolvedRelationArgumentScan::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  {
    fields->emplace_back("name", ToStringImpl(name_));
  }
  if (!IsDefaultValue(is_value_table_)) {
    fields->emplace_back("is_value_table", ToStringImpl(is_value_table_));
  }
}

zetasql_base::Status ResolvedRelationArgumentScan::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedRelationArgumentScan::name not accessed)";
  }
  if ((accessed_ & (1<<1)) == 0 &&
      !IsDefaultValue(is_value_table_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedRelationArgumentScan::is_value_table not accessed "
           "and has non-default value)";
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedRelationArgumentScan::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
}

const ResolvedNodeKind ResolvedArgumentList::TYPE;

ResolvedArgumentList::~ResolvedArgumentList() {
}

zetasql_base::Status ResolvedArgumentList::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedArgumentProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_argument_list_node());
}

zetasql_base::Status ResolvedArgumentList::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedArgumentListProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  for (const auto& elem : arg_list_) {
    ZETASQL_RETURN_IF_ERROR(elem->SaveTo(
      file_descriptor_set_map, proto->add_arg_list()));
  }
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedArgumentList>> ResolvedArgumentList::RestoreFrom(
    const ResolvedArgumentListProto& proto,
    const ResolvedNode::RestoreParams& params) {
  std::vector<std::unique_ptr<const ResolvedArgumentDef>> arg_list;
  for (const auto& elem : proto.arg_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedArgumentDef> elem_restored,
                     ResolvedArgumentDef::RestoreFrom(elem, params));
    arg_list.push_back(std::move(elem_restored));
  }
  auto node = MakeResolvedArgumentList(
      std::move(arg_list));

  return std::move(node);
}

void ResolvedArgumentList::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
  for (const auto& elem : arg_list_) {
    child_nodes->emplace_back(elem.get());
  }
}

void ResolvedArgumentList::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
  for (auto& elem : arg_list_) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(&elem));
  }
}

zetasql_base::Status ResolvedArgumentList::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedArgumentList(this);
}

zetasql_base::Status ResolvedArgumentList::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  for (const auto& elem : arg_list_) {
    ZETASQL_RETURN_IF_ERROR(elem.get()->Accept(visitor));
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedArgumentList::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  if (!arg_list_.empty()) {
    fields->emplace_back("arg_list", arg_list_);
  }
}

zetasql_base::Status ResolvedArgumentList::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) != 0) {
    for (const auto& it : arg_list_) ZETASQL_RETURN_IF_ERROR(it->CheckFieldsAccessed());
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedArgumentList::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
  for (const auto& it : arg_list_) it->ClearFieldsAccessed();
}

const ResolvedNodeKind ResolvedFunctionSignatureHolder::TYPE;

ResolvedFunctionSignatureHolder::~ResolvedFunctionSignatureHolder() {
}

zetasql_base::Status ResolvedFunctionSignatureHolder::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedArgumentProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_function_signature_holder_node());
}

zetasql_base::Status ResolvedFunctionSignatureHolder::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedFunctionSignatureHolderProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  ZETASQL_RETURN_IF_ERROR(SaveToImpl(
      signature_, file_descriptor_set_map,
      proto->mutable_signature()));
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedFunctionSignatureHolder>> ResolvedFunctionSignatureHolder::RestoreFrom(
    const ResolvedFunctionSignatureHolderProto& proto,
    const ResolvedNode::RestoreParams& params) {
  ZETASQL_ASSIGN_OR_RETURN(FunctionSignature signature,
                   RestoreFromImpl(proto.signature(),
                                   params));
  auto node = MakeResolvedFunctionSignatureHolder(
      std::move(signature));

  return std::move(node);
}

void ResolvedFunctionSignatureHolder::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
}

void ResolvedFunctionSignatureHolder::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
}

zetasql_base::Status ResolvedFunctionSignatureHolder::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedFunctionSignatureHolder(this);
}

zetasql_base::Status ResolvedFunctionSignatureHolder::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  return ::zetasql_base::OkStatus();
}

void ResolvedFunctionSignatureHolder::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  {
    fields->emplace_back("signature", ToStringVerbose(signature_));
  }
}

zetasql_base::Status ResolvedFunctionSignatureHolder::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedFunctionSignatureHolder::signature not accessed)";
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedFunctionSignatureHolder::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
}

const ResolvedNodeKind ResolvedDropFunctionStmt::TYPE;

ResolvedDropFunctionStmt::~ResolvedDropFunctionStmt() {
}

zetasql_base::Status ResolvedDropFunctionStmt::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedStatementProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_drop_function_stmt_node());
}

zetasql_base::Status ResolvedDropFunctionStmt::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedDropFunctionStmtProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  proto->set_is_if_exists(is_if_exists_);
  for (const auto& elem : name_path_) {
    proto->add_name_path(elem);
  }
  if (arguments_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(arguments_->SaveTo(
        file_descriptor_set_map, proto->mutable_arguments()));
  }
  if (signature_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(signature_->SaveTo(
        file_descriptor_set_map, proto->mutable_signature()));
  }
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedDropFunctionStmt>> ResolvedDropFunctionStmt::RestoreFrom(
    const ResolvedDropFunctionStmtProto& proto,
    const ResolvedNode::RestoreParams& params) {
  bool is_if_exists =
      proto.is_if_exists();
  std::vector<std::string> name_path;
  for (const auto& elem : proto.name_path()) {
    name_path.push_back(elem);
  }
  std::unique_ptr<const ResolvedArgumentList> arguments;
  if (proto.
  has_arguments()) {
    ZETASQL_ASSIGN_OR_RETURN(arguments,
                     ResolvedArgumentList::RestoreFrom(
                         proto.arguments(), params));
  }
  std::unique_ptr<const ResolvedFunctionSignatureHolder> signature;
  if (proto.
  has_signature()) {
    ZETASQL_ASSIGN_OR_RETURN(signature,
                     ResolvedFunctionSignatureHolder::RestoreFrom(
                         proto.signature(), params));
  }
  std::vector<std::unique_ptr<const ResolvedOption>> hint_list;
  for (const auto& elem : proto.parent().hint_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedOption> elem_restored,
                     ResolvedOption::RestoreFrom(elem, params));
    hint_list.push_back(std::move(elem_restored));
  }
  auto node = MakeResolvedDropFunctionStmt(
      std::move(is_if_exists),
      std::move(name_path),
      std::move(arguments),
      std::move(signature));

  node->set_hint_list(std::move(hint_list));
  return std::move(node);
}

void ResolvedDropFunctionStmt::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
  if (arguments_ != nullptr) {
    child_nodes->emplace_back(arguments_.get());
  }
  if (signature_ != nullptr) {
    child_nodes->emplace_back(signature_.get());
  }
}

void ResolvedDropFunctionStmt::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
  if (arguments_ != nullptr) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(
            &arguments_));
    static_assert(sizeof(arguments_) ==
                  sizeof(*(mutable_child_node_ptrs->back())),
                  "Incorrect casting of mutable child node");
  }
  if (signature_ != nullptr) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(
            &signature_));
    static_assert(sizeof(signature_) ==
                  sizeof(*(mutable_child_node_ptrs->back())),
                  "Incorrect casting of mutable child node");
  }
}

zetasql_base::Status ResolvedDropFunctionStmt::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedDropFunctionStmt(this);
}

zetasql_base::Status ResolvedDropFunctionStmt::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  if (arguments_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(arguments_.get()->Accept(visitor));
  }
  if (signature_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(signature_.get()->Accept(visitor));
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedDropFunctionStmt::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  {
    fields->emplace_back("is_if_exists", ToStringImpl(is_if_exists_));
  }
  {
    fields->emplace_back("name_path", ToStringImpl(name_path_));
  }
  if (arguments_ != nullptr) {
    fields->emplace_back("arguments", arguments_.get());
  }
  if (signature_ != nullptr) {
    fields->emplace_back("signature", signature_.get());
  }
}

zetasql_base::Status ResolvedDropFunctionStmt::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedDropFunctionStmt::is_if_exists not accessed)";
  }
  if ((accessed_ & (1<<1)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedDropFunctionStmt::name_path not accessed)";
  }
  if ((accessed_ & (1<<2)) != 0) {
    if (arguments_ != nullptr) {
      ZETASQL_RETURN_IF_ERROR(arguments_->CheckFieldsAccessed());
    }
  }
  if ((accessed_ & (1<<3)) != 0) {
    if (signature_ != nullptr) {
      ZETASQL_RETURN_IF_ERROR(signature_->CheckFieldsAccessed());
    }
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedDropFunctionStmt::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
  if (arguments_ != nullptr) arguments_->ClearFieldsAccessed();
  if (signature_ != nullptr) signature_->ClearFieldsAccessed();
}

const ResolvedNodeKind ResolvedCallStmt::TYPE;

ResolvedCallStmt::~ResolvedCallStmt() {
}

zetasql_base::Status ResolvedCallStmt::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedStatementProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_call_stmt_node());
}

zetasql_base::Status ResolvedCallStmt::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedCallStmtProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  ZETASQL_RETURN_IF_ERROR(SaveToImpl(
      procedure_, file_descriptor_set_map,
      proto->mutable_procedure()));
  ZETASQL_RETURN_IF_ERROR(SaveToImpl(
      signature_, file_descriptor_set_map,
      proto->mutable_signature()));
  for (const auto& elem : argument_list_) {
    ZETASQL_RETURN_IF_ERROR(elem->SaveTo(
      file_descriptor_set_map, proto->add_argument_list()));
  }
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedCallStmt>> ResolvedCallStmt::RestoreFrom(
    const ResolvedCallStmtProto& proto,
    const ResolvedNode::RestoreParams& params) {
  ZETASQL_ASSIGN_OR_RETURN(const Procedure* procedure,
                   RestoreFromImpl(proto.procedure(),
                                   params));
  ZETASQL_ASSIGN_OR_RETURN(FunctionSignature signature,
                   RestoreFromImpl(proto.signature(),
                                   params));
  std::vector<std::unique_ptr<const ResolvedExpr>> argument_list;
  for (const auto& elem : proto.argument_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedExpr> elem_restored,
                     ResolvedExpr::RestoreFrom(elem, params));
    argument_list.push_back(std::move(elem_restored));
  }
  std::vector<std::unique_ptr<const ResolvedOption>> hint_list;
  for (const auto& elem : proto.parent().hint_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedOption> elem_restored,
                     ResolvedOption::RestoreFrom(elem, params));
    hint_list.push_back(std::move(elem_restored));
  }
  auto node = MakeResolvedCallStmt(
      std::move(procedure),
      std::move(signature),
      std::move(argument_list));

  node->set_hint_list(std::move(hint_list));
  return std::move(node);
}

void ResolvedCallStmt::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
  for (const auto& elem : argument_list_) {
    child_nodes->emplace_back(elem.get());
  }
}

void ResolvedCallStmt::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
  for (auto& elem : argument_list_) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(&elem));
  }
}

zetasql_base::Status ResolvedCallStmt::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedCallStmt(this);
}

zetasql_base::Status ResolvedCallStmt::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  for (const auto& elem : argument_list_) {
    ZETASQL_RETURN_IF_ERROR(elem.get()->Accept(visitor));
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedCallStmt::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  {
    fields->emplace_back("procedure", ToStringImpl(procedure_));
  }
  if (!IsDefaultValue(signature_)) {
    fields->emplace_back("signature", ToStringImpl(signature_));
  }
  if (!argument_list_.empty()) {
    fields->emplace_back("argument_list", argument_list_);
  }
}

zetasql_base::Status ResolvedCallStmt::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedCallStmt::procedure not accessed)";
  }
  if ((accessed_ & (1<<2)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedCallStmt::argument_list not accessed)";
  }
  if ((accessed_ & (1<<2)) != 0) {
    for (const auto& it : argument_list_) ZETASQL_RETURN_IF_ERROR(it->CheckFieldsAccessed());
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedCallStmt::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
  for (const auto& it : argument_list_) it->ClearFieldsAccessed();
}

const ResolvedNodeKind ResolvedImportStmt::TYPE;

const ResolvedImportStmt::ImportKind ResolvedImportStmt::MODULE;
const ResolvedImportStmt::ImportKind ResolvedImportStmt::PROTO;
const ResolvedImportStmt::ImportKind ResolvedImportStmt::__ImportKind__switch_must_have_a_default__;

ResolvedImportStmt::~ResolvedImportStmt() {
}

zetasql_base::Status ResolvedImportStmt::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedStatementProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_import_stmt_node());
}

zetasql_base::Status ResolvedImportStmt::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedImportStmtProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  proto->set_import_kind(import_kind_);
  for (const auto& elem : name_path_) {
    proto->add_name_path(elem);
  }
  proto->set_file_path(file_path_);
  for (const auto& elem : alias_path_) {
    proto->add_alias_path(elem);
  }
  for (const auto& elem : into_alias_path_) {
    proto->add_into_alias_path(elem);
  }
  for (const auto& elem : option_list_) {
    ZETASQL_RETURN_IF_ERROR(elem->SaveTo(
      file_descriptor_set_map, proto->add_option_list()));
  }
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedImportStmt>> ResolvedImportStmt::RestoreFrom(
    const ResolvedImportStmtProto& proto,
    const ResolvedNode::RestoreParams& params) {
  ImportKind import_kind =
      proto.import_kind();
  std::vector<std::string> name_path;
  for (const auto& elem : proto.name_path()) {
    name_path.push_back(elem);
  }
  std::string file_path =
      proto.file_path();
  std::vector<std::string> alias_path;
  for (const auto& elem : proto.alias_path()) {
    alias_path.push_back(elem);
  }
  std::vector<std::string> into_alias_path;
  for (const auto& elem : proto.into_alias_path()) {
    into_alias_path.push_back(elem);
  }
  std::vector<std::unique_ptr<const ResolvedOption>> option_list;
  for (const auto& elem : proto.option_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedOption> elem_restored,
                     ResolvedOption::RestoreFrom(elem, params));
    option_list.push_back(std::move(elem_restored));
  }
  std::vector<std::unique_ptr<const ResolvedOption>> hint_list;
  for (const auto& elem : proto.parent().hint_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedOption> elem_restored,
                     ResolvedOption::RestoreFrom(elem, params));
    hint_list.push_back(std::move(elem_restored));
  }
  auto node = MakeResolvedImportStmt(
      std::move(import_kind),
      std::move(name_path),
      std::move(file_path),
      std::move(alias_path),
      std::move(into_alias_path),
      std::move(option_list));

  node->set_hint_list(std::move(hint_list));
  return std::move(node);
}

void ResolvedImportStmt::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
  for (const auto& elem : option_list_) {
    child_nodes->emplace_back(elem.get());
  }
}

void ResolvedImportStmt::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
  for (auto& elem : option_list_) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(&elem));
  }
}

zetasql_base::Status ResolvedImportStmt::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedImportStmt(this);
}

zetasql_base::Status ResolvedImportStmt::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  for (const auto& elem : option_list_) {
    ZETASQL_RETURN_IF_ERROR(elem.get()->Accept(visitor));
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedImportStmt::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  {
    fields->emplace_back("import_kind", ToStringImpl(import_kind_));
  }
  if (!IsDefaultValue(name_path_)) {
    fields->emplace_back("name_path", ToStringImpl(name_path_));
  }
  if (!IsDefaultValue(file_path_)) {
    fields->emplace_back("file_path", ToStringImpl(file_path_));
  }
  if (!IsDefaultValue(alias_path_)) {
    fields->emplace_back("alias_path", ToStringImpl(alias_path_));
  }
  if (!IsDefaultValue(into_alias_path_)) {
    fields->emplace_back("into_alias_path", ToStringImpl(into_alias_path_));
  }
  if (!option_list_.empty()) {
    fields->emplace_back("option_list", option_list_);
  }
}

zetasql_base::Status ResolvedImportStmt::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedImportStmt::import_kind not accessed)";
  }
  if ((accessed_ & (1<<1)) == 0 &&
      !IsDefaultValue(name_path_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedImportStmt::name_path not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<2)) == 0 &&
      !IsDefaultValue(file_path_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedImportStmt::file_path not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<3)) == 0 &&
      !IsDefaultValue(alias_path_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedImportStmt::alias_path not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<4)) == 0 &&
      !IsDefaultValue(into_alias_path_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedImportStmt::into_alias_path not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<5)) == 0 &&
      !IsDefaultValue(option_list_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedImportStmt::option_list not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<5)) != 0) {
    for (const auto& it : option_list_) ZETASQL_RETURN_IF_ERROR(it->CheckFieldsAccessed());
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedImportStmt::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
  for (const auto& it : option_list_) it->ClearFieldsAccessed();
}

const ResolvedNodeKind ResolvedModuleStmt::TYPE;

ResolvedModuleStmt::~ResolvedModuleStmt() {
}

zetasql_base::Status ResolvedModuleStmt::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedStatementProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_module_stmt_node());
}

zetasql_base::Status ResolvedModuleStmt::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedModuleStmtProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  for (const auto& elem : name_path_) {
    proto->add_name_path(elem);
  }
  for (const auto& elem : option_list_) {
    ZETASQL_RETURN_IF_ERROR(elem->SaveTo(
      file_descriptor_set_map, proto->add_option_list()));
  }
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedModuleStmt>> ResolvedModuleStmt::RestoreFrom(
    const ResolvedModuleStmtProto& proto,
    const ResolvedNode::RestoreParams& params) {
  std::vector<std::string> name_path;
  for (const auto& elem : proto.name_path()) {
    name_path.push_back(elem);
  }
  std::vector<std::unique_ptr<const ResolvedOption>> option_list;
  for (const auto& elem : proto.option_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedOption> elem_restored,
                     ResolvedOption::RestoreFrom(elem, params));
    option_list.push_back(std::move(elem_restored));
  }
  std::vector<std::unique_ptr<const ResolvedOption>> hint_list;
  for (const auto& elem : proto.parent().hint_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedOption> elem_restored,
                     ResolvedOption::RestoreFrom(elem, params));
    hint_list.push_back(std::move(elem_restored));
  }
  auto node = MakeResolvedModuleStmt(
      std::move(name_path),
      std::move(option_list));

  node->set_hint_list(std::move(hint_list));
  return std::move(node);
}

void ResolvedModuleStmt::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
  for (const auto& elem : option_list_) {
    child_nodes->emplace_back(elem.get());
  }
}

void ResolvedModuleStmt::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
  for (auto& elem : option_list_) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(&elem));
  }
}

zetasql_base::Status ResolvedModuleStmt::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedModuleStmt(this);
}

zetasql_base::Status ResolvedModuleStmt::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  for (const auto& elem : option_list_) {
    ZETASQL_RETURN_IF_ERROR(elem.get()->Accept(visitor));
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedModuleStmt::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  {
    fields->emplace_back("name_path", ToStringImpl(name_path_));
  }
  if (!option_list_.empty()) {
    fields->emplace_back("option_list", option_list_);
  }
}

zetasql_base::Status ResolvedModuleStmt::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedModuleStmt::name_path not accessed)";
  }
  if ((accessed_ & (1<<1)) == 0 &&
      !IsDefaultValue(option_list_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedModuleStmt::option_list not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<1)) != 0) {
    for (const auto& it : option_list_) ZETASQL_RETURN_IF_ERROR(it->CheckFieldsAccessed());
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedModuleStmt::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
  for (const auto& it : option_list_) it->ClearFieldsAccessed();
}

const ResolvedNodeKind ResolvedAggregateHavingModifier::TYPE;

const ResolvedAggregateHavingModifier::HavingModifierKind ResolvedAggregateHavingModifier::INVALID;
const ResolvedAggregateHavingModifier::HavingModifierKind ResolvedAggregateHavingModifier::MAX;
const ResolvedAggregateHavingModifier::HavingModifierKind ResolvedAggregateHavingModifier::MIN;

ResolvedAggregateHavingModifier::~ResolvedAggregateHavingModifier() {
}

zetasql_base::Status ResolvedAggregateHavingModifier::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedArgumentProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_aggregate_having_modifier_node());
}

zetasql_base::Status ResolvedAggregateHavingModifier::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedAggregateHavingModifierProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  proto->set_kind(kind_);
  if (having_expr_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(having_expr_->SaveTo(
        file_descriptor_set_map, proto->mutable_having_expr()));
  }
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedAggregateHavingModifier>> ResolvedAggregateHavingModifier::RestoreFrom(
    const ResolvedAggregateHavingModifierProto& proto,
    const ResolvedNode::RestoreParams& params) {
  HavingModifierKind kind =
      proto.kind();
  std::unique_ptr<const ResolvedExpr> having_expr;
  if (proto.
  has_having_expr()) {
    ZETASQL_ASSIGN_OR_RETURN(having_expr,
                     ResolvedExpr::RestoreFrom(
                         proto.having_expr(), params));
  }
  auto node = MakeResolvedAggregateHavingModifier(
      std::move(kind),
      std::move(having_expr));

  return std::move(node);
}

void ResolvedAggregateHavingModifier::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
  if (having_expr_ != nullptr) {
    child_nodes->emplace_back(having_expr_.get());
  }
}

void ResolvedAggregateHavingModifier::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
  if (having_expr_ != nullptr) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(
            &having_expr_));
    static_assert(sizeof(having_expr_) ==
                  sizeof(*(mutable_child_node_ptrs->back())),
                  "Incorrect casting of mutable child node");
  }
}

zetasql_base::Status ResolvedAggregateHavingModifier::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedAggregateHavingModifier(this);
}

zetasql_base::Status ResolvedAggregateHavingModifier::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  if (having_expr_ != nullptr) {
    ZETASQL_RETURN_IF_ERROR(having_expr_.get()->Accept(visitor));
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedAggregateHavingModifier::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  {
    fields->emplace_back("kind", ToStringImpl(kind_));
  }
  if (having_expr_ != nullptr) {
    fields->emplace_back("having_expr", having_expr_.get());
  }
}

zetasql_base::Status ResolvedAggregateHavingModifier::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedAggregateHavingModifier::kind not accessed)";
  }
  if ((accessed_ & (1<<1)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedAggregateHavingModifier::having_expr not accessed)";
  }
  if ((accessed_ & (1<<1)) != 0) {
    if (having_expr_ != nullptr) {
      ZETASQL_RETURN_IF_ERROR(having_expr_->CheckFieldsAccessed());
    }
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedAggregateHavingModifier::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
  if (having_expr_ != nullptr) having_expr_->ClearFieldsAccessed();
}

const ResolvedNodeKind ResolvedCreateMaterializedViewStmt::TYPE;

ResolvedCreateMaterializedViewStmt::~ResolvedCreateMaterializedViewStmt() {
}

zetasql_base::Status ResolvedCreateMaterializedViewStmt::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedCreateViewBaseProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_create_materialized_view_stmt_node());
}

zetasql_base::Status ResolvedCreateMaterializedViewStmt::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedCreateMaterializedViewStmtProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedCreateMaterializedViewStmt>> ResolvedCreateMaterializedViewStmt::RestoreFrom(
    const ResolvedCreateMaterializedViewStmtProto& proto,
    const ResolvedNode::RestoreParams& params) {
  std::vector<std::unique_ptr<const ResolvedOption>> hint_list;
  for (const auto& elem : proto.parent().parent().parent().hint_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedOption> elem_restored,
                     ResolvedOption::RestoreFrom(elem, params));
    hint_list.push_back(std::move(elem_restored));
  }
  std::vector<std::string> name_path;
  for (const auto& elem : proto.parent().parent().name_path()) {
    name_path.push_back(elem);
  }
  CreateScope create_scope =
      proto.parent().parent().create_scope();
  CreateMode create_mode =
      proto.parent().parent().create_mode();
  std::vector<std::unique_ptr<const ResolvedOption>> option_list;
  for (const auto& elem : proto.parent().option_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedOption> elem_restored,
                     ResolvedOption::RestoreFrom(elem, params));
    option_list.push_back(std::move(elem_restored));
  }
  std::vector<std::unique_ptr<const ResolvedOutputColumn>> output_column_list;
  for (const auto& elem : proto.parent().output_column_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedOutputColumn> elem_restored,
                     ResolvedOutputColumn::RestoreFrom(elem, params));
    output_column_list.push_back(std::move(elem_restored));
  }
  std::unique_ptr<const ResolvedScan> query;
  if (proto.parent().
  has_query()) {
    ZETASQL_ASSIGN_OR_RETURN(query,
                     ResolvedScan::RestoreFrom(
                         proto.parent().query(), params));
  }
  std::string sql =
      proto.parent().sql();
  SqlSecurity sql_security =
      proto.parent().sql_security();
  bool is_value_table =
      proto.parent().is_value_table();
  auto node = MakeResolvedCreateMaterializedViewStmt(
      std::move(name_path),
      std::move(create_scope),
      std::move(create_mode),
      std::move(option_list),
      std::move(output_column_list),
      std::move(query),
      std::move(sql),
      std::move(sql_security),
      std::move(is_value_table));

  node->set_hint_list(std::move(hint_list));
  return std::move(node);
}

zetasql_base::Status ResolvedCreateMaterializedViewStmt::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedCreateMaterializedViewStmt(this);
}

zetasql_base::Status ResolvedCreateMaterializedViewStmt::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  return ::zetasql_base::OkStatus();
}

const ResolvedNodeKind ResolvedCreateProcedureStmt::TYPE;

ResolvedCreateProcedureStmt::~ResolvedCreateProcedureStmt() {
}

zetasql_base::Status ResolvedCreateProcedureStmt::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    AnyResolvedCreateStatementProto* proto) const {
  return SaveTo(
      file_descriptor_set_map, proto->mutable_resolved_create_procedure_stmt_node());
}

zetasql_base::Status ResolvedCreateProcedureStmt::SaveTo(
    Type::FileDescriptorSetMap* file_descriptor_set_map,
    ResolvedCreateProcedureStmtProto* proto) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::SaveTo(
      file_descriptor_set_map, proto->mutable_parent()));
  if (proto->parent().ByteSize() == 0) {
    proto->clear_parent();
  }
  for (const auto& elem : argument_name_list_) {
    proto->add_argument_name_list(elem);
  }
  ZETASQL_RETURN_IF_ERROR(SaveToImpl(
      signature_, file_descriptor_set_map,
      proto->mutable_signature()));
  for (const auto& elem : option_list_) {
    ZETASQL_RETURN_IF_ERROR(elem->SaveTo(
      file_descriptor_set_map, proto->add_option_list()));
  }
  proto->set_procedure_body(procedure_body_);
  return ::zetasql_base::OkStatus();
}

zetasql_base::StatusOr<std::unique_ptr<ResolvedCreateProcedureStmt>> ResolvedCreateProcedureStmt::RestoreFrom(
    const ResolvedCreateProcedureStmtProto& proto,
    const ResolvedNode::RestoreParams& params) {
  std::vector<std::string> argument_name_list;
  for (const auto& elem : proto.argument_name_list()) {
    argument_name_list.push_back(elem);
  }
  ZETASQL_ASSIGN_OR_RETURN(FunctionSignature signature,
                   RestoreFromImpl(proto.signature(),
                                   params));
  std::vector<std::unique_ptr<const ResolvedOption>> option_list;
  for (const auto& elem : proto.option_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedOption> elem_restored,
                     ResolvedOption::RestoreFrom(elem, params));
    option_list.push_back(std::move(elem_restored));
  }
  std::string procedure_body =
      proto.procedure_body();
  std::vector<std::unique_ptr<const ResolvedOption>> hint_list;
  for (const auto& elem : proto.parent().parent().hint_list()) {
    ZETASQL_ASSIGN_OR_RETURN(std::unique_ptr<const ResolvedOption> elem_restored,
                     ResolvedOption::RestoreFrom(elem, params));
    hint_list.push_back(std::move(elem_restored));
  }
  std::vector<std::string> name_path;
  for (const auto& elem : proto.parent().name_path()) {
    name_path.push_back(elem);
  }
  CreateScope create_scope =
      proto.parent().create_scope();
  CreateMode create_mode =
      proto.parent().create_mode();
  auto node = MakeResolvedCreateProcedureStmt(
      std::move(name_path),
      std::move(create_scope),
      std::move(create_mode),
      std::move(argument_name_list),
      std::move(signature),
      std::move(option_list),
      std::move(procedure_body));

  node->set_hint_list(std::move(hint_list));
  return std::move(node);
}

void ResolvedCreateProcedureStmt::GetChildNodes(
    std::vector<const ResolvedNode*>* child_nodes) const {
  SUPER::GetChildNodes(child_nodes);
  for (const auto& elem : option_list_) {
    child_nodes->emplace_back(elem.get());
  }
}

void ResolvedCreateProcedureStmt::AddMutableChildNodePointers(
    std::vector<std::unique_ptr<const ResolvedNode>*>*
        mutable_child_node_ptrs) {
  SUPER::AddMutableChildNodePointers(mutable_child_node_ptrs);
  for (auto& elem : option_list_) {
    mutable_child_node_ptrs->emplace_back(
        reinterpret_cast<std::unique_ptr<const ResolvedNode>*>(&elem));
  }
}

zetasql_base::Status ResolvedCreateProcedureStmt::Accept(ResolvedASTVisitor* visitor) const {
  return visitor->VisitResolvedCreateProcedureStmt(this);
}

zetasql_base::Status ResolvedCreateProcedureStmt::ChildrenAccept(ResolvedASTVisitor* visitor) const {
  ZETASQL_RETURN_IF_ERROR(SUPER::ChildrenAccept(visitor));
  for (const auto& elem : option_list_) {
    ZETASQL_RETURN_IF_ERROR(elem.get()->Accept(visitor));
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedCreateProcedureStmt::CollectDebugStringFields(
    std::vector<DebugStringField>* fields) const {
  SUPER::CollectDebugStringFields(fields);
  {
    fields->emplace_back("argument_name_list", ToStringCommaSeparated(argument_name_list_));
  }
  {
    fields->emplace_back("signature", ToStringVerbose(signature_));
  }
  if (!option_list_.empty()) {
    fields->emplace_back("option_list", option_list_);
  }
  {
    fields->emplace_back("procedure_body", ToStringImpl(procedure_body_));
  }
}

zetasql_base::Status ResolvedCreateProcedureStmt::CheckFieldsAccessed() const {
  ZETASQL_RETURN_IF_ERROR(SUPER::CheckFieldsAccessed());

  if ((accessed_ & (1<<0)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedCreateProcedureStmt::argument_name_list not accessed)";
  }
  if ((accessed_ & (1<<1)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedCreateProcedureStmt::signature not accessed)";
  }
  if ((accessed_ & (1<<2)) == 0 &&
      !IsDefaultValue(option_list_)) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedCreateProcedureStmt::option_list not accessed "
           "and has non-default value)";
  }
  if ((accessed_ & (1<<3)) == 0) {
    return ::zetasql_base::UnimplementedErrorBuilder(ZETASQL_LOC).LogError()
        << "Unimplemented feature "
           "(ResolvedCreateProcedureStmt::procedure_body not accessed)";
  }
  if ((accessed_ & (1<<2)) != 0) {
    for (const auto& it : option_list_) ZETASQL_RETURN_IF_ERROR(it->CheckFieldsAccessed());
  }
  return ::zetasql_base::OkStatus();
}

void ResolvedCreateProcedureStmt::ClearFieldsAccessed() const {
  SUPER::ClearFieldsAccessed();

  accessed_ = 0;
  for (const auto& it : option_list_) it->ClearFieldsAccessed();
}

}  // namespace zetasql