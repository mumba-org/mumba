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

// resolved_ast.h GENERATED FROM resolved_ast.h.template
#ifndef ZETASQL_RESOLVED_AST_RESOLVED_AST_H_
#define ZETASQL_RESOLVED_AST_RESOLVED_AST_H_

#include <atomic>
#include <memory>
#include <vector>

#include "google/protobuf/descriptor.h"
#include "zetasql/public/catalog.h"
#include "zetasql/public/constant.h"
#include "zetasql/public/function.h"
#include "zetasql/public/procedure.h"
#include "zetasql/public/table_valued_function.h"
#include "zetasql/public/type.h"
#include "zetasql/proto/type_annotation.pb.h"
#include "zetasql/public/value.h"
#include "zetasql/proto/resolved_ast.pb.h"
#include "zetasql/proto/resolved_ast_enums.pb.h"
#include "zetasql/resolved_ast/resolved_column.h"
#include "zetasql/resolved_ast/resolved_node.h"
#include "zetasql/resolved_ast/resolved_node_kind.h"
#include "zetasql/base/status.h"
#include "zetasql/base/statusor.h"

namespace zetasql {

class ResolvedASTVisitor;

class ResolvedArgument;
class ResolvedExpr;
class ResolvedLiteral;
class ResolvedParameter;
class ResolvedExpressionColumn;
class ResolvedColumnRef;
class ResolvedConstant;
class ResolvedFunctionCallBase;
class ResolvedFunctionCall;
class ResolvedNonScalarFunctionCallBase;
class ResolvedAggregateFunctionCall;
class ResolvedAnalyticFunctionCall;
class ResolvedCast;
class ResolvedMakeStruct;
class ResolvedMakeProto;
class ResolvedMakeProtoField;
class ResolvedGetStructField;
class ResolvedGetProtoField;
class ResolvedSubqueryExpr;
class ResolvedScan;
class ResolvedModel;
class ResolvedSingleRowScan;
class ResolvedTableScan;
class ResolvedJoinScan;
class ResolvedArrayScan;
class ResolvedColumnHolder;
class ResolvedFilterScan;
class ResolvedGroupingSet;
class ResolvedAggregateScanBase;
class ResolvedAggregateScan;
class ResolvedSetOperationItem;
class ResolvedSetOperationScan;
class ResolvedOrderByScan;
class ResolvedLimitOffsetScan;
class ResolvedWithRefScan;
class ResolvedAnalyticScan;
class ResolvedSampleScan;
class ResolvedComputedColumn;
class ResolvedOrderByItem;
class ResolvedColumnAnnotations;
class ResolvedGeneratedColumnInfo;
class ResolvedColumnDefinition;
class ResolvedPrimaryKey;
class ResolvedForeignKey;
class ResolvedCheckConstraint;
class ResolvedOutputColumn;
class ResolvedProjectScan;
class ResolvedTVFScan;
class ResolvedTVFArgument;
class ResolvedStatement;
class ResolvedExplainStmt;
class ResolvedQueryStmt;
class ResolvedCreateDatabaseStmt;
class ResolvedCreateStatement;
class ResolvedIndexItem;
class ResolvedUnnestItem;
class ResolvedCreateIndexStmt;
class ResolvedCreateTableStmtBase;
class ResolvedCreateTableStmt;
class ResolvedCreateTableAsSelectStmt;
class ResolvedCreateModelStmt;
class ResolvedCreateViewBase;
class ResolvedCreateViewStmt;
class ResolvedCreateExternalTableStmt;
class ResolvedExportDataStmt;
class ResolvedDefineTableStmt;
class ResolvedDescribeStmt;
class ResolvedShowStmt;
class ResolvedBeginStmt;
class ResolvedSetTransactionStmt;
class ResolvedCommitStmt;
class ResolvedRollbackStmt;
class ResolvedStartBatchStmt;
class ResolvedRunBatchStmt;
class ResolvedAbortBatchStmt;
class ResolvedDropStmt;
class ResolvedDropMaterializedViewStmt;
class ResolvedWithScan;
class ResolvedWithEntry;
class ResolvedOption;
class ResolvedWindowPartitioning;
class ResolvedWindowOrdering;
class ResolvedWindowFrame;
class ResolvedAnalyticFunctionGroup;
class ResolvedWindowFrameExpr;
class ResolvedDMLValue;
class ResolvedDMLDefault;
class ResolvedAssertStmt;
class ResolvedAssertRowsModified;
class ResolvedInsertRow;
class ResolvedInsertStmt;
class ResolvedDeleteStmt;
class ResolvedUpdateItem;
class ResolvedUpdateArrayItem;
class ResolvedUpdateStmt;
class ResolvedMergeWhen;
class ResolvedMergeStmt;
class ResolvedPrivilege;
class ResolvedGrantOrRevokeStmt;
class ResolvedGrantStmt;
class ResolvedRevokeStmt;
class ResolvedAlterObjectStmt;
class ResolvedAlterMaterializedViewStmt;
class ResolvedAlterTableStmt;
class ResolvedAlterViewStmt;
class ResolvedAlterAction;
class ResolvedSetOptionsAction;
class ResolvedAlterTableSetOptionsStmt;
class ResolvedRenameStmt;
class ResolvedCreateRowPolicyStmt;
class ResolvedDropRowPolicyStmt;
class ResolvedAlterRowPolicyStmt;
class ResolvedCreateConstantStmt;
class ResolvedCreateFunctionStmt;
class ResolvedArgumentDef;
class ResolvedArgumentRef;
class ResolvedCreateTableFunctionStmt;
class ResolvedRelationArgumentScan;
class ResolvedArgumentList;
class ResolvedFunctionSignatureHolder;
class ResolvedDropFunctionStmt;
class ResolvedCallStmt;
class ResolvedImportStmt;
class ResolvedModuleStmt;
class ResolvedAggregateHavingModifier;
class ResolvedCreateMaterializedViewStmt;
class ResolvedCreateProcedureStmt;
// Argument nodes are not self-contained nodes in the tree.  They exist
// only to describe parameters to another node (e.g. columns in an OrderBy).
// This node is here for organizational purposes only, to cluster these
// argument nodes.
class ResolvedArgument  : public ResolvedNode {
 public:
  typedef ResolvedNode SUPER;

  // Number of leaf node types that exist as descendants of this abstract type.
  static const int NUM_DESCENDANT_LEAF_TYPES = 36;

  ResolvedArgument()
      : ResolvedNode()
  {}
 public:

  ResolvedArgument(const ResolvedArgument&) = delete;
  ResolvedArgument& operator=(const ResolvedArgument&) = delete;

  ~ResolvedArgument() override;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const override;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const override;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedArgumentProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedNodeProto* proto) const final;

  virtual zetasql_base::Status SaveTo(
      Type::FileDescriptorSetMap* file_descriptor_set_map,
      AnyResolvedArgumentProto* proto) const = 0;
  static zetasql_base::StatusOr<std::unique_ptr<ResolvedArgument>> RestoreFrom(
      const AnyResolvedArgumentProto& proto,
      const ResolvedNode::RestoreParams& params);

  // Member fields

 protected:
  explicit ResolvedArgument(
      ConstructorOverload)
      : ResolvedNode(
) {
  }

 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

};

class ResolvedExpr  : public ResolvedNode {
 public:
  typedef ResolvedNode SUPER;

  // Number of leaf node types that exist as descendants of this abstract type.
  static const int NUM_DESCENDANT_LEAF_TYPES = 16;

  bool IsExpression() const final { return true; }

  ResolvedExpr()
      : ResolvedNode()
      , type_()
  {}
 public:

  ResolvedExpr(const ResolvedExpr&) = delete;
  ResolvedExpr& operator=(const ResolvedExpr&) = delete;

  ~ResolvedExpr() override;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const override;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const override;

  zetasql_base::Status CheckFieldsAccessed() const override;
  void ClearFieldsAccessed() const override;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedExprProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedNodeProto* proto) const final;

  virtual zetasql_base::Status SaveTo(
      Type::FileDescriptorSetMap* file_descriptor_set_map,
      AnyResolvedExprProto* proto) const = 0;
  static zetasql_base::StatusOr<std::unique_ptr<ResolvedExpr>> RestoreFrom(
      const AnyResolvedExprProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const override;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) override;

  // Member fields

  const Type* type() const {
    accessed_ |= (1<<0);
    return type_;
  }
  void set_type(const Type* v) {
    type_ = v;
  }

 protected:
  explicit ResolvedExpr(
      const Type* type,
      ConstructorOverload)
      : ResolvedNode(
),
      type_(type) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const override;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  const Type* type_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

// Any literal value, including NULL literals.
// There is a special-cased constructor here that gets the type from the
// Value.
class ResolvedLiteral final : public ResolvedExpr {
 public:
  typedef ResolvedExpr SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_LITERAL;

  friend std::unique_ptr<ResolvedLiteral> MakeResolvedLiteral();
 protected:
  ResolvedLiteral()
      : ResolvedExpr()
      , value_()
      , has_explicit_type_()
      , float_literal_id_()
  {}
 public:

  ResolvedLiteral(const ResolvedLiteral&) = delete;
  ResolvedLiteral& operator=(const ResolvedLiteral&) = delete;

  friend std::unique_ptr<ResolvedLiteral> MakeResolvedLiteral(
      const Type* type,
      const Value& value,
      bool has_explicit_type,
      int float_literal_id
  );
  ~ResolvedLiteral() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_LITERAL; }
  std::string node_kind_string() const final { return "Literal"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedLiteralProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedExprProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedLiteral>> RestoreFrom(
      const ResolvedLiteralProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  const Value& value() const {
    accessed_ |= (1<<0);
    return value_;
  }
  void set_value(const Value& v) {
    value_ = v;
  }

  // If true, then the literal is explicitly typed and cannot be used
  // for literal coercions.
  //
  // This exists mainly for resolver bookkeeping and should be ignored
  // by engines.
  bool has_explicit_type() const {
    accessed_ |= (1<<1);
    return has_explicit_type_;
  }
  void set_has_explicit_type(bool v) {
    has_explicit_type_ = v;
  }

  // Distinct ID of the literal, if it is a floating point value,
  // within the resolved AST. When coercing from floating point
  // to NUMERIC, the resolver uses the float_literal_id to find the
  // original image of the literal to avoid precision loss. An ID of 0
  // represents a literal without a cached image.
  int float_literal_id() const {
    accessed_ |= (1<<2);
    return float_literal_id_;
  }
  void set_float_literal_id(int v) {
    float_literal_id_ = v;
  }

 protected:
  explicit ResolvedLiteral(
      const Type* type,
      const Value& value,
      bool has_explicit_type,
      int float_literal_id,
      ConstructorOverload)
      : ResolvedExpr(
            type,
            ConstructorOverload::NEW_CONSTRUCTOR),
      value_(value),
      has_explicit_type_(has_explicit_type),
      float_literal_id_(float_literal_id) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  Value value_;
  bool has_explicit_type_;
  int float_literal_id_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedLiteral> MakeResolvedLiteral(
    const Type* type,
    const Value& value,
    bool has_explicit_type,
    int float_literal_id) {
  return std::unique_ptr<ResolvedLiteral>(new ResolvedLiteral(
        type,
        value,
        has_explicit_type,
        float_literal_id,
        ResolvedLiteral::NEW_CONSTRUCTOR));
}

inline std::unique_ptr<ResolvedLiteral> MakeResolvedLiteral() {
  return std::unique_ptr<ResolvedLiteral>(
      new ResolvedLiteral());
}

class ResolvedParameter final : public ResolvedExpr {
 public:
  typedef ResolvedExpr SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_PARAMETER;

  friend std::unique_ptr<ResolvedParameter> MakeResolvedParameter();
 protected:
  ResolvedParameter()
      : ResolvedExpr()
      , name_()
      , position_()
      , is_untyped_()
  {}
 public:

  ResolvedParameter(const ResolvedParameter&) = delete;
  ResolvedParameter& operator=(const ResolvedParameter&) = delete;

  friend std::unique_ptr<ResolvedParameter> MakeResolvedParameter(
      const Type* type,
      const std::string& name,
      int position,
      bool is_untyped
  );
  ~ResolvedParameter() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_PARAMETER; }
  std::string node_kind_string() const final { return "Parameter"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedParameterProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedExprProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedParameter>> RestoreFrom(
      const ResolvedParameterProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  // If non-empty, the name of the parameter.
  //
  // A ResolvedParameter will have either a name or a position but not
  // both.
  const std::string& name() const {
    accessed_ |= (1<<0);
    return name_;
  }
  void set_name(const std::string& v) {
    name_ = v;
  }

  // If non-zero, the 1-based position of the positional parameter.
  //
  // A ResolvedParameter will have either a name or a position but not
  // both.
  int position() const {
    accessed_ |= (1<<1);
    return position_;
  }
  void set_position(int v) {
    position_ = v;
  }

  // If true, then the parameter has no specified type.
  //
  // This exists mainly for resolver bookkeeping and should be ignored
  // by engines.
  bool is_untyped() const {
    accessed_ |= (1<<2);
    return is_untyped_;
  }
  void set_is_untyped(bool v) {
    is_untyped_ = v;
  }

 protected:
  explicit ResolvedParameter(
      const Type* type,
      const std::string& name,
      int position,
      bool is_untyped,
      ConstructorOverload)
      : ResolvedExpr(
            type,
            ConstructorOverload::NEW_CONSTRUCTOR),
      name_(name),
      position_(position),
      is_untyped_(is_untyped) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  std::string name_;
  int position_;
  bool is_untyped_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedParameter> MakeResolvedParameter(
    const Type* type,
    const std::string& name,
    int position,
    bool is_untyped) {
  return std::unique_ptr<ResolvedParameter>(new ResolvedParameter(
        type,
        name,
        position,
        is_untyped,
        ResolvedParameter::NEW_CONSTRUCTOR));
}

inline std::unique_ptr<ResolvedParameter> MakeResolvedParameter() {
  return std::unique_ptr<ResolvedParameter>(
      new ResolvedParameter());
}

// This represents a column when analyzing a standalone expression.
// This is only used when the analyzer was called using AnalyzeExpression.
// Expression column names and types come from
// AnalyzerOptions::AddExpressionColumn.
// <name> will always be in lowercase.
class ResolvedExpressionColumn final : public ResolvedExpr {
 public:
  typedef ResolvedExpr SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_EXPRESSION_COLUMN;

  friend std::unique_ptr<ResolvedExpressionColumn> MakeResolvedExpressionColumn();
 protected:
  ResolvedExpressionColumn()
      : ResolvedExpr()
      , name_()
  {}
 public:

  ResolvedExpressionColumn(const ResolvedExpressionColumn&) = delete;
  ResolvedExpressionColumn& operator=(const ResolvedExpressionColumn&) = delete;

  friend std::unique_ptr<ResolvedExpressionColumn> MakeResolvedExpressionColumn(
      const Type* type,
      const std::string& name
  );
  ~ResolvedExpressionColumn() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_EXPRESSION_COLUMN; }
  std::string node_kind_string() const final { return "ExpressionColumn"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedExpressionColumnProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedExprProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedExpressionColumn>> RestoreFrom(
      const ResolvedExpressionColumnProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  const std::string& name() const {
    accessed_ |= (1<<0);
    return name_;
  }
  void set_name(const std::string& v) {
    name_ = v;
  }

 protected:
  explicit ResolvedExpressionColumn(
      const Type* type,
      const std::string& name,
      ConstructorOverload)
      : ResolvedExpr(
            type,
            ConstructorOverload::NEW_CONSTRUCTOR),
      name_(name) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  std::string name_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedExpressionColumn> MakeResolvedExpressionColumn(
    const Type* type,
    const std::string& name) {
  return std::unique_ptr<ResolvedExpressionColumn>(new ResolvedExpressionColumn(
        type,
        name,
        ResolvedExpressionColumn::NEW_CONSTRUCTOR));
}

inline std::unique_ptr<ResolvedExpressionColumn> MakeResolvedExpressionColumn() {
  return std::unique_ptr<ResolvedExpressionColumn>(
      new ResolvedExpressionColumn());
}

// An expression referencing the value of some column visible in the
// current Scan node.
//
// If <is_correlated> is false, this must be a column visible in the Scan
// containing this expression, either because it was produced inside that
// Scan or it is on the <column_list> of some child of this Scan.
//
// If <is_correlated> is true, this references a column from outside a
// subquery that is visible as a correlated column inside.
// The column referenced here must show up on the parameters list for the
// subquery.  See ResolvedSubqueryExpr.
class ResolvedColumnRef final : public ResolvedExpr {
 public:
  typedef ResolvedExpr SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_COLUMN_REF;

  friend std::unique_ptr<ResolvedColumnRef> MakeResolvedColumnRef();
 protected:
  ResolvedColumnRef()
      : ResolvedExpr()
      , column_()
      , is_correlated_()
  {}
 public:

  ResolvedColumnRef(const ResolvedColumnRef&) = delete;
  ResolvedColumnRef& operator=(const ResolvedColumnRef&) = delete;

  friend std::unique_ptr<ResolvedColumnRef> MakeResolvedColumnRef(
      const Type* type,
      const ResolvedColumn& column,
      bool is_correlated
  );
  ~ResolvedColumnRef() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_COLUMN_REF; }
  std::string node_kind_string() const final { return "ColumnRef"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedColumnRefProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedExprProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedColumnRef>> RestoreFrom(
      const ResolvedColumnRefProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  const ResolvedColumn& column() const {
    accessed_ |= (1<<0);
    return column_;
  }
  void set_column(const ResolvedColumn& v) {
    column_ = v;
  }

  bool is_correlated() const {
    accessed_ |= (1<<1);
    return is_correlated_;
  }
  void set_is_correlated(bool v) {
    is_correlated_ = v;
  }

 protected:
  explicit ResolvedColumnRef(
      const Type* type,
      const ResolvedColumn& column,
      bool is_correlated,
      ConstructorOverload)
      : ResolvedExpr(
            type,
            ConstructorOverload::NEW_CONSTRUCTOR),
      column_(column),
      is_correlated_(is_correlated) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  ResolvedColumn column_;
  bool is_correlated_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedColumnRef> MakeResolvedColumnRef(
    const Type* type,
    const ResolvedColumn& column,
    bool is_correlated) {
  return std::unique_ptr<ResolvedColumnRef>(new ResolvedColumnRef(
        type,
        column,
        is_correlated,
        ResolvedColumnRef::NEW_CONSTRUCTOR));
}

inline std::unique_ptr<ResolvedColumnRef> MakeResolvedColumnRef() {
  return std::unique_ptr<ResolvedColumnRef>(
      new ResolvedColumnRef());
}

// A reference to a named constant.
class ResolvedConstant final : public ResolvedExpr {
 public:
  typedef ResolvedExpr SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_CONSTANT;

  friend std::unique_ptr<ResolvedConstant> MakeResolvedConstant();
 protected:
  ResolvedConstant()
      : ResolvedExpr()
      , constant_()
  {}
 public:

  ResolvedConstant(const ResolvedConstant&) = delete;
  ResolvedConstant& operator=(const ResolvedConstant&) = delete;

  friend std::unique_ptr<ResolvedConstant> MakeResolvedConstant(
      const Type* type,
      const Constant* constant
  );
  ~ResolvedConstant() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_CONSTANT; }
  std::string node_kind_string() const final { return "Constant"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedConstantProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedExprProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedConstant>> RestoreFrom(
      const ResolvedConstantProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  // The matching Constant from the Catalog.
  const Constant* constant() const {
    accessed_ |= (1<<0);
    return constant_;
  }
  void set_constant(const Constant* v) {
    constant_ = v;
  }

 protected:
  explicit ResolvedConstant(
      const Type* type,
      const Constant* constant,
      ConstructorOverload)
      : ResolvedExpr(
            type,
            ConstructorOverload::NEW_CONSTRUCTOR),
      constant_(constant) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
  std::string GetNameForDebugString() const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  const Constant* constant_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedConstant> MakeResolvedConstant(
    const Type* type,
    const Constant* constant) {
  return std::unique_ptr<ResolvedConstant>(new ResolvedConstant(
        type,
        constant,
        ResolvedConstant::NEW_CONSTRUCTOR));
}

inline std::unique_ptr<ResolvedConstant> MakeResolvedConstant() {
  return std::unique_ptr<ResolvedConstant>(
      new ResolvedConstant());
}

// Common base class for scalar and aggregate function calls.
class ResolvedFunctionCallBase  : public ResolvedExpr {
 public:
  typedef ResolvedExpr SUPER;

  // Number of leaf node types that exist as descendants of this abstract type.
  static const int NUM_DESCENDANT_LEAF_TYPES = 3;

  typedef ResolvedFunctionCallBaseEnums::ErrorMode ErrorMode;
  static const ErrorMode DEFAULT_ERROR_MODE = ResolvedFunctionCallBaseEnums::DEFAULT_ERROR_MODE;
  static const ErrorMode SAFE_ERROR_MODE = ResolvedFunctionCallBaseEnums::SAFE_ERROR_MODE;

  ~ResolvedFunctionCallBase() override;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const override;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const override;

  zetasql_base::Status CheckFieldsAccessed() const override;
  void ClearFieldsAccessed() const override;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedFunctionCallBaseProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedExprProto* proto) const final;

  virtual zetasql_base::Status SaveTo(
      Type::FileDescriptorSetMap* file_descriptor_set_map,
      AnyResolvedFunctionCallBaseProto* proto) const = 0;
  static zetasql_base::StatusOr<std::unique_ptr<ResolvedFunctionCallBase>> RestoreFrom(
      const AnyResolvedFunctionCallBaseProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const override;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) override;

  // Member fields

  // The matching Function from the Catalog.
  const Function* function() const {
    accessed_ |= (1<<0);
    return function_;
  }
  void set_function(const Function* v) {
    function_ = v;
  }

  // The concrete FunctionSignature reflecting the matching Function
  // signature and the function's resolved input <argument_list>.
  // The function has the mode AGGREGATE iff it is an aggregate
  // function, in which case this node must be either
  // ResolvedAggregateFunctionCall or ResolvedAnalyticFunctionCall.
  const FunctionSignature& signature() const {
    accessed_ |= (1<<1);
    return signature_;
  }
  void set_signature(const FunctionSignature& v) {
    signature_ = v;
  }

  const std::vector<std::unique_ptr<const ResolvedExpr>>& argument_list() const {
    accessed_ |= (1<<2);
    return argument_list_;
  }
  int argument_list_size() const {
    if (argument_list_.empty()) accessed_ |= (1<<2);
    return static_cast<int>(argument_list_.size());
  }
  const ResolvedExpr* argument_list(int i) const {
    accessed_ |= (1<<2);
    return argument_list_.at(i).get();
  }
  void add_argument_list(std::unique_ptr<const ResolvedExpr> v) {
    argument_list_.emplace_back(std::move(v));
  }
  void set_argument_list(std::vector<std::unique_ptr<const ResolvedExpr>> v) {
    argument_list_ = std::move(v);
  }

  std::vector<std::unique_ptr<const ResolvedExpr>> release_argument_list() {
    std::vector<std::unique_ptr<const ResolvedExpr>> tmp;
    argument_list_.swap(tmp);
    return tmp;
  }

  // If error_mode=SAFE_ERROR_MODE, and if this function call returns a
  // semantic error (based on input data, not transient server
  // problems), return NULL instead of an error. This is used for
  // functions called using SAFE, as in SAFE.FUNCTION(...).
  ErrorMode error_mode() const {
    accessed_ |= (1<<3);
    return error_mode_;
  }
  void set_error_mode(ErrorMode v) {
    error_mode_ = v;
  }

 protected:
  explicit ResolvedFunctionCallBase(
      const Type* type,
      const Function* function,
      const FunctionSignature& signature,
      std::vector<std::unique_ptr<const ResolvedExpr>> argument_list,
      ErrorMode error_mode,
      ConstructorOverload)
      : ResolvedExpr(
            type,
            ConstructorOverload::NEW_CONSTRUCTOR),
      function_(function),
      signature_(signature),
      argument_list_(std::move(argument_list)),
      error_mode_(error_mode) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const override;
  std::string GetNameForDebugString() const override;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  const Function* function_;
  FunctionSignature signature_;
  std::vector<std::unique_ptr<const ResolvedExpr>> argument_list_;
  ErrorMode error_mode_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

// A regular function call.  The signature will always have mode SCALAR.
// Most scalar expressions show up as FunctionCalls using builtin signatures.
class ResolvedFunctionCall final : public ResolvedFunctionCallBase {
 public:
  typedef ResolvedFunctionCallBase SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_FUNCTION_CALL;

  friend std::unique_ptr<ResolvedFunctionCall> MakeResolvedFunctionCall(
      const Type* type,
      const Function* function,
      const FunctionSignature& signature,
      std::vector<std::unique_ptr<const ResolvedExpr>> argument_list,
      ErrorMode error_mode,
      const std::shared_ptr<ResolvedFunctionCallInfo>& function_call_info
  );
  ~ResolvedFunctionCall() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_FUNCTION_CALL; }
  std::string node_kind_string() const final { return "FunctionCall"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedFunctionCallProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedFunctionCallBaseProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedFunctionCall>> RestoreFrom(
      const ResolvedFunctionCallProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  // This contains optional custom information about a particular
  // function call.
  //
  // If some Function subclass requires computing additional
  // information at resolving time, that extra information can be
  // stored as a subclass of ResolvedFunctionCallInfo here.
  // For example, TemplatedSQLFunction stores the resolved template
  // body here as a TemplatedSQLFunctionCall.
  //
  // This field is ignorable because for most types of function calls,
  // there is no extra information to consider besides the arguments
  // and other fields from ResolvedFunctionCallBase.
  const std::shared_ptr<ResolvedFunctionCallInfo>& function_call_info() const {
    accessed_ |= (1<<0);
    return function_call_info_;
  }
  void set_function_call_info(const std::shared_ptr<ResolvedFunctionCallInfo>& v) {
    function_call_info_ = v;
  }

 protected:
  explicit ResolvedFunctionCall(
      const Type* type,
      const Function* function,
      const FunctionSignature& signature,
      std::vector<std::unique_ptr<const ResolvedExpr>> argument_list,
      ErrorMode error_mode,
      const std::shared_ptr<ResolvedFunctionCallInfo>& function_call_info,
      ConstructorOverload)
      : ResolvedFunctionCallBase(
            type,
            function,
            signature,
            std::move(argument_list),
            error_mode,
            ConstructorOverload::NEW_CONSTRUCTOR),
      function_call_info_(function_call_info) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  std::shared_ptr<ResolvedFunctionCallInfo> function_call_info_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedFunctionCall> MakeResolvedFunctionCall(
    const Type* type,
    const Function* function,
    const FunctionSignature& signature,
    std::vector<std::unique_ptr<const ResolvedExpr>> argument_list,
    ResolvedFunctionCallBase::ErrorMode error_mode,
    const std::shared_ptr<ResolvedFunctionCallInfo>& function_call_info) {
  return std::unique_ptr<ResolvedFunctionCall>(new ResolvedFunctionCall(
        type,
        function,
        signature,
        std::move(argument_list),
        error_mode,
        function_call_info,
        ResolvedFunctionCall::NEW_CONSTRUCTOR));
}

// Overloaded factory method for the construction of ResolvedFunctionCall with
// a wider range of inputs for node-vector inputs.  In particular allows:
// 1. unique_ptr element type can be non-const.
// 2. unique_ptr element type can be any descendant of the required type.
// 3. input container can be any object with a `begin()` and `end()`.
//
// Note, initializer lists cannot be used to pass
//  argument_list
// due to incompatibility with unique_ptr.  Use zetasql::MakeNodeVector
// instead.
template <
  typename argument_list_t
      = std::vector<std::unique_ptr<const ResolvedExpr>>>
std::unique_ptr<ResolvedFunctionCall> MakeResolvedFunctionCall(
    const Type* type,
    const Function* function,
    const FunctionSignature& signature,
    argument_list_t argument_list,
    ResolvedFunctionCallBase::ErrorMode error_mode,
    const std::shared_ptr<ResolvedFunctionCallInfo>& function_call_info) {
  static_assert(std::is_base_of<
      ResolvedExpr,
      typename std::decay<decltype(**(argument_list.begin()))>::type>::value,
      "argument_list must be a container of unique_ptr with elements of type "
      "ResolvedExpr (or its descendants).");
  return MakeResolvedFunctionCall(
      type,
      function,
      signature,
      {std::make_move_iterator(argument_list.begin()),
       std::make_move_iterator(argument_list.end())},
      error_mode,
      function_call_info);
}

// Common base class for scalar and aggregate function calls.
class ResolvedNonScalarFunctionCallBase  : public ResolvedFunctionCallBase {
 public:
  typedef ResolvedFunctionCallBase SUPER;

  // Number of leaf node types that exist as descendants of this abstract type.
  static const int NUM_DESCENDANT_LEAF_TYPES = 2;

  typedef ResolvedNonScalarFunctionCallBaseEnums::NullHandlingModifier NullHandlingModifier;
  static const NullHandlingModifier DEFAULT_NULL_HANDLING = ResolvedNonScalarFunctionCallBaseEnums::DEFAULT_NULL_HANDLING;
  static const NullHandlingModifier IGNORE_NULLS = ResolvedNonScalarFunctionCallBaseEnums::IGNORE_NULLS;
  static const NullHandlingModifier RESPECT_NULLS = ResolvedNonScalarFunctionCallBaseEnums::RESPECT_NULLS;

  ~ResolvedNonScalarFunctionCallBase() override;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const override;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const override;

  zetasql_base::Status CheckFieldsAccessed() const override;
  void ClearFieldsAccessed() const override;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedNonScalarFunctionCallBaseProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedFunctionCallBaseProto* proto) const final;

  virtual zetasql_base::Status SaveTo(
      Type::FileDescriptorSetMap* file_descriptor_set_map,
      AnyResolvedNonScalarFunctionCallBaseProto* proto) const = 0;
  static zetasql_base::StatusOr<std::unique_ptr<ResolvedNonScalarFunctionCallBase>> RestoreFrom(
      const AnyResolvedNonScalarFunctionCallBaseProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const override;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) override;

  // Member fields

  // Apply DISTINCT to the stream of input values before calling
  // function.
  bool distinct() const {
    accessed_ |= (1<<0);
    return distinct_;
  }
  void set_distinct(bool v) {
    distinct_ = v;
  }

  // Apply IGNORE/RESPECT NULLS filtering to the stream of input
  // values.
  NullHandlingModifier null_handling_modifier() const {
    accessed_ |= (1<<1);
    return null_handling_modifier_;
  }
  void set_null_handling_modifier(NullHandlingModifier v) {
    null_handling_modifier_ = v;
  }

 protected:
  explicit ResolvedNonScalarFunctionCallBase(
      const Type* type,
      const Function* function,
      const FunctionSignature& signature,
      std::vector<std::unique_ptr<const ResolvedExpr>> argument_list,
      ErrorMode error_mode,
      bool distinct,
      NullHandlingModifier null_handling_modifier,
      ConstructorOverload)
      : ResolvedFunctionCallBase(
            type,
            function,
            signature,
            std::move(argument_list),
            error_mode,
            ConstructorOverload::NEW_CONSTRUCTOR),
      distinct_(distinct),
      null_handling_modifier_(null_handling_modifier) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const override;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  bool distinct_;
  NullHandlingModifier null_handling_modifier_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

// An aggregate function call.  The signature always has mode AGGREGATE.
// This node only ever shows up as the outer function call in a
// ResolvedAggregateScan::aggregate_list.
class ResolvedAggregateFunctionCall final : public ResolvedNonScalarFunctionCallBase {
 public:
  typedef ResolvedNonScalarFunctionCallBase SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_AGGREGATE_FUNCTION_CALL;

  friend std::unique_ptr<ResolvedAggregateFunctionCall> MakeResolvedAggregateFunctionCall(
      const Type* type,
      const Function* function,
      const FunctionSignature& signature,
      std::vector<std::unique_ptr<const ResolvedExpr>> argument_list,
      ErrorMode error_mode,
      bool distinct,
      NullHandlingModifier null_handling_modifier,
      std::unique_ptr<const ResolvedAggregateHavingModifier> having_modifier,
      std::vector<std::unique_ptr<const ResolvedOrderByItem>> order_by_item_list,
      std::unique_ptr<const ResolvedExpr> limit,
      const std::shared_ptr<ResolvedFunctionCallInfo>& function_call_info
  );
  ~ResolvedAggregateFunctionCall() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_AGGREGATE_FUNCTION_CALL; }
  std::string node_kind_string() const final { return "AggregateFunctionCall"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedAggregateFunctionCallProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedNonScalarFunctionCallBaseProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedAggregateFunctionCall>> RestoreFrom(
      const ResolvedAggregateFunctionCallProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  // Apply HAVING MAX/MIN filtering to the stream of input values.
  const ResolvedAggregateHavingModifier* having_modifier() const {
    accessed_ |= (1<<0);
    return having_modifier_.get();
  }
  void set_having_modifier(std::unique_ptr<const ResolvedAggregateHavingModifier> v) {
    having_modifier_ = std::move(v);
  }

  std::unique_ptr<const ResolvedAggregateHavingModifier> release_having_modifier() {
    return std::move(having_modifier_);
  }

  // Apply ordering to the stream of input values before calling
  // function.
  const std::vector<std::unique_ptr<const ResolvedOrderByItem>>& order_by_item_list() const {
    accessed_ |= (1<<1);
    return order_by_item_list_;
  }
  int order_by_item_list_size() const {
    if (order_by_item_list_.empty()) accessed_ |= (1<<1);
    return static_cast<int>(order_by_item_list_.size());
  }
  const ResolvedOrderByItem* order_by_item_list(int i) const {
    accessed_ |= (1<<1);
    return order_by_item_list_.at(i).get();
  }
  void add_order_by_item_list(std::unique_ptr<const ResolvedOrderByItem> v) {
    order_by_item_list_.emplace_back(std::move(v));
  }
  void set_order_by_item_list(std::vector<std::unique_ptr<const ResolvedOrderByItem>> v) {
    order_by_item_list_ = std::move(v);
  }

  std::vector<std::unique_ptr<const ResolvedOrderByItem>> release_order_by_item_list() {
    std::vector<std::unique_ptr<const ResolvedOrderByItem>> tmp;
    order_by_item_list_.swap(tmp);
    return tmp;
  }

  const ResolvedExpr* limit() const {
    accessed_ |= (1<<2);
    return limit_.get();
  }
  void set_limit(std::unique_ptr<const ResolvedExpr> v) {
    limit_ = std::move(v);
  }

  std::unique_ptr<const ResolvedExpr> release_limit() {
    return std::move(limit_);
  }

  // This contains optional custom information about a particular
  // function call. Functions may introduce subclasses of this class to
  // add custom information as needed on a per-function basis.
  //
  // This field is ignorable because for most types of function calls,
  // there is no extra information to consider besides the arguments
  // and other fields from ResolvedFunctionCallBase. However, for
  // example, the TemplateSQLFunction in
  // zetasql/public/templated_sql_function.h defines the
  // TemplatedSQLFunctionCall subclass which includes the
  // fully-resolved function body in context of the actual concrete
  // types of the arguments provided to the function call.
  const std::shared_ptr<ResolvedFunctionCallInfo>& function_call_info() const {
    accessed_ |= (1<<3);
    return function_call_info_;
  }
  void set_function_call_info(const std::shared_ptr<ResolvedFunctionCallInfo>& v) {
    function_call_info_ = v;
  }

 protected:
  explicit ResolvedAggregateFunctionCall(
      const Type* type,
      const Function* function,
      const FunctionSignature& signature,
      std::vector<std::unique_ptr<const ResolvedExpr>> argument_list,
      ErrorMode error_mode,
      bool distinct,
      NullHandlingModifier null_handling_modifier,
      std::unique_ptr<const ResolvedAggregateHavingModifier> having_modifier,
      std::vector<std::unique_ptr<const ResolvedOrderByItem>> order_by_item_list,
      std::unique_ptr<const ResolvedExpr> limit,
      const std::shared_ptr<ResolvedFunctionCallInfo>& function_call_info,
      ConstructorOverload)
      : ResolvedNonScalarFunctionCallBase(
            type,
            function,
            signature,
            std::move(argument_list),
            error_mode,
            distinct,
            null_handling_modifier,
            ConstructorOverload::NEW_CONSTRUCTOR),
      having_modifier_(std::move(having_modifier)),
      order_by_item_list_(std::move(order_by_item_list)),
      limit_(std::move(limit)),
      function_call_info_(function_call_info) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  std::unique_ptr<const ResolvedAggregateHavingModifier> having_modifier_;
  std::vector<std::unique_ptr<const ResolvedOrderByItem>> order_by_item_list_;
  std::unique_ptr<const ResolvedExpr> limit_;
  std::shared_ptr<ResolvedFunctionCallInfo> function_call_info_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedAggregateFunctionCall> MakeResolvedAggregateFunctionCall(
    const Type* type,
    const Function* function,
    const FunctionSignature& signature,
    std::vector<std::unique_ptr<const ResolvedExpr>> argument_list,
    ResolvedFunctionCallBase::ErrorMode error_mode,
    bool distinct,
    ResolvedNonScalarFunctionCallBase::NullHandlingModifier null_handling_modifier,
    std::unique_ptr<const ResolvedAggregateHavingModifier> having_modifier,
    std::vector<std::unique_ptr<const ResolvedOrderByItem>> order_by_item_list,
    std::unique_ptr<const ResolvedExpr> limit,
    const std::shared_ptr<ResolvedFunctionCallInfo>& function_call_info) {
  return std::unique_ptr<ResolvedAggregateFunctionCall>(new ResolvedAggregateFunctionCall(
        type,
        function,
        signature,
        std::move(argument_list),
        error_mode,
        distinct,
        null_handling_modifier,
        std::move(having_modifier),
        std::move(order_by_item_list),
        std::move(limit),
        function_call_info,
        ResolvedAggregateFunctionCall::NEW_CONSTRUCTOR));
}

// Overloaded factory method for the construction of ResolvedAggregateFunctionCall with
// a wider range of inputs for node-vector inputs.  In particular allows:
// 1. unique_ptr element type can be non-const.
// 2. unique_ptr element type can be any descendant of the required type.
// 3. input container can be any object with a `begin()` and `end()`.
//
// Note, initializer lists cannot be used to pass
//  argument_list, order_by_item_list
// due to incompatibility with unique_ptr.  Use zetasql::MakeNodeVector
// instead.
template <
  typename argument_list_t
      = std::vector<std::unique_ptr<const ResolvedExpr>>,
  typename order_by_item_list_t
      = std::vector<std::unique_ptr<const ResolvedOrderByItem>>>
std::unique_ptr<ResolvedAggregateFunctionCall> MakeResolvedAggregateFunctionCall(
    const Type* type,
    const Function* function,
    const FunctionSignature& signature,
    argument_list_t argument_list,
    ResolvedFunctionCallBase::ErrorMode error_mode,
    bool distinct,
    ResolvedNonScalarFunctionCallBase::NullHandlingModifier null_handling_modifier,
    std::unique_ptr<const ResolvedAggregateHavingModifier> having_modifier,
    order_by_item_list_t order_by_item_list,
    std::unique_ptr<const ResolvedExpr> limit,
    const std::shared_ptr<ResolvedFunctionCallInfo>& function_call_info) {
  static_assert(std::is_base_of<
      ResolvedExpr,
      typename std::decay<decltype(**(argument_list.begin()))>::type>::value,
      "argument_list must be a container of unique_ptr with elements of type "
      "ResolvedExpr (or its descendants).");
  static_assert(std::is_base_of<
      ResolvedOrderByItem,
      typename std::decay<decltype(**(order_by_item_list.begin()))>::type>::value,
      "order_by_item_list must be a container of unique_ptr with elements of type "
      "ResolvedOrderByItem (or its descendants).");
  return MakeResolvedAggregateFunctionCall(
      type,
      function,
      signature,
      {std::make_move_iterator(argument_list.begin()),
       std::make_move_iterator(argument_list.end())},
      error_mode,
      distinct,
      null_handling_modifier,
      std::move(having_modifier),
      {std::make_move_iterator(order_by_item_list.begin()),
       std::make_move_iterator(order_by_item_list.end())},
      std::move(limit),
      function_call_info);
}

// An analytic function call. The mode of the function is either AGGREGATE
// or ANALYTIC. This node only ever shows up as a function call in a
// ResolvedAnalyticFunctionGroup::analytic_function_list. Its associated
// window is not under this node but as a sibling of its parent node.
//
// <window_frame> can be NULL.
class ResolvedAnalyticFunctionCall final : public ResolvedNonScalarFunctionCallBase {
 public:
  typedef ResolvedNonScalarFunctionCallBase SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_ANALYTIC_FUNCTION_CALL;

  friend std::unique_ptr<ResolvedAnalyticFunctionCall> MakeResolvedAnalyticFunctionCall(
      const Type* type,
      const Function* function,
      const FunctionSignature& signature,
      std::vector<std::unique_ptr<const ResolvedExpr>> argument_list,
      ErrorMode error_mode,
      bool distinct,
      NullHandlingModifier null_handling_modifier,
      std::unique_ptr<const ResolvedWindowFrame> window_frame
  );
  ~ResolvedAnalyticFunctionCall() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_ANALYTIC_FUNCTION_CALL; }
  std::string node_kind_string() const final { return "AnalyticFunctionCall"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedAnalyticFunctionCallProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedNonScalarFunctionCallBaseProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedAnalyticFunctionCall>> RestoreFrom(
      const ResolvedAnalyticFunctionCallProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  const ResolvedWindowFrame* window_frame() const {
    accessed_ |= (1<<0);
    return window_frame_.get();
  }
  void set_window_frame(std::unique_ptr<const ResolvedWindowFrame> v) {
    window_frame_ = std::move(v);
  }

  std::unique_ptr<const ResolvedWindowFrame> release_window_frame() {
    return std::move(window_frame_);
  }

 protected:
  explicit ResolvedAnalyticFunctionCall(
      const Type* type,
      const Function* function,
      const FunctionSignature& signature,
      std::vector<std::unique_ptr<const ResolvedExpr>> argument_list,
      ErrorMode error_mode,
      bool distinct,
      NullHandlingModifier null_handling_modifier,
      std::unique_ptr<const ResolvedWindowFrame> window_frame,
      ConstructorOverload)
      : ResolvedNonScalarFunctionCallBase(
            type,
            function,
            signature,
            std::move(argument_list),
            error_mode,
            distinct,
            null_handling_modifier,
            ConstructorOverload::NEW_CONSTRUCTOR),
      window_frame_(std::move(window_frame)) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  std::unique_ptr<const ResolvedWindowFrame> window_frame_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedAnalyticFunctionCall> MakeResolvedAnalyticFunctionCall(
    const Type* type,
    const Function* function,
    const FunctionSignature& signature,
    std::vector<std::unique_ptr<const ResolvedExpr>> argument_list,
    ResolvedFunctionCallBase::ErrorMode error_mode,
    bool distinct,
    ResolvedNonScalarFunctionCallBase::NullHandlingModifier null_handling_modifier,
    std::unique_ptr<const ResolvedWindowFrame> window_frame) {
  return std::unique_ptr<ResolvedAnalyticFunctionCall>(new ResolvedAnalyticFunctionCall(
        type,
        function,
        signature,
        std::move(argument_list),
        error_mode,
        distinct,
        null_handling_modifier,
        std::move(window_frame),
        ResolvedAnalyticFunctionCall::NEW_CONSTRUCTOR));
}

// Overloaded factory method for the construction of ResolvedAnalyticFunctionCall with
// a wider range of inputs for node-vector inputs.  In particular allows:
// 1. unique_ptr element type can be non-const.
// 2. unique_ptr element type can be any descendant of the required type.
// 3. input container can be any object with a `begin()` and `end()`.
//
// Note, initializer lists cannot be used to pass
//  argument_list
// due to incompatibility with unique_ptr.  Use zetasql::MakeNodeVector
// instead.
template <
  typename argument_list_t
      = std::vector<std::unique_ptr<const ResolvedExpr>>>
std::unique_ptr<ResolvedAnalyticFunctionCall> MakeResolvedAnalyticFunctionCall(
    const Type* type,
    const Function* function,
    const FunctionSignature& signature,
    argument_list_t argument_list,
    ResolvedFunctionCallBase::ErrorMode error_mode,
    bool distinct,
    ResolvedNonScalarFunctionCallBase::NullHandlingModifier null_handling_modifier,
    std::unique_ptr<const ResolvedWindowFrame> window_frame) {
  static_assert(std::is_base_of<
      ResolvedExpr,
      typename std::decay<decltype(**(argument_list.begin()))>::type>::value,
      "argument_list must be a container of unique_ptr with elements of type "
      "ResolvedExpr (or its descendants).");
  return MakeResolvedAnalyticFunctionCall(
      type,
      function,
      signature,
      {std::make_move_iterator(argument_list.begin()),
       std::make_move_iterator(argument_list.end())},
      error_mode,
      distinct,
      null_handling_modifier,
      std::move(window_frame));
}

// A cast expression, casting the result of an input expression to the
// target Type.
//
// Valid casts are defined in the CastHashMap (see cast.cc), which identifies
// valid from-Type, to-Type pairs.  Consumers can access it through
// GetZetaSQLCasts().
class ResolvedCast final : public ResolvedExpr {
 public:
  typedef ResolvedExpr SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_CAST;

  friend std::unique_ptr<ResolvedCast> MakeResolvedCast();
 protected:
  ResolvedCast()
      : ResolvedExpr()
      , expr_()
      , return_null_on_error_()
  {}
 public:

  ResolvedCast(const ResolvedCast&) = delete;
  ResolvedCast& operator=(const ResolvedCast&) = delete;

  friend std::unique_ptr<ResolvedCast> MakeResolvedCast(
      const Type* type,
      std::unique_ptr<const ResolvedExpr> expr,
      bool return_null_on_error
  );
  ~ResolvedCast() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_CAST; }
  std::string node_kind_string() const final { return "Cast"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedCastProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedExprProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedCast>> RestoreFrom(
      const ResolvedCastProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  const ResolvedExpr* expr() const {
    accessed_ |= (1<<0);
    return expr_.get();
  }
  void set_expr(std::unique_ptr<const ResolvedExpr> v) {
    expr_ = std::move(v);
  }

  std::unique_ptr<const ResolvedExpr> release_expr() {
    return std::move(expr_);
  }

  // Whether to return NULL if the cast fails. This is set to true for
  // SAFE_CAST.
  bool return_null_on_error() const {
    accessed_ |= (1<<1);
    return return_null_on_error_;
  }
  void set_return_null_on_error(bool v) {
    return_null_on_error_ = v;
  }

 protected:
  explicit ResolvedCast(
      const Type* type,
      std::unique_ptr<const ResolvedExpr> expr,
      bool return_null_on_error,
      ConstructorOverload)
      : ResolvedExpr(
            type,
            ConstructorOverload::NEW_CONSTRUCTOR),
      expr_(std::move(expr)),
      return_null_on_error_(return_null_on_error) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
  std::string GetNameForDebugString() const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  std::unique_ptr<const ResolvedExpr> expr_;
  bool return_null_on_error_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedCast> MakeResolvedCast(
    const Type* type,
    std::unique_ptr<const ResolvedExpr> expr,
    bool return_null_on_error) {
  return std::unique_ptr<ResolvedCast>(new ResolvedCast(
        type,
        std::move(expr),
        return_null_on_error,
        ResolvedCast::NEW_CONSTRUCTOR));
}

inline std::unique_ptr<ResolvedCast> MakeResolvedCast() {
  return std::unique_ptr<ResolvedCast>(
      new ResolvedCast());
}

// Construct a struct value.  <type> is always a StructType.
// <field_list> matches 1:1 with the fields in <type> position-wise.
// Each field's type will match the corresponding field in <type>.
class ResolvedMakeStruct final : public ResolvedExpr {
 public:
  typedef ResolvedExpr SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_MAKE_STRUCT;

  friend std::unique_ptr<ResolvedMakeStruct> MakeResolvedMakeStruct();
 protected:
  ResolvedMakeStruct()
      : ResolvedExpr()
      , field_list_()
  {}
 public:

  ResolvedMakeStruct(const ResolvedMakeStruct&) = delete;
  ResolvedMakeStruct& operator=(const ResolvedMakeStruct&) = delete;

  friend std::unique_ptr<ResolvedMakeStruct> MakeResolvedMakeStruct(
      const Type* type,
      std::vector<std::unique_ptr<const ResolvedExpr>> field_list
  );
  ~ResolvedMakeStruct() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_MAKE_STRUCT; }
  std::string node_kind_string() const final { return "MakeStruct"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedMakeStructProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedExprProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedMakeStruct>> RestoreFrom(
      const ResolvedMakeStructProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  const std::vector<std::unique_ptr<const ResolvedExpr>>& field_list() const {
    accessed_ |= (1<<0);
    return field_list_;
  }
  int field_list_size() const {
    if (field_list_.empty()) accessed_ |= (1<<0);
    return static_cast<int>(field_list_.size());
  }
  const ResolvedExpr* field_list(int i) const {
    accessed_ |= (1<<0);
    return field_list_.at(i).get();
  }
  void add_field_list(std::unique_ptr<const ResolvedExpr> v) {
    field_list_.emplace_back(std::move(v));
  }
  void set_field_list(std::vector<std::unique_ptr<const ResolvedExpr>> v) {
    field_list_ = std::move(v);
  }

  std::vector<std::unique_ptr<const ResolvedExpr>> release_field_list() {
    std::vector<std::unique_ptr<const ResolvedExpr>> tmp;
    field_list_.swap(tmp);
    return tmp;
  }

 protected:
  explicit ResolvedMakeStruct(
      const Type* type,
      std::vector<std::unique_ptr<const ResolvedExpr>> field_list,
      ConstructorOverload)
      : ResolvedExpr(
            type,
            ConstructorOverload::NEW_CONSTRUCTOR),
      field_list_(std::move(field_list)) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  std::vector<std::unique_ptr<const ResolvedExpr>> field_list_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedMakeStruct> MakeResolvedMakeStruct(
    const Type* type,
    std::vector<std::unique_ptr<const ResolvedExpr>> field_list) {
  return std::unique_ptr<ResolvedMakeStruct>(new ResolvedMakeStruct(
        type,
        std::move(field_list),
        ResolvedMakeStruct::NEW_CONSTRUCTOR));
}

// Overloaded factory method for the construction of ResolvedMakeStruct with
// a wider range of inputs for node-vector inputs.  In particular allows:
// 1. unique_ptr element type can be non-const.
// 2. unique_ptr element type can be any descendant of the required type.
// 3. input container can be any object with a `begin()` and `end()`.
//
// Note, initializer lists cannot be used to pass
//  field_list
// due to incompatibility with unique_ptr.  Use zetasql::MakeNodeVector
// instead.
template <
  typename field_list_t
      = std::vector<std::unique_ptr<const ResolvedExpr>>>
std::unique_ptr<ResolvedMakeStruct> MakeResolvedMakeStruct(
    const Type* type,
    field_list_t field_list) {
  static_assert(std::is_base_of<
      ResolvedExpr,
      typename std::decay<decltype(**(field_list.begin()))>::type>::value,
      "field_list must be a container of unique_ptr with elements of type "
      "ResolvedExpr (or its descendants).");
  return MakeResolvedMakeStruct(
      type,
      {std::make_move_iterator(field_list.begin()),
       std::make_move_iterator(field_list.end())});
}

inline std::unique_ptr<ResolvedMakeStruct> MakeResolvedMakeStruct() {
  return std::unique_ptr<ResolvedMakeStruct>(
      new ResolvedMakeStruct());
}

// Construct a proto value.  <type> is always a ProtoType.
// <field_list> is a vector of (FieldDescriptor, expr) pairs to write.
// <field_list> will contain all required fields, and no duplicate fields.
class ResolvedMakeProto final : public ResolvedExpr {
 public:
  typedef ResolvedExpr SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_MAKE_PROTO;

  friend std::unique_ptr<ResolvedMakeProto> MakeResolvedMakeProto();
 protected:
  ResolvedMakeProto()
      : ResolvedExpr()
      , field_list_()
  {}
 public:

  ResolvedMakeProto(const ResolvedMakeProto&) = delete;
  ResolvedMakeProto& operator=(const ResolvedMakeProto&) = delete;

  friend std::unique_ptr<ResolvedMakeProto> MakeResolvedMakeProto(
      const Type* type,
      std::vector<std::unique_ptr<const ResolvedMakeProtoField>> field_list
  );
  ~ResolvedMakeProto() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_MAKE_PROTO; }
  std::string node_kind_string() const final { return "MakeProto"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedMakeProtoProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedExprProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedMakeProto>> RestoreFrom(
      const ResolvedMakeProtoProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  const std::vector<std::unique_ptr<const ResolvedMakeProtoField>>& field_list() const {
    accessed_ |= (1<<0);
    return field_list_;
  }
  int field_list_size() const {
    if (field_list_.empty()) accessed_ |= (1<<0);
    return static_cast<int>(field_list_.size());
  }
  const ResolvedMakeProtoField* field_list(int i) const {
    accessed_ |= (1<<0);
    return field_list_.at(i).get();
  }
  void add_field_list(std::unique_ptr<const ResolvedMakeProtoField> v) {
    field_list_.emplace_back(std::move(v));
  }
  void set_field_list(std::vector<std::unique_ptr<const ResolvedMakeProtoField>> v) {
    field_list_ = std::move(v);
  }

  std::vector<std::unique_ptr<const ResolvedMakeProtoField>> release_field_list() {
    std::vector<std::unique_ptr<const ResolvedMakeProtoField>> tmp;
    field_list_.swap(tmp);
    return tmp;
  }

 protected:
  explicit ResolvedMakeProto(
      const Type* type,
      std::vector<std::unique_ptr<const ResolvedMakeProtoField>> field_list,
      ConstructorOverload)
      : ResolvedExpr(
            type,
            ConstructorOverload::NEW_CONSTRUCTOR),
      field_list_(std::move(field_list)) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  std::vector<std::unique_ptr<const ResolvedMakeProtoField>> field_list_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedMakeProto> MakeResolvedMakeProto(
    const Type* type,
    std::vector<std::unique_ptr<const ResolvedMakeProtoField>> field_list) {
  return std::unique_ptr<ResolvedMakeProto>(new ResolvedMakeProto(
        type,
        std::move(field_list),
        ResolvedMakeProto::NEW_CONSTRUCTOR));
}

// Overloaded factory method for the construction of ResolvedMakeProto with
// a wider range of inputs for node-vector inputs.  In particular allows:
// 1. unique_ptr element type can be non-const.
// 2. unique_ptr element type can be any descendant of the required type.
// 3. input container can be any object with a `begin()` and `end()`.
//
// Note, initializer lists cannot be used to pass
//  field_list
// due to incompatibility with unique_ptr.  Use zetasql::MakeNodeVector
// instead.
template <
  typename field_list_t
      = std::vector<std::unique_ptr<const ResolvedMakeProtoField>>>
std::unique_ptr<ResolvedMakeProto> MakeResolvedMakeProto(
    const Type* type,
    field_list_t field_list) {
  static_assert(std::is_base_of<
      ResolvedMakeProtoField,
      typename std::decay<decltype(**(field_list.begin()))>::type>::value,
      "field_list must be a container of unique_ptr with elements of type "
      "ResolvedMakeProtoField (or its descendants).");
  return MakeResolvedMakeProto(
      type,
      {std::make_move_iterator(field_list.begin()),
       std::make_move_iterator(field_list.end())});
}

inline std::unique_ptr<ResolvedMakeProto> MakeResolvedMakeProto() {
  return std::unique_ptr<ResolvedMakeProto>(
      new ResolvedMakeProto());
}

// One field assignment in a ResolvedMakeProto expression.
// The type of expr will match with the zetasql type of the proto field.
// The type will be an array iff the field is repeated.
//
// For NULL values of <expr>, the proto field should be cleared.
//
// If any value of <expr> cannot be written into the field, this query
// should fail.
class ResolvedMakeProtoField final : public ResolvedArgument {
 public:
  typedef ResolvedArgument SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_MAKE_PROTO_FIELD;

  friend std::unique_ptr<ResolvedMakeProtoField> MakeResolvedMakeProtoField();
 protected:
  ResolvedMakeProtoField()
      : ResolvedArgument()
      , field_descriptor_()
      , format_()
      , expr_()
  {}
 public:

  ResolvedMakeProtoField(const ResolvedMakeProtoField&) = delete;
  ResolvedMakeProtoField& operator=(const ResolvedMakeProtoField&) = delete;

  friend std::unique_ptr<ResolvedMakeProtoField> MakeResolvedMakeProtoField(
      const google::protobuf::FieldDescriptor* field_descriptor,
      FieldFormat::Format format,
      std::unique_ptr<const ResolvedExpr> expr
  );
  ~ResolvedMakeProtoField() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_MAKE_PROTO_FIELD; }
  std::string node_kind_string() const final { return "MakeProtoField"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedMakeProtoFieldProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedArgumentProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedMakeProtoField>> RestoreFrom(
      const ResolvedMakeProtoFieldProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  const google::protobuf::FieldDescriptor* field_descriptor() const {
    accessed_ |= (1<<0);
    return field_descriptor_;
  }
  void set_field_descriptor(const google::protobuf::FieldDescriptor* v) {
    field_descriptor_ = v;
  }

  // Provides the Format annotation that should be used when building
  // this field.  The annotation specifies both the ZetaSQL type and
  // the encoding format for this field.
  FieldFormat::Format format() const {
    accessed_ |= (1<<1);
    return format_;
  }
  void set_format(FieldFormat::Format v) {
    format_ = v;
  }

  const ResolvedExpr* expr() const {
    accessed_ |= (1<<2);
    return expr_.get();
  }
  void set_expr(std::unique_ptr<const ResolvedExpr> v) {
    expr_ = std::move(v);
  }

  std::unique_ptr<const ResolvedExpr> release_expr() {
    return std::move(expr_);
  }

 protected:
  explicit ResolvedMakeProtoField(
      const google::protobuf::FieldDescriptor* field_descriptor,
      FieldFormat::Format format,
      std::unique_ptr<const ResolvedExpr> expr,
      ConstructorOverload)
      : ResolvedArgument(
            ConstructorOverload::NEW_CONSTRUCTOR),
      field_descriptor_(field_descriptor),
      format_(format),
      expr_(std::move(expr)) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
  std::string GetNameForDebugString() const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  const google::protobuf::FieldDescriptor* field_descriptor_;
  FieldFormat::Format format_;
  std::unique_ptr<const ResolvedExpr> expr_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedMakeProtoField> MakeResolvedMakeProtoField(
    const google::protobuf::FieldDescriptor* field_descriptor,
    FieldFormat::Format format,
    std::unique_ptr<const ResolvedExpr> expr) {
  return std::unique_ptr<ResolvedMakeProtoField>(new ResolvedMakeProtoField(
        field_descriptor,
        format,
        std::move(expr),
        ResolvedMakeProtoField::NEW_CONSTRUCTOR));
}

inline std::unique_ptr<ResolvedMakeProtoField> MakeResolvedMakeProtoField() {
  return std::unique_ptr<ResolvedMakeProtoField>(
      new ResolvedMakeProtoField());
}

// Get the field in position <field_idx> (0-based) from <expr>, which has a
// STRUCT type.
class ResolvedGetStructField final : public ResolvedExpr {
 public:
  typedef ResolvedExpr SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_GET_STRUCT_FIELD;

  friend std::unique_ptr<ResolvedGetStructField> MakeResolvedGetStructField();
 protected:
  ResolvedGetStructField()
      : ResolvedExpr()
      , expr_()
      , field_idx_()
  {}
 public:

  ResolvedGetStructField(const ResolvedGetStructField&) = delete;
  ResolvedGetStructField& operator=(const ResolvedGetStructField&) = delete;

  friend std::unique_ptr<ResolvedGetStructField> MakeResolvedGetStructField(
      const Type* type,
      std::unique_ptr<const ResolvedExpr> expr,
      int field_idx
  );
  ~ResolvedGetStructField() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_GET_STRUCT_FIELD; }
  std::string node_kind_string() const final { return "GetStructField"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedGetStructFieldProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedExprProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedGetStructField>> RestoreFrom(
      const ResolvedGetStructFieldProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  const ResolvedExpr* expr() const {
    accessed_ |= (1<<0);
    return expr_.get();
  }
  void set_expr(std::unique_ptr<const ResolvedExpr> v) {
    expr_ = std::move(v);
  }

  std::unique_ptr<const ResolvedExpr> release_expr() {
    return std::move(expr_);
  }

  int field_idx() const {
    accessed_ |= (1<<1);
    return field_idx_;
  }
  void set_field_idx(int v) {
    field_idx_ = v;
  }

 protected:
  explicit ResolvedGetStructField(
      const Type* type,
      std::unique_ptr<const ResolvedExpr> expr,
      int field_idx,
      ConstructorOverload)
      : ResolvedExpr(
            type,
            ConstructorOverload::NEW_CONSTRUCTOR),
      expr_(std::move(expr)),
      field_idx_(field_idx) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  std::unique_ptr<const ResolvedExpr> expr_;
  int field_idx_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedGetStructField> MakeResolvedGetStructField(
    const Type* type,
    std::unique_ptr<const ResolvedExpr> expr,
    int field_idx) {
  return std::unique_ptr<ResolvedGetStructField>(new ResolvedGetStructField(
        type,
        std::move(expr),
        field_idx,
        ResolvedGetStructField::NEW_CONSTRUCTOR));
}

inline std::unique_ptr<ResolvedGetStructField> MakeResolvedGetStructField() {
  return std::unique_ptr<ResolvedGetStructField>(
      new ResolvedGetStructField());
}

class ResolvedGetProtoField final : public ResolvedExpr {
 public:
  typedef ResolvedExpr SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_GET_PROTO_FIELD;

  friend std::unique_ptr<ResolvedGetProtoField> MakeResolvedGetProtoField();
 protected:
  ResolvedGetProtoField()
      : ResolvedExpr()
      , expr_()
      , field_descriptor_()
      , default_value_()
      , get_has_bit_()
      , format_()
      , return_default_value_when_unset_()
  {}
 public:

  ResolvedGetProtoField(const ResolvedGetProtoField&) = delete;
  ResolvedGetProtoField& operator=(const ResolvedGetProtoField&) = delete;

  friend std::unique_ptr<ResolvedGetProtoField> MakeResolvedGetProtoField(
      const Type* type,
      std::unique_ptr<const ResolvedExpr> expr,
      const google::protobuf::FieldDescriptor* field_descriptor,
      const Value& default_value,
      bool get_has_bit,
      FieldFormat::Format format,
      bool return_default_value_when_unset
  );
  ~ResolvedGetProtoField() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_GET_PROTO_FIELD; }
  std::string node_kind_string() const final { return "GetProtoField"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedGetProtoFieldProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedExprProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedGetProtoField>> RestoreFrom(
      const ResolvedGetProtoFieldProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  const ResolvedExpr* expr() const {
    accessed_ |= (1<<0);
    return expr_.get();
  }
  void set_expr(std::unique_ptr<const ResolvedExpr> v) {
    expr_ = std::move(v);
  }

  std::unique_ptr<const ResolvedExpr> release_expr() {
    return std::move(expr_);
  }

  // The proto2 FieldDescriptor to extract.  This provides the tag
  // number and wire type.  Additional decoding may be necessary if any
  // of the other modifiers below are set.  Consumers should use those
  // ZetaSQL-computed modifiers rather than examining field
  // annotations directly.
  //
  // The field is an extension field iff
  // field_descriptor->is_extension() is true.  NOTE: The extended
  // descriptor's full_name must match the <expr>'s type's full_name,
  // but may not be the same Descriptor. Extension FieldDescriptors may
  // come from a different DescriptorPool.
  //
  // The field is required if field_descriptor->is_required().  If the
  // field is required and not present, an error should result.
  const google::protobuf::FieldDescriptor* field_descriptor() const {
    accessed_ |= (1<<1);
    return field_descriptor_;
  }
  void set_field_descriptor(const google::protobuf::FieldDescriptor* v) {
    field_descriptor_ = v;
  }

  // Default value to use when the proto field is not set. The default
  // may be NULL (e.g. for fields with a use_defaults=false
  // annotation).
  //
  // This will not be filled in (the Value will be uninitialized) if
  // get_has_bit is true, or the field is required.
  //
  // If field_descriptor->is_required() and the field is not present,
  // the engine should return an error.
  //
  // If the <expr> itself returns NULL, then extracting a field should
  // also return NULL, unless <return_default_value_when_unset> is
  // true. In that case, the default value is returned.
  //
  // TODO Make un-ignorable after clients migrate to start
  // using it.
  const Value& default_value() const {
    accessed_ |= (1<<2);
    return default_value_;
  }
  void set_default_value(const Value& v) {
    default_value_ = v;
  }

  // Indicates whether to return a bool indicating if a value was
  // present, rather than return the value (or NULL). Never set for
  // repeated fields. This field cannot be set if
  // <return_default_value_when_unset> is true, and vice versa.
  // Expression type will be BOOL.
  bool get_has_bit() const {
    accessed_ |= (1<<3);
    return get_has_bit_;
  }
  void set_get_has_bit(bool v) {
    get_has_bit_ = v;
  }

  // Provides the Format annotation that should be used when reading
  // this field.  The annotation specifies both the ZetaSQL type and
  // the encoding format for this field. This cannot be set when
  // get_has_bit is true.
  FieldFormat::Format format() const {
    accessed_ |= (1<<4);
    return format_;
  }
  void set_format(FieldFormat::Format v) {
    format_ = v;
  }

  // Indicates that the default value should be returned if <expr> is
  // NULL.
  //
  // This can only be set for non-message fields and fields that are
  // not annotated with zetasql.use_defaults=false. This cannot be
  // set when <get_has_bit> is true or the field is required.
  bool return_default_value_when_unset() const {
    accessed_ |= (1<<5);
    return return_default_value_when_unset_;
  }
  void set_return_default_value_when_unset(bool v) {
    return_default_value_when_unset_ = v;
  }

 protected:
  explicit ResolvedGetProtoField(
      const Type* type,
      std::unique_ptr<const ResolvedExpr> expr,
      const google::protobuf::FieldDescriptor* field_descriptor,
      const Value& default_value,
      bool get_has_bit,
      FieldFormat::Format format,
      bool return_default_value_when_unset,
      ConstructorOverload)
      : ResolvedExpr(
            type,
            ConstructorOverload::NEW_CONSTRUCTOR),
      expr_(std::move(expr)),
      field_descriptor_(field_descriptor),
      default_value_(default_value),
      get_has_bit_(get_has_bit),
      format_(format),
      return_default_value_when_unset_(return_default_value_when_unset) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  std::unique_ptr<const ResolvedExpr> expr_;
  const google::protobuf::FieldDescriptor* field_descriptor_;
  Value default_value_;
  bool get_has_bit_;
  FieldFormat::Format format_;
  bool return_default_value_when_unset_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedGetProtoField> MakeResolvedGetProtoField(
    const Type* type,
    std::unique_ptr<const ResolvedExpr> expr,
    const google::protobuf::FieldDescriptor* field_descriptor,
    const Value& default_value,
    bool get_has_bit,
    FieldFormat::Format format,
    bool return_default_value_when_unset) {
  return std::unique_ptr<ResolvedGetProtoField>(new ResolvedGetProtoField(
        type,
        std::move(expr),
        field_descriptor,
        default_value,
        get_has_bit,
        format,
        return_default_value_when_unset,
        ResolvedGetProtoField::NEW_CONSTRUCTOR));
}

inline std::unique_ptr<ResolvedGetProtoField> MakeResolvedGetProtoField() {
  return std::unique_ptr<ResolvedGetProtoField>(
      new ResolvedGetProtoField());
}

// A subquery in an expression (not a FROM clause).  The subquery runs
// in the context of a single input row and produces a single output value.
//
// Correlated subqueries can be thought of like functions, with a parameter
// list.  The <parameter_list> gives the set of ResolvedColumns from outside
// the subquery that are used inside.
//
// Inside the subquery, the only allowed references to values outside the
// subquery are to the named ColumnRefs listed in <parameter_list>.
// Any reference to one of these parameters will be represented as a
// ResolvedColumnRef with <is_correlated> set to true.
//
// These parameters are only visible through one level of expression
// subquery.  An expression subquery inside an expression has to list
// parameters again if parameters from the outer query are passed down
// further.  (This does not apply for table subqueries inside an expression
// subquery.  Table subqueries are never indicated in the resolved AST, so
// Scan nodes inside an expression query may have come from a nested table
// subquery, and they can still reference the expression subquery's
// parameters.)
//
// An empty <parameter_list> means that the subquery is uncorrelated.  It is
// permissable to run an uncorrelated subquery only once and reuse the result.
// TODO Do we want to specify semantics more firmly here?
//
// The semantics vary based on SubqueryType:
//   SCALAR
//     Usage: ( <subquery> )
//     If the subquery produces zero rows, the output value is NULL.
//     If the subquery produces exactly one row, that row is the output value.
//     If the subquery produces more than one row, raise a runtime error.
//
//   ARRAY
//     Usage: ARRAY( <subquery> )
//     The subquery produces an array value with zero or more rows, with
//     one array element per subquery row produced.
//
//   EXISTS
//     Usage: EXISTS( <subquery> )
//     The output type is always bool.  The result is true if the subquery
//     produces at least one row, and false otherwise.
//
//   IN
//     Usage: <in_expr> [NOT] IN ( <subquery> )
//     The output type is always bool.  The result is true when <in_expr> is
//     equal to at least one row, and false otherwise.  The <subquery> row
//     contains only one column, and the types of <in_expr> and the
//     subquery column must exactly match a built-in signature for the
//     '$equals' comparison function (they must be the same type or one
//     must be INT64 and the other UINT64).  NOT will be expressed as a $not
//     FunctionCall wrapping this SubqueryExpr.
//
// The subquery for a SCALAR or ARRAY or IN subquery must have exactly one
// output column.
// The output type for a SCALAR or ARRAY subquery is that column's type or
// an array of that column's type.  (The subquery scan may include a Project
// with a MakeStruct or MakeProto expression to construct a single value
// from multiple columns.)
class ResolvedSubqueryExpr final : public ResolvedExpr {
 public:
  typedef ResolvedExpr SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_SUBQUERY_EXPR;

  typedef ResolvedSubqueryExprEnums::SubqueryType SubqueryType;
  static const SubqueryType SCALAR = ResolvedSubqueryExprEnums::SCALAR;
  static const SubqueryType ARRAY = ResolvedSubqueryExprEnums::ARRAY;
  static const SubqueryType EXISTS = ResolvedSubqueryExprEnums::EXISTS;
  static const SubqueryType IN = ResolvedSubqueryExprEnums::IN;

  friend std::unique_ptr<ResolvedSubqueryExpr> MakeResolvedSubqueryExpr();
 protected:
  ResolvedSubqueryExpr()
      : ResolvedExpr()
      , subquery_type_()
      , parameter_list_()
      , in_expr_()
      , subquery_()
      , hint_list_()
  {}
 public:

  ResolvedSubqueryExpr(const ResolvedSubqueryExpr&) = delete;
  ResolvedSubqueryExpr& operator=(const ResolvedSubqueryExpr&) = delete;

  friend std::unique_ptr<ResolvedSubqueryExpr> MakeResolvedSubqueryExpr(
      const Type* type,
      SubqueryType subquery_type,
      std::vector<std::unique_ptr<const ResolvedColumnRef>> parameter_list,
      std::unique_ptr<const ResolvedExpr> in_expr,
      std::unique_ptr<const ResolvedScan> subquery
  );
  ~ResolvedSubqueryExpr() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_SUBQUERY_EXPR; }
  std::string node_kind_string() const final { return "SubqueryExpr"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedSubqueryExprProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedExprProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedSubqueryExpr>> RestoreFrom(
      const ResolvedSubqueryExprProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  SubqueryType subquery_type() const {
    accessed_ |= (1<<0);
    return subquery_type_;
  }
  void set_subquery_type(SubqueryType v) {
    subquery_type_ = v;
  }

  const std::vector<std::unique_ptr<const ResolvedColumnRef>>& parameter_list() const {
    accessed_ |= (1<<1);
    return parameter_list_;
  }
  int parameter_list_size() const {
    if (parameter_list_.empty()) accessed_ |= (1<<1);
    return static_cast<int>(parameter_list_.size());
  }
  const ResolvedColumnRef* parameter_list(int i) const {
    accessed_ |= (1<<1);
    return parameter_list_.at(i).get();
  }
  void add_parameter_list(std::unique_ptr<const ResolvedColumnRef> v) {
    parameter_list_.emplace_back(std::move(v));
  }
  void set_parameter_list(std::vector<std::unique_ptr<const ResolvedColumnRef>> v) {
    parameter_list_ = std::move(v);
  }

  std::vector<std::unique_ptr<const ResolvedColumnRef>> release_parameter_list() {
    std::vector<std::unique_ptr<const ResolvedColumnRef>> tmp;
    parameter_list_.swap(tmp);
    return tmp;
  }

  // Field is only populated for subquery of type IN.
  const ResolvedExpr* in_expr() const {
    accessed_ |= (1<<2);
    return in_expr_.get();
  }
  void set_in_expr(std::unique_ptr<const ResolvedExpr> v) {
    in_expr_ = std::move(v);
  }

  std::unique_ptr<const ResolvedExpr> release_in_expr() {
    return std::move(in_expr_);
  }

  const ResolvedScan* subquery() const {
    accessed_ |= (1<<3);
    return subquery_.get();
  }
  void set_subquery(std::unique_ptr<const ResolvedScan> v) {
    subquery_ = std::move(v);
  }

  std::unique_ptr<const ResolvedScan> release_subquery() {
    return std::move(subquery_);
  }

  // Note: Hints currently happen only for EXISTS or IN subquery but
  // not for ARRAY or SCALAR subquery.
  const std::vector<std::unique_ptr<const ResolvedOption>>& hint_list() const {
    accessed_ |= (1<<4);
    return hint_list_;
  }
  int hint_list_size() const {
    if (hint_list_.empty()) accessed_ |= (1<<4);
    return static_cast<int>(hint_list_.size());
  }
  const ResolvedOption* hint_list(int i) const {
    accessed_ |= (1<<4);
    return hint_list_.at(i).get();
  }
  void add_hint_list(std::unique_ptr<const ResolvedOption> v) {
    hint_list_.emplace_back(std::move(v));
  }
  void set_hint_list(std::vector<std::unique_ptr<const ResolvedOption>> v) {
    hint_list_ = std::move(v);
  }

  std::vector<std::unique_ptr<const ResolvedOption>> release_hint_list() {
    std::vector<std::unique_ptr<const ResolvedOption>> tmp;
    hint_list_.swap(tmp);
    return tmp;
  }

 protected:
  explicit ResolvedSubqueryExpr(
      const Type* type,
      SubqueryType subquery_type,
      std::vector<std::unique_ptr<const ResolvedColumnRef>> parameter_list,
      std::unique_ptr<const ResolvedExpr> in_expr,
      std::unique_ptr<const ResolvedScan> subquery,
      ConstructorOverload)
      : ResolvedExpr(
            type,
            ConstructorOverload::NEW_CONSTRUCTOR),
      subquery_type_(subquery_type),
      parameter_list_(std::move(parameter_list)),
      in_expr_(std::move(in_expr)),
      subquery_(std::move(subquery)),
      hint_list_() {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  SubqueryType subquery_type_;
  std::vector<std::unique_ptr<const ResolvedColumnRef>> parameter_list_;
  std::unique_ptr<const ResolvedExpr> in_expr_;
  std::unique_ptr<const ResolvedScan> subquery_;
  std::vector<std::unique_ptr<const ResolvedOption>> hint_list_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedSubqueryExpr> MakeResolvedSubqueryExpr(
    const Type* type,
    ResolvedSubqueryExpr::SubqueryType subquery_type,
    std::vector<std::unique_ptr<const ResolvedColumnRef>> parameter_list,
    std::unique_ptr<const ResolvedExpr> in_expr,
    std::unique_ptr<const ResolvedScan> subquery) {
  return std::unique_ptr<ResolvedSubqueryExpr>(new ResolvedSubqueryExpr(
        type,
        subquery_type,
        std::move(parameter_list),
        std::move(in_expr),
        std::move(subquery),
        ResolvedSubqueryExpr::NEW_CONSTRUCTOR));
}

// Overloaded factory method for the construction of ResolvedSubqueryExpr with
// a wider range of inputs for node-vector inputs.  In particular allows:
// 1. unique_ptr element type can be non-const.
// 2. unique_ptr element type can be any descendant of the required type.
// 3. input container can be any object with a `begin()` and `end()`.
//
// Note, initializer lists cannot be used to pass
//  parameter_list
// due to incompatibility with unique_ptr.  Use zetasql::MakeNodeVector
// instead.
template <
  typename parameter_list_t
      = std::vector<std::unique_ptr<const ResolvedColumnRef>>>
std::unique_ptr<ResolvedSubqueryExpr> MakeResolvedSubqueryExpr(
    const Type* type,
    ResolvedSubqueryExpr::SubqueryType subquery_type,
    parameter_list_t parameter_list,
    std::unique_ptr<const ResolvedExpr> in_expr,
    std::unique_ptr<const ResolvedScan> subquery) {
  static_assert(std::is_base_of<
      ResolvedColumnRef,
      typename std::decay<decltype(**(parameter_list.begin()))>::type>::value,
      "parameter_list must be a container of unique_ptr with elements of type "
      "ResolvedColumnRef (or its descendants).");
  return MakeResolvedSubqueryExpr(
      type,
      subquery_type,
      {std::make_move_iterator(parameter_list.begin()),
       std::make_move_iterator(parameter_list.end())},
      std::move(in_expr),
      std::move(subquery));
}

inline std::unique_ptr<ResolvedSubqueryExpr> MakeResolvedSubqueryExpr() {
  return std::unique_ptr<ResolvedSubqueryExpr>(
      new ResolvedSubqueryExpr());
}

// Common superclass for all Scans, which are nodes that produce rows
// (e.g. scans, joins, table subqueries).  A query's FROM clause is
// represented as a single Scan that composes all input sources into
// a single row stream.
//
// Each Scan has a <column_list> that says what columns are produced.
// The Scan logically produces a stream of output rows, where each row
// has exactly these columns.
//
// Each Scan may have an attached <hint_list>, storing each hint as
// a ResolvedOption.
//
// If <is_ordered> is true, this Scan produces an ordered output, either
// by generating order itself (OrderByScan) or by preserving the order
// of its single input scan (LimitOffsetScan, ProjectScan, or WithScan).
class ResolvedScan  : public ResolvedNode {
 public:
  typedef ResolvedNode SUPER;

  // Number of leaf node types that exist as descendants of this abstract type.
  static const int NUM_DESCENDANT_LEAF_TYPES = 16;

  bool IsScan() const final { return true; }

  ResolvedScan()
      : ResolvedNode()
      , column_list_()
      , hint_list_()
      , is_ordered_()
  {}
 public:

  ResolvedScan(const ResolvedScan&) = delete;
  ResolvedScan& operator=(const ResolvedScan&) = delete;

  ~ResolvedScan() override;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const override;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const override;

  zetasql_base::Status CheckFieldsAccessed() const override;
  void ClearFieldsAccessed() const override;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedScanProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedNodeProto* proto) const final;

  virtual zetasql_base::Status SaveTo(
      Type::FileDescriptorSetMap* file_descriptor_set_map,
      AnyResolvedScanProto* proto) const = 0;
  static zetasql_base::StatusOr<std::unique_ptr<ResolvedScan>> RestoreFrom(
      const AnyResolvedScanProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const override;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) override;

  // Member fields

  const std::vector<ResolvedColumn>& column_list() const {
    accessed_ |= (1<<0);
    return column_list_;
  }
  int column_list_size() const {
    if (column_list_.empty()) accessed_ |= (1<<0);
    return static_cast<int>(column_list_.size());
  }
  ResolvedColumn column_list(int i) const {
    accessed_ |= (1<<0);
    return column_list_.at(i);
  }
  void add_column_list(ResolvedColumn v) {
    column_list_.push_back(ResolvedColumn(v));
  }
  void set_column_list(const std::vector<ResolvedColumn>& v) {
    column_list_ = v;
  }
  std::vector<ResolvedColumn>* mutable_column_list() {
    accessed_ |= (1<<0);
    return &column_list_;
  }

  const std::vector<std::unique_ptr<const ResolvedOption>>& hint_list() const {
    accessed_ |= (1<<1);
    return hint_list_;
  }
  int hint_list_size() const {
    if (hint_list_.empty()) accessed_ |= (1<<1);
    return static_cast<int>(hint_list_.size());
  }
  const ResolvedOption* hint_list(int i) const {
    accessed_ |= (1<<1);
    return hint_list_.at(i).get();
  }
  void add_hint_list(std::unique_ptr<const ResolvedOption> v) {
    hint_list_.emplace_back(std::move(v));
  }
  void set_hint_list(std::vector<std::unique_ptr<const ResolvedOption>> v) {
    hint_list_ = std::move(v);
  }

  std::vector<std::unique_ptr<const ResolvedOption>> release_hint_list() {
    std::vector<std::unique_ptr<const ResolvedOption>> tmp;
    hint_list_.swap(tmp);
    return tmp;
  }

  bool is_ordered() const {
    accessed_ |= (1<<2);
    return is_ordered_;
  }
  void set_is_ordered(bool v) {
    is_ordered_ = v;
  }

 protected:
  explicit ResolvedScan(
      const std::vector<ResolvedColumn>& column_list,
      ConstructorOverload)
      : ResolvedNode(
),
      column_list_(column_list),
      hint_list_(),
      is_ordered_() {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const override;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  std::vector<ResolvedColumn> column_list_;
  std::vector<std::unique_ptr<const ResolvedOption>> hint_list_;
  bool is_ordered_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

// Represents a machine learning model as a TVF argument.
// <model> is the machine learning model object known to the resolver
// (usually through the catalog).
class ResolvedModel final : public ResolvedArgument {
 public:
  typedef ResolvedArgument SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_MODEL;

  friend std::unique_ptr<ResolvedModel> MakeResolvedModel();
 protected:
  ResolvedModel()
      : ResolvedArgument()
      , model_()
  {}
 public:

  ResolvedModel(const ResolvedModel&) = delete;
  ResolvedModel& operator=(const ResolvedModel&) = delete;

  friend std::unique_ptr<ResolvedModel> MakeResolvedModel(
      const Model* model
  );
  ~ResolvedModel() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_MODEL; }
  std::string node_kind_string() const final { return "Model"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedModelProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedArgumentProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedModel>> RestoreFrom(
      const ResolvedModelProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  const Model* model() const {
    accessed_ |= (1<<0);
    return model_;
  }
  void set_model(const Model* v) {
    model_ = v;
  }

 protected:
  explicit ResolvedModel(
      const Model* model,
      ConstructorOverload)
      : ResolvedArgument(
            ConstructorOverload::NEW_CONSTRUCTOR),
      model_(model) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  const Model* model_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedModel> MakeResolvedModel(
    const Model* model) {
  return std::unique_ptr<ResolvedModel>(new ResolvedModel(
        model,
        ResolvedModel::NEW_CONSTRUCTOR));
}

inline std::unique_ptr<ResolvedModel> MakeResolvedModel() {
  return std::unique_ptr<ResolvedModel>(
      new ResolvedModel());
}

// Scan that produces a single row with no columns.  Used for queries without
// a FROM clause, where all output comes from the select list.
class ResolvedSingleRowScan final : public ResolvedScan {
 public:
  typedef ResolvedScan SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_SINGLE_ROW_SCAN;

  friend std::unique_ptr<ResolvedSingleRowScan> MakeResolvedSingleRowScan();
 protected:
  ResolvedSingleRowScan()
      : ResolvedScan()
  {}
 public:

  ResolvedSingleRowScan(const ResolvedSingleRowScan&) = delete;
  ResolvedSingleRowScan& operator=(const ResolvedSingleRowScan&) = delete;

  friend std::unique_ptr<ResolvedSingleRowScan> MakeResolvedSingleRowScan(
      const std::vector<ResolvedColumn>& column_list
  );
  ~ResolvedSingleRowScan() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_SINGLE_ROW_SCAN; }
  std::string node_kind_string() const final { return "SingleRowScan"; }

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedSingleRowScanProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedScanProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedSingleRowScan>> RestoreFrom(
      const ResolvedSingleRowScanProto& proto,
      const ResolvedNode::RestoreParams& params);

  // Member fields

 protected:
  explicit ResolvedSingleRowScan(
      const std::vector<ResolvedColumn>& column_list,
      ConstructorOverload)
      : ResolvedScan(
            column_list,
            ConstructorOverload::NEW_CONSTRUCTOR) {
  }

 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

};

inline std::unique_ptr<ResolvedSingleRowScan> MakeResolvedSingleRowScan(
    const std::vector<ResolvedColumn>& column_list) {
  return std::unique_ptr<ResolvedSingleRowScan>(new ResolvedSingleRowScan(
        column_list,
        ResolvedSingleRowScan::NEW_CONSTRUCTOR));
}

inline std::unique_ptr<ResolvedSingleRowScan> MakeResolvedSingleRowScan() {
  return std::unique_ptr<ResolvedSingleRowScan>(
      new ResolvedSingleRowScan());
}

// Scan a Table.
// The <column_list>[i] should be matched to a Table column by
// <table>.GetColumn(<column_index_list>[i]).
//
// If AnalyzerOptions::prune_unused_columns is true, the <column_list> and
// <column_index_list> will include only columns that were referenced
// in the user query. (SELECT * counts as referencing all columns.)
// This column_list can then be used for column-level ACL checking on tables.
//
// for_system_time_expr when non NULL resolves to TIMESTAMP used in
// FOR SYSTEM_TIME AS OF clause. The expression is expected to be constant
// and no columns are visible to it.
//
// If provided, <alias> refers to an explicit alias which was used to
// reference a Table in the user query. If the Table was given an implicitly
// generated alias, then defaults to "".
//
// TODO: Enforce <column_index_list> in the constructor arg list. For
// historical reasons, some clients match <column_list> to Table columns by
// name. All code building this should always set_column_index_list() to
// provide the indexes of all columns in <table> right after the construction
// of a ResolvedTableScan.
class ResolvedTableScan final : public ResolvedScan {
 public:
  typedef ResolvedScan SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_TABLE_SCAN;

  friend std::unique_ptr<ResolvedTableScan> MakeResolvedTableScan();
 protected:
  ResolvedTableScan()
      : ResolvedScan()
      , table_()
      , for_system_time_expr_()
      , column_index_list_()
      , alias_()
  {}
 public:

  ResolvedTableScan(const ResolvedTableScan&) = delete;
  ResolvedTableScan& operator=(const ResolvedTableScan&) = delete;

  friend std::unique_ptr<ResolvedTableScan> MakeResolvedTableScan(
      const std::vector<ResolvedColumn>& column_list,
      const Table* table,
      std::unique_ptr<const ResolvedExpr> for_system_time_expr,
      const std::string& alias
  );
  ~ResolvedTableScan() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_TABLE_SCAN; }
  std::string node_kind_string() const final { return "TableScan"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedTableScanProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedScanProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedTableScan>> RestoreFrom(
      const ResolvedTableScanProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  const Table* table() const {
    accessed_ |= (1<<0);
    return table_;
  }
  void set_table(const Table* v) {
    table_ = v;
  }

  const ResolvedExpr* for_system_time_expr() const {
    accessed_ |= (1<<1);
    return for_system_time_expr_.get();
  }
  void set_for_system_time_expr(std::unique_ptr<const ResolvedExpr> v) {
    for_system_time_expr_ = std::move(v);
  }

  std::unique_ptr<const ResolvedExpr> release_for_system_time_expr() {
    return std::move(for_system_time_expr_);
  }

  const std::vector<int>& column_index_list() const {
    accessed_ |= (1<<2);
    return column_index_list_;
  }
  int column_index_list_size() const {
    if (column_index_list_.empty()) accessed_ |= (1<<2);
    return static_cast<int>(column_index_list_.size());
  }
  int column_index_list(int i) const {
    accessed_ |= (1<<2);
    return column_index_list_.at(i);
  }
  void add_column_index_list(int v) {
    column_index_list_.push_back(int(v));
  }
  void set_column_index_list(const std::vector<int>& v) {
    column_index_list_ = v;
  }
  std::vector<int>* mutable_column_index_list() {
    accessed_ |= (1<<2);
    return &column_index_list_;
  }

  const std::string& alias() const {
    accessed_ |= (1<<3);
    return alias_;
  }
  void set_alias(const std::string& v) {
    alias_ = v;
  }

 protected:
  explicit ResolvedTableScan(
      const std::vector<ResolvedColumn>& column_list,
      const Table* table,
      std::unique_ptr<const ResolvedExpr> for_system_time_expr,
      const std::string& alias,
      ConstructorOverload)
      : ResolvedScan(
            column_list,
            ConstructorOverload::NEW_CONSTRUCTOR),
      table_(table),
      for_system_time_expr_(std::move(for_system_time_expr)),
      column_index_list_(),
      alias_(alias) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  const Table* table_;
  std::unique_ptr<const ResolvedExpr> for_system_time_expr_;
  std::vector<int> column_index_list_;
  std::string alias_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedTableScan> MakeResolvedTableScan(
    const std::vector<ResolvedColumn>& column_list,
    const Table* table,
    std::unique_ptr<const ResolvedExpr> for_system_time_expr,
    const std::string& alias) {
  return std::unique_ptr<ResolvedTableScan>(new ResolvedTableScan(
        column_list,
        table,
        std::move(for_system_time_expr),
        alias,
        ResolvedTableScan::NEW_CONSTRUCTOR));
}

inline std::unique_ptr<ResolvedTableScan> MakeResolvedTableScan() {
  return std::unique_ptr<ResolvedTableScan>(
      new ResolvedTableScan());
}

// A Scan that joins two input scans.
// The <column_list> will contain columns selected from the union
// of the input scan's <column_lists>.
// When the join is a LEFT/RIGHT/FULL join, ResolvedColumns that came from
// the non-joined side get NULL values.
class ResolvedJoinScan final : public ResolvedScan {
 public:
  typedef ResolvedScan SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_JOIN_SCAN;

  typedef ResolvedJoinScanEnums::JoinType JoinType;
  static const JoinType INNER = ResolvedJoinScanEnums::INNER;
  static const JoinType LEFT = ResolvedJoinScanEnums::LEFT;
  static const JoinType RIGHT = ResolvedJoinScanEnums::RIGHT;
  static const JoinType FULL = ResolvedJoinScanEnums::FULL;

  friend std::unique_ptr<ResolvedJoinScan> MakeResolvedJoinScan();
 protected:
  ResolvedJoinScan()
      : ResolvedScan()
      , join_type_()
      , left_scan_()
      , right_scan_()
      , join_expr_()
  {}
 public:

  ResolvedJoinScan(const ResolvedJoinScan&) = delete;
  ResolvedJoinScan& operator=(const ResolvedJoinScan&) = delete;

  friend std::unique_ptr<ResolvedJoinScan> MakeResolvedJoinScan(
      const std::vector<ResolvedColumn>& column_list,
      JoinType join_type,
      std::unique_ptr<const ResolvedScan> left_scan,
      std::unique_ptr<const ResolvedScan> right_scan,
      std::unique_ptr<const ResolvedExpr> join_expr
  );
  ~ResolvedJoinScan() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_JOIN_SCAN; }
  std::string node_kind_string() const final { return "JoinScan"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedJoinScanProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedScanProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedJoinScan>> RestoreFrom(
      const ResolvedJoinScanProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  JoinType join_type() const {
    accessed_ |= (1<<0);
    return join_type_;
  }
  void set_join_type(JoinType v) {
    join_type_ = v;
  }

  const ResolvedScan* left_scan() const {
    accessed_ |= (1<<1);
    return left_scan_.get();
  }
  void set_left_scan(std::unique_ptr<const ResolvedScan> v) {
    left_scan_ = std::move(v);
  }

  std::unique_ptr<const ResolvedScan> release_left_scan() {
    return std::move(left_scan_);
  }

  const ResolvedScan* right_scan() const {
    accessed_ |= (1<<2);
    return right_scan_.get();
  }
  void set_right_scan(std::unique_ptr<const ResolvedScan> v) {
    right_scan_ = std::move(v);
  }

  std::unique_ptr<const ResolvedScan> release_right_scan() {
    return std::move(right_scan_);
  }

  const ResolvedExpr* join_expr() const {
    accessed_ |= (1<<3);
    return join_expr_.get();
  }
  void set_join_expr(std::unique_ptr<const ResolvedExpr> v) {
    join_expr_ = std::move(v);
  }

  std::unique_ptr<const ResolvedExpr> release_join_expr() {
    return std::move(join_expr_);
  }

 protected:
  explicit ResolvedJoinScan(
      const std::vector<ResolvedColumn>& column_list,
      JoinType join_type,
      std::unique_ptr<const ResolvedScan> left_scan,
      std::unique_ptr<const ResolvedScan> right_scan,
      std::unique_ptr<const ResolvedExpr> join_expr,
      ConstructorOverload)
      : ResolvedScan(
            column_list,
            ConstructorOverload::NEW_CONSTRUCTOR),
      join_type_(join_type),
      left_scan_(std::move(left_scan)),
      right_scan_(std::move(right_scan)),
      join_expr_(std::move(join_expr)) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  JoinType join_type_;
  std::unique_ptr<const ResolvedScan> left_scan_;
  std::unique_ptr<const ResolvedScan> right_scan_;
  std::unique_ptr<const ResolvedExpr> join_expr_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedJoinScan> MakeResolvedJoinScan(
    const std::vector<ResolvedColumn>& column_list,
    ResolvedJoinScan::JoinType join_type,
    std::unique_ptr<const ResolvedScan> left_scan,
    std::unique_ptr<const ResolvedScan> right_scan,
    std::unique_ptr<const ResolvedExpr> join_expr) {
  return std::unique_ptr<ResolvedJoinScan>(new ResolvedJoinScan(
        column_list,
        join_type,
        std::move(left_scan),
        std::move(right_scan),
        std::move(join_expr),
        ResolvedJoinScan::NEW_CONSTRUCTOR));
}

inline std::unique_ptr<ResolvedJoinScan> MakeResolvedJoinScan() {
  return std::unique_ptr<ResolvedJoinScan>(
      new ResolvedJoinScan());
}

// Scan an array value, produced from some expression.
//
// If input_scan is NULL, this scans the given array value and produces
// one row per array element.  This can occur when using UNNEST(expression).
//
// If <input_scan> is non-NULL, for each row in the stream produced by
// input_scan, this evaluates the expression <array_expr> (which must return
// an array type) and then produces a stream with one row per array element.
//
// If <join_expr> is non-NULL, then this condition is evaluated as an ON
// clause for the array join.  The named column produced in <array_expr>
// may be used inside <join_expr>.
//
// If the array is empty (after evaluating <join_expr>), then
// 1. If <is_outer> is false, the scan produces zero rows.
// 2. If <is_outer> is true, the scan produces one row with a NULL value for
//    the <element_column>.
//
// <element_column> is the new column produced by this scan that stores the
// array element value for each row.
//
// If present, <array_offset_column> defines the column produced by this
// scan that stores the array offset (0-based) for the corresponding
// <element_column>.
//
// This node's column_list can have columns from input_scan, <element_column>
// and <array_offset_column>.
class ResolvedArrayScan final : public ResolvedScan {
 public:
  typedef ResolvedScan SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_ARRAY_SCAN;

  friend std::unique_ptr<ResolvedArrayScan> MakeResolvedArrayScan();
 protected:
  ResolvedArrayScan()
      : ResolvedScan()
      , input_scan_()
      , array_expr_()
      , element_column_()
      , array_offset_column_()
      , join_expr_()
      , is_outer_()
  {}
 public:

  ResolvedArrayScan(const ResolvedArrayScan&) = delete;
  ResolvedArrayScan& operator=(const ResolvedArrayScan&) = delete;

  friend std::unique_ptr<ResolvedArrayScan> MakeResolvedArrayScan(
      const std::vector<ResolvedColumn>& column_list,
      std::unique_ptr<const ResolvedScan> input_scan,
      std::unique_ptr<const ResolvedExpr> array_expr,
      const ResolvedColumn& element_column,
      std::unique_ptr<const ResolvedColumnHolder> array_offset_column,
      std::unique_ptr<const ResolvedExpr> join_expr,
      bool is_outer
  );
  ~ResolvedArrayScan() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_ARRAY_SCAN; }
  std::string node_kind_string() const final { return "ArrayScan"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedArrayScanProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedScanProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedArrayScan>> RestoreFrom(
      const ResolvedArrayScanProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  const ResolvedScan* input_scan() const {
    accessed_ |= (1<<0);
    return input_scan_.get();
  }
  void set_input_scan(std::unique_ptr<const ResolvedScan> v) {
    input_scan_ = std::move(v);
  }

  std::unique_ptr<const ResolvedScan> release_input_scan() {
    return std::move(input_scan_);
  }

  const ResolvedExpr* array_expr() const {
    accessed_ |= (1<<1);
    return array_expr_.get();
  }
  void set_array_expr(std::unique_ptr<const ResolvedExpr> v) {
    array_expr_ = std::move(v);
  }

  std::unique_ptr<const ResolvedExpr> release_array_expr() {
    return std::move(array_expr_);
  }

  const ResolvedColumn& element_column() const {
    accessed_ |= (1<<2);
    return element_column_;
  }
  void set_element_column(const ResolvedColumn& v) {
    element_column_ = v;
  }

  const ResolvedColumnHolder* array_offset_column() const {
    accessed_ |= (1<<3);
    return array_offset_column_.get();
  }
  void set_array_offset_column(std::unique_ptr<const ResolvedColumnHolder> v) {
    array_offset_column_ = std::move(v);
  }

  std::unique_ptr<const ResolvedColumnHolder> release_array_offset_column() {
    return std::move(array_offset_column_);
  }

  const ResolvedExpr* join_expr() const {
    accessed_ |= (1<<4);
    return join_expr_.get();
  }
  void set_join_expr(std::unique_ptr<const ResolvedExpr> v) {
    join_expr_ = std::move(v);
  }

  std::unique_ptr<const ResolvedExpr> release_join_expr() {
    return std::move(join_expr_);
  }

  bool is_outer() const {
    accessed_ |= (1<<5);
    return is_outer_;
  }
  void set_is_outer(bool v) {
    is_outer_ = v;
  }

 protected:
  explicit ResolvedArrayScan(
      const std::vector<ResolvedColumn>& column_list,
      std::unique_ptr<const ResolvedScan> input_scan,
      std::unique_ptr<const ResolvedExpr> array_expr,
      const ResolvedColumn& element_column,
      std::unique_ptr<const ResolvedColumnHolder> array_offset_column,
      std::unique_ptr<const ResolvedExpr> join_expr,
      bool is_outer,
      ConstructorOverload)
      : ResolvedScan(
            column_list,
            ConstructorOverload::NEW_CONSTRUCTOR),
      input_scan_(std::move(input_scan)),
      array_expr_(std::move(array_expr)),
      element_column_(element_column),
      array_offset_column_(std::move(array_offset_column)),
      join_expr_(std::move(join_expr)),
      is_outer_(is_outer) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  std::unique_ptr<const ResolvedScan> input_scan_;
  std::unique_ptr<const ResolvedExpr> array_expr_;
  ResolvedColumn element_column_;
  std::unique_ptr<const ResolvedColumnHolder> array_offset_column_;
  std::unique_ptr<const ResolvedExpr> join_expr_;
  bool is_outer_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedArrayScan> MakeResolvedArrayScan(
    const std::vector<ResolvedColumn>& column_list,
    std::unique_ptr<const ResolvedScan> input_scan,
    std::unique_ptr<const ResolvedExpr> array_expr,
    const ResolvedColumn& element_column,
    std::unique_ptr<const ResolvedColumnHolder> array_offset_column,
    std::unique_ptr<const ResolvedExpr> join_expr,
    bool is_outer) {
  return std::unique_ptr<ResolvedArrayScan>(new ResolvedArrayScan(
        column_list,
        std::move(input_scan),
        std::move(array_expr),
        element_column,
        std::move(array_offset_column),
        std::move(join_expr),
        is_outer,
        ResolvedArrayScan::NEW_CONSTRUCTOR));
}

inline std::unique_ptr<ResolvedArrayScan> MakeResolvedArrayScan() {
  return std::unique_ptr<ResolvedArrayScan>(
      new ResolvedArrayScan());
}

// This wrapper is used for an optional ResolvedColumn inside another node.
class ResolvedColumnHolder final : public ResolvedArgument {
 public:
  typedef ResolvedArgument SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_COLUMN_HOLDER;

  friend std::unique_ptr<ResolvedColumnHolder> MakeResolvedColumnHolder();
 protected:
  ResolvedColumnHolder()
      : ResolvedArgument()
      , column_()
  {}
 public:

  ResolvedColumnHolder(const ResolvedColumnHolder&) = delete;
  ResolvedColumnHolder& operator=(const ResolvedColumnHolder&) = delete;

  friend std::unique_ptr<ResolvedColumnHolder> MakeResolvedColumnHolder(
      const ResolvedColumn& column
  );
  ~ResolvedColumnHolder() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_COLUMN_HOLDER; }
  std::string node_kind_string() const final { return "ColumnHolder"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedColumnHolderProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedArgumentProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedColumnHolder>> RestoreFrom(
      const ResolvedColumnHolderProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  const ResolvedColumn& column() const {
    accessed_ |= (1<<0);
    return column_;
  }
  void set_column(const ResolvedColumn& v) {
    column_ = v;
  }

 protected:
  explicit ResolvedColumnHolder(
      const ResolvedColumn& column,
      ConstructorOverload)
      : ResolvedArgument(
            ConstructorOverload::NEW_CONSTRUCTOR),
      column_(column) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  ResolvedColumn column_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedColumnHolder> MakeResolvedColumnHolder(
    const ResolvedColumn& column) {
  return std::unique_ptr<ResolvedColumnHolder>(new ResolvedColumnHolder(
        column,
        ResolvedColumnHolder::NEW_CONSTRUCTOR));
}

inline std::unique_ptr<ResolvedColumnHolder> MakeResolvedColumnHolder() {
  return std::unique_ptr<ResolvedColumnHolder>(
      new ResolvedColumnHolder());
}

// Scan rows from input_scan, and emit all rows where filter_expr
// evaluates to true.  filter_expr is always of type bool.
// This node's column_list will be a subset of input_scan's column_list.
class ResolvedFilterScan final : public ResolvedScan {
 public:
  typedef ResolvedScan SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_FILTER_SCAN;

  friend std::unique_ptr<ResolvedFilterScan> MakeResolvedFilterScan();
 protected:
  ResolvedFilterScan()
      : ResolvedScan()
      , input_scan_()
      , filter_expr_()
  {}
 public:

  ResolvedFilterScan(const ResolvedFilterScan&) = delete;
  ResolvedFilterScan& operator=(const ResolvedFilterScan&) = delete;

  friend std::unique_ptr<ResolvedFilterScan> MakeResolvedFilterScan(
      const std::vector<ResolvedColumn>& column_list,
      std::unique_ptr<const ResolvedScan> input_scan,
      std::unique_ptr<const ResolvedExpr> filter_expr
  );
  ~ResolvedFilterScan() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_FILTER_SCAN; }
  std::string node_kind_string() const final { return "FilterScan"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedFilterScanProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedScanProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedFilterScan>> RestoreFrom(
      const ResolvedFilterScanProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  const ResolvedScan* input_scan() const {
    accessed_ |= (1<<0);
    return input_scan_.get();
  }
  void set_input_scan(std::unique_ptr<const ResolvedScan> v) {
    input_scan_ = std::move(v);
  }

  std::unique_ptr<const ResolvedScan> release_input_scan() {
    return std::move(input_scan_);
  }

  const ResolvedExpr* filter_expr() const {
    accessed_ |= (1<<1);
    return filter_expr_.get();
  }
  void set_filter_expr(std::unique_ptr<const ResolvedExpr> v) {
    filter_expr_ = std::move(v);
  }

  std::unique_ptr<const ResolvedExpr> release_filter_expr() {
    return std::move(filter_expr_);
  }

 protected:
  explicit ResolvedFilterScan(
      const std::vector<ResolvedColumn>& column_list,
      std::unique_ptr<const ResolvedScan> input_scan,
      std::unique_ptr<const ResolvedExpr> filter_expr,
      ConstructorOverload)
      : ResolvedScan(
            column_list,
            ConstructorOverload::NEW_CONSTRUCTOR),
      input_scan_(std::move(input_scan)),
      filter_expr_(std::move(filter_expr)) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  std::unique_ptr<const ResolvedScan> input_scan_;
  std::unique_ptr<const ResolvedExpr> filter_expr_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedFilterScan> MakeResolvedFilterScan(
    const std::vector<ResolvedColumn>& column_list,
    std::unique_ptr<const ResolvedScan> input_scan,
    std::unique_ptr<const ResolvedExpr> filter_expr) {
  return std::unique_ptr<ResolvedFilterScan>(new ResolvedFilterScan(
        column_list,
        std::move(input_scan),
        std::move(filter_expr),
        ResolvedFilterScan::NEW_CONSTRUCTOR));
}

inline std::unique_ptr<ResolvedFilterScan> MakeResolvedFilterScan() {
  return std::unique_ptr<ResolvedFilterScan>(
      new ResolvedFilterScan());
}

// List of group by columns that form a grouping set.
//
// Columns must come from group_by_list in ResolvedAggregateScan.
// group_by_column_list will not contain any duplicates. There may be more
// than one ResolvedGroupingSet in the ResolvedAggregateScan with the same
// columns, however.
class ResolvedGroupingSet final : public ResolvedArgument {
 public:
  typedef ResolvedArgument SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_GROUPING_SET;

  friend std::unique_ptr<ResolvedGroupingSet> MakeResolvedGroupingSet();
 protected:
  ResolvedGroupingSet()
      : ResolvedArgument()
      , group_by_column_list_()
  {}
 public:

  ResolvedGroupingSet(const ResolvedGroupingSet&) = delete;
  ResolvedGroupingSet& operator=(const ResolvedGroupingSet&) = delete;

  friend std::unique_ptr<ResolvedGroupingSet> MakeResolvedGroupingSet(
      std::vector<std::unique_ptr<const ResolvedColumnRef>> group_by_column_list
  );
  ~ResolvedGroupingSet() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_GROUPING_SET; }
  std::string node_kind_string() const final { return "GroupingSet"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedGroupingSetProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedArgumentProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedGroupingSet>> RestoreFrom(
      const ResolvedGroupingSetProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  const std::vector<std::unique_ptr<const ResolvedColumnRef>>& group_by_column_list() const {
    accessed_ |= (1<<0);
    return group_by_column_list_;
  }
  int group_by_column_list_size() const {
    if (group_by_column_list_.empty()) accessed_ |= (1<<0);
    return static_cast<int>(group_by_column_list_.size());
  }
  const ResolvedColumnRef* group_by_column_list(int i) const {
    accessed_ |= (1<<0);
    return group_by_column_list_.at(i).get();
  }
  void add_group_by_column_list(std::unique_ptr<const ResolvedColumnRef> v) {
    group_by_column_list_.emplace_back(std::move(v));
  }
  void set_group_by_column_list(std::vector<std::unique_ptr<const ResolvedColumnRef>> v) {
    group_by_column_list_ = std::move(v);
  }

  std::vector<std::unique_ptr<const ResolvedColumnRef>> release_group_by_column_list() {
    std::vector<std::unique_ptr<const ResolvedColumnRef>> tmp;
    group_by_column_list_.swap(tmp);
    return tmp;
  }

 protected:
  explicit ResolvedGroupingSet(
      std::vector<std::unique_ptr<const ResolvedColumnRef>> group_by_column_list,
      ConstructorOverload)
      : ResolvedArgument(
            ConstructorOverload::NEW_CONSTRUCTOR),
      group_by_column_list_(std::move(group_by_column_list)) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  std::vector<std::unique_ptr<const ResolvedColumnRef>> group_by_column_list_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedGroupingSet> MakeResolvedGroupingSet(
    std::vector<std::unique_ptr<const ResolvedColumnRef>> group_by_column_list) {
  return std::unique_ptr<ResolvedGroupingSet>(new ResolvedGroupingSet(
        std::move(group_by_column_list),
        ResolvedGroupingSet::NEW_CONSTRUCTOR));
}

// Overloaded factory method for the construction of ResolvedGroupingSet with
// a wider range of inputs for node-vector inputs.  In particular allows:
// 1. unique_ptr element type can be non-const.
// 2. unique_ptr element type can be any descendant of the required type.
// 3. input container can be any object with a `begin()` and `end()`.
//
// Note, initializer lists cannot be used to pass
//  group_by_column_list
// due to incompatibility with unique_ptr.  Use zetasql::MakeNodeVector
// instead.
template <
  typename group_by_column_list_t
      = std::vector<std::unique_ptr<const ResolvedColumnRef>>>
std::unique_ptr<ResolvedGroupingSet> MakeResolvedGroupingSet(
    group_by_column_list_t group_by_column_list) {
  static_assert(std::is_base_of<
      ResolvedColumnRef,
      typename std::decay<decltype(**(group_by_column_list.begin()))>::type>::value,
      "group_by_column_list must be a container of unique_ptr with elements of type "
      "ResolvedColumnRef (or its descendants).");
  return MakeResolvedGroupingSet(
      {std::make_move_iterator(group_by_column_list.begin()),
       std::make_move_iterator(group_by_column_list.end())});
}

inline std::unique_ptr<ResolvedGroupingSet> MakeResolvedGroupingSet() {
  return std::unique_ptr<ResolvedGroupingSet>(
      new ResolvedGroupingSet());
}

// Base class for aggregation scans. Apply aggregation to rows produced from
// input_scan, and output aggregated rows.
//
// Group by keys in <group_by_list>.  If <group_by_list> is empty,
// aggregate all input rows into one output row.
//
// Compute all aggregations in <aggregate_list>.  All expressions in
// <aggregate_list> have a ResolvedAggregateFunctionCall with mode
// Function::AGGREGATE as their outermost node.
//
// The output <column_list> contains only columns produced from
// <group_by_list> and <aggregate_list>.  No other columns are visible after
// aggregation.
class ResolvedAggregateScanBase  : public ResolvedScan {
 public:
  typedef ResolvedScan SUPER;

  // Number of leaf node types that exist as descendants of this abstract type.
  static const int NUM_DESCENDANT_LEAF_TYPES = 1;

  ResolvedAggregateScanBase()
      : ResolvedScan()
      , input_scan_()
      , group_by_list_()
      , aggregate_list_()
  {}
 public:

  ResolvedAggregateScanBase(const ResolvedAggregateScanBase&) = delete;
  ResolvedAggregateScanBase& operator=(const ResolvedAggregateScanBase&) = delete;

  ~ResolvedAggregateScanBase() override;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const override;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const override;

  zetasql_base::Status CheckFieldsAccessed() const override;
  void ClearFieldsAccessed() const override;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedAggregateScanBaseProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedScanProto* proto) const final;

  virtual zetasql_base::Status SaveTo(
      Type::FileDescriptorSetMap* file_descriptor_set_map,
      AnyResolvedAggregateScanBaseProto* proto) const = 0;
  static zetasql_base::StatusOr<std::unique_ptr<ResolvedAggregateScanBase>> RestoreFrom(
      const AnyResolvedAggregateScanBaseProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const override;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) override;

  // Member fields

  const ResolvedScan* input_scan() const {
    accessed_ |= (1<<0);
    return input_scan_.get();
  }
  void set_input_scan(std::unique_ptr<const ResolvedScan> v) {
    input_scan_ = std::move(v);
  }

  std::unique_ptr<const ResolvedScan> release_input_scan() {
    return std::move(input_scan_);
  }

  const std::vector<std::unique_ptr<const ResolvedComputedColumn>>& group_by_list() const {
    accessed_ |= (1<<1);
    return group_by_list_;
  }
  int group_by_list_size() const {
    if (group_by_list_.empty()) accessed_ |= (1<<1);
    return static_cast<int>(group_by_list_.size());
  }
  const ResolvedComputedColumn* group_by_list(int i) const {
    accessed_ |= (1<<1);
    return group_by_list_.at(i).get();
  }
  void add_group_by_list(std::unique_ptr<const ResolvedComputedColumn> v) {
    group_by_list_.emplace_back(std::move(v));
  }
  void set_group_by_list(std::vector<std::unique_ptr<const ResolvedComputedColumn>> v) {
    group_by_list_ = std::move(v);
  }

  std::vector<std::unique_ptr<const ResolvedComputedColumn>> release_group_by_list() {
    std::vector<std::unique_ptr<const ResolvedComputedColumn>> tmp;
    group_by_list_.swap(tmp);
    return tmp;
  }

  const std::vector<std::unique_ptr<const ResolvedComputedColumn>>& aggregate_list() const {
    accessed_ |= (1<<2);
    return aggregate_list_;
  }
  int aggregate_list_size() const {
    if (aggregate_list_.empty()) accessed_ |= (1<<2);
    return static_cast<int>(aggregate_list_.size());
  }
  const ResolvedComputedColumn* aggregate_list(int i) const {
    accessed_ |= (1<<2);
    return aggregate_list_.at(i).get();
  }
  void add_aggregate_list(std::unique_ptr<const ResolvedComputedColumn> v) {
    aggregate_list_.emplace_back(std::move(v));
  }
  void set_aggregate_list(std::vector<std::unique_ptr<const ResolvedComputedColumn>> v) {
    aggregate_list_ = std::move(v);
  }

  std::vector<std::unique_ptr<const ResolvedComputedColumn>> release_aggregate_list() {
    std::vector<std::unique_ptr<const ResolvedComputedColumn>> tmp;
    aggregate_list_.swap(tmp);
    return tmp;
  }

 protected:
  explicit ResolvedAggregateScanBase(
      const std::vector<ResolvedColumn>& column_list,
      std::unique_ptr<const ResolvedScan> input_scan,
      std::vector<std::unique_ptr<const ResolvedComputedColumn>> group_by_list,
      std::vector<std::unique_ptr<const ResolvedComputedColumn>> aggregate_list,
      ConstructorOverload)
      : ResolvedScan(
            column_list,
            ConstructorOverload::NEW_CONSTRUCTOR),
      input_scan_(std::move(input_scan)),
      group_by_list_(std::move(group_by_list)),
      aggregate_list_(std::move(aggregate_list)) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const override;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  std::unique_ptr<const ResolvedScan> input_scan_;
  std::vector<std::unique_ptr<const ResolvedComputedColumn>> group_by_list_;
  std::vector<std::unique_ptr<const ResolvedComputedColumn>> aggregate_list_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

// Apply aggregation to rows produced from input_scan, and output aggregated
// rows.
//
// For each item in <grouping_set_list>, output additional rows computing the
// same <aggregate_list> over the input rows using a particular grouping set.
// The aggregation input values, including <input_scan>, computed columns in
// <group_by_list>, and aggregate function arguments in <aggregate_list>,
// should be computed just once and then reused as aggregation input for each
// grouping set. (This ensures that ROLLUP rows have correct totals, even
// with non-stable functions in the input.) For each grouping set, the
// <group_by_list> elements not included in the <group_by_column_list> are
// replaced with NULL.
//
// <rollup_column_list> is the original list of columns from
// GROUP BY ROLLUP(...), if there was a ROLLUP clause, and is used only for
// rebuilding equivalent SQL for the resolved AST. Engines should refer to
// <grouping_set_list> rather than <rollup_column_list>.
class ResolvedAggregateScan final : public ResolvedAggregateScanBase {
 public:
  typedef ResolvedAggregateScanBase SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_AGGREGATE_SCAN;

  friend std::unique_ptr<ResolvedAggregateScan> MakeResolvedAggregateScan();
 protected:
  ResolvedAggregateScan()
      : ResolvedAggregateScanBase()
      , grouping_set_list_()
      , rollup_column_list_()
  {}
 public:

  ResolvedAggregateScan(const ResolvedAggregateScan&) = delete;
  ResolvedAggregateScan& operator=(const ResolvedAggregateScan&) = delete;

  friend std::unique_ptr<ResolvedAggregateScan> MakeResolvedAggregateScan(
      const std::vector<ResolvedColumn>& column_list,
      std::unique_ptr<const ResolvedScan> input_scan,
      std::vector<std::unique_ptr<const ResolvedComputedColumn>> group_by_list,
      std::vector<std::unique_ptr<const ResolvedComputedColumn>> aggregate_list,
      std::vector<std::unique_ptr<const ResolvedGroupingSet>> grouping_set_list,
      std::vector<std::unique_ptr<const ResolvedColumnRef>> rollup_column_list
  );
  ~ResolvedAggregateScan() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_AGGREGATE_SCAN; }
  std::string node_kind_string() const final { return "AggregateScan"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedAggregateScanProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedAggregateScanBaseProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedAggregateScan>> RestoreFrom(
      const ResolvedAggregateScanProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  const std::vector<std::unique_ptr<const ResolvedGroupingSet>>& grouping_set_list() const {
    accessed_ |= (1<<0);
    return grouping_set_list_;
  }
  int grouping_set_list_size() const {
    if (grouping_set_list_.empty()) accessed_ |= (1<<0);
    return static_cast<int>(grouping_set_list_.size());
  }
  const ResolvedGroupingSet* grouping_set_list(int i) const {
    accessed_ |= (1<<0);
    return grouping_set_list_.at(i).get();
  }
  void add_grouping_set_list(std::unique_ptr<const ResolvedGroupingSet> v) {
    grouping_set_list_.emplace_back(std::move(v));
  }
  void set_grouping_set_list(std::vector<std::unique_ptr<const ResolvedGroupingSet>> v) {
    grouping_set_list_ = std::move(v);
  }

  std::vector<std::unique_ptr<const ResolvedGroupingSet>> release_grouping_set_list() {
    std::vector<std::unique_ptr<const ResolvedGroupingSet>> tmp;
    grouping_set_list_.swap(tmp);
    return tmp;
  }

  const std::vector<std::unique_ptr<const ResolvedColumnRef>>& rollup_column_list() const {
    accessed_ |= (1<<1);
    return rollup_column_list_;
  }
  int rollup_column_list_size() const {
    if (rollup_column_list_.empty()) accessed_ |= (1<<1);
    return static_cast<int>(rollup_column_list_.size());
  }
  const ResolvedColumnRef* rollup_column_list(int i) const {
    accessed_ |= (1<<1);
    return rollup_column_list_.at(i).get();
  }
  void add_rollup_column_list(std::unique_ptr<const ResolvedColumnRef> v) {
    rollup_column_list_.emplace_back(std::move(v));
  }
  void set_rollup_column_list(std::vector<std::unique_ptr<const ResolvedColumnRef>> v) {
    rollup_column_list_ = std::move(v);
  }

  std::vector<std::unique_ptr<const ResolvedColumnRef>> release_rollup_column_list() {
    std::vector<std::unique_ptr<const ResolvedColumnRef>> tmp;
    rollup_column_list_.swap(tmp);
    return tmp;
  }

 protected:
  explicit ResolvedAggregateScan(
      const std::vector<ResolvedColumn>& column_list,
      std::unique_ptr<const ResolvedScan> input_scan,
      std::vector<std::unique_ptr<const ResolvedComputedColumn>> group_by_list,
      std::vector<std::unique_ptr<const ResolvedComputedColumn>> aggregate_list,
      std::vector<std::unique_ptr<const ResolvedGroupingSet>> grouping_set_list,
      std::vector<std::unique_ptr<const ResolvedColumnRef>> rollup_column_list,
      ConstructorOverload)
      : ResolvedAggregateScanBase(
            column_list,
            std::move(input_scan),
            std::move(group_by_list),
            std::move(aggregate_list),
            ConstructorOverload::NEW_CONSTRUCTOR),
      grouping_set_list_(std::move(grouping_set_list)),
      rollup_column_list_(std::move(rollup_column_list)) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  std::vector<std::unique_ptr<const ResolvedGroupingSet>> grouping_set_list_;
  std::vector<std::unique_ptr<const ResolvedColumnRef>> rollup_column_list_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedAggregateScan> MakeResolvedAggregateScan(
    const std::vector<ResolvedColumn>& column_list,
    std::unique_ptr<const ResolvedScan> input_scan,
    std::vector<std::unique_ptr<const ResolvedComputedColumn>> group_by_list,
    std::vector<std::unique_ptr<const ResolvedComputedColumn>> aggregate_list,
    std::vector<std::unique_ptr<const ResolvedGroupingSet>> grouping_set_list,
    std::vector<std::unique_ptr<const ResolvedColumnRef>> rollup_column_list) {
  return std::unique_ptr<ResolvedAggregateScan>(new ResolvedAggregateScan(
        column_list,
        std::move(input_scan),
        std::move(group_by_list),
        std::move(aggregate_list),
        std::move(grouping_set_list),
        std::move(rollup_column_list),
        ResolvedAggregateScan::NEW_CONSTRUCTOR));
}

// Overloaded factory method for the construction of ResolvedAggregateScan with
// a wider range of inputs for node-vector inputs.  In particular allows:
// 1. unique_ptr element type can be non-const.
// 2. unique_ptr element type can be any descendant of the required type.
// 3. input container can be any object with a `begin()` and `end()`.
//
// Note, initializer lists cannot be used to pass
//  group_by_list, aggregate_list, grouping_set_list, rollup_column_list
// due to incompatibility with unique_ptr.  Use zetasql::MakeNodeVector
// instead.
template <
  typename group_by_list_t
      = std::vector<std::unique_ptr<const ResolvedComputedColumn>>,
  typename aggregate_list_t
      = std::vector<std::unique_ptr<const ResolvedComputedColumn>>,
  typename grouping_set_list_t
      = std::vector<std::unique_ptr<const ResolvedGroupingSet>>,
  typename rollup_column_list_t
      = std::vector<std::unique_ptr<const ResolvedColumnRef>>>
std::unique_ptr<ResolvedAggregateScan> MakeResolvedAggregateScan(
    const std::vector<ResolvedColumn>& column_list,
    std::unique_ptr<const ResolvedScan> input_scan,
    group_by_list_t group_by_list,
    aggregate_list_t aggregate_list,
    grouping_set_list_t grouping_set_list,
    rollup_column_list_t rollup_column_list) {
  static_assert(std::is_base_of<
      ResolvedComputedColumn,
      typename std::decay<decltype(**(group_by_list.begin()))>::type>::value,
      "group_by_list must be a container of unique_ptr with elements of type "
      "ResolvedComputedColumn (or its descendants).");
  static_assert(std::is_base_of<
      ResolvedComputedColumn,
      typename std::decay<decltype(**(aggregate_list.begin()))>::type>::value,
      "aggregate_list must be a container of unique_ptr with elements of type "
      "ResolvedComputedColumn (or its descendants).");
  static_assert(std::is_base_of<
      ResolvedGroupingSet,
      typename std::decay<decltype(**(grouping_set_list.begin()))>::type>::value,
      "grouping_set_list must be a container of unique_ptr with elements of type "
      "ResolvedGroupingSet (or its descendants).");
  static_assert(std::is_base_of<
      ResolvedColumnRef,
      typename std::decay<decltype(**(rollup_column_list.begin()))>::type>::value,
      "rollup_column_list must be a container of unique_ptr with elements of type "
      "ResolvedColumnRef (or its descendants).");
  return MakeResolvedAggregateScan(
      column_list,
      std::move(input_scan),
      {std::make_move_iterator(group_by_list.begin()),
       std::make_move_iterator(group_by_list.end())},
      {std::make_move_iterator(aggregate_list.begin()),
       std::make_move_iterator(aggregate_list.end())},
      {std::make_move_iterator(grouping_set_list.begin()),
       std::make_move_iterator(grouping_set_list.end())},
      {std::make_move_iterator(rollup_column_list.begin()),
       std::make_move_iterator(rollup_column_list.end())});
}

inline std::unique_ptr<ResolvedAggregateScan> MakeResolvedAggregateScan() {
  return std::unique_ptr<ResolvedAggregateScan>(
      new ResolvedAggregateScan());
}

// This is one input item in a ResolvedSetOperation.
// The <output_column_list> matches 1:1 with the ResolvedSetOperation's
// <column_list> and specifies how columns from <scan> map to output columns.
// Each column from <scan> can map to zero or more output columns.
class ResolvedSetOperationItem final : public ResolvedArgument {
 public:
  typedef ResolvedArgument SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_SET_OPERATION_ITEM;

  friend std::unique_ptr<ResolvedSetOperationItem> MakeResolvedSetOperationItem();
 protected:
  ResolvedSetOperationItem()
      : ResolvedArgument()
      , scan_()
      , output_column_list_()
  {}
 public:

  ResolvedSetOperationItem(const ResolvedSetOperationItem&) = delete;
  ResolvedSetOperationItem& operator=(const ResolvedSetOperationItem&) = delete;

  friend std::unique_ptr<ResolvedSetOperationItem> MakeResolvedSetOperationItem(
      std::unique_ptr<const ResolvedScan> scan,
      const std::vector<ResolvedColumn>& output_column_list
  );
  ~ResolvedSetOperationItem() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_SET_OPERATION_ITEM; }
  std::string node_kind_string() const final { return "SetOperationItem"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedSetOperationItemProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedArgumentProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedSetOperationItem>> RestoreFrom(
      const ResolvedSetOperationItemProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  const ResolvedScan* scan() const {
    accessed_ |= (1<<0);
    return scan_.get();
  }
  void set_scan(std::unique_ptr<const ResolvedScan> v) {
    scan_ = std::move(v);
  }

  std::unique_ptr<const ResolvedScan> release_scan() {
    return std::move(scan_);
  }

  const std::vector<ResolvedColumn>& output_column_list() const {
    accessed_ |= (1<<1);
    return output_column_list_;
  }
  int output_column_list_size() const {
    if (output_column_list_.empty()) accessed_ |= (1<<1);
    return static_cast<int>(output_column_list_.size());
  }
  ResolvedColumn output_column_list(int i) const {
    accessed_ |= (1<<1);
    return output_column_list_.at(i);
  }
  void add_output_column_list(ResolvedColumn v) {
    output_column_list_.push_back(ResolvedColumn(v));
  }
  void set_output_column_list(const std::vector<ResolvedColumn>& v) {
    output_column_list_ = v;
  }
  std::vector<ResolvedColumn>* mutable_output_column_list() {
    accessed_ |= (1<<1);
    return &output_column_list_;
  }

 protected:
  explicit ResolvedSetOperationItem(
      std::unique_ptr<const ResolvedScan> scan,
      const std::vector<ResolvedColumn>& output_column_list,
      ConstructorOverload)
      : ResolvedArgument(
            ConstructorOverload::NEW_CONSTRUCTOR),
      scan_(std::move(scan)),
      output_column_list_(output_column_list) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  std::unique_ptr<const ResolvedScan> scan_;
  std::vector<ResolvedColumn> output_column_list_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedSetOperationItem> MakeResolvedSetOperationItem(
    std::unique_ptr<const ResolvedScan> scan,
    const std::vector<ResolvedColumn>& output_column_list) {
  return std::unique_ptr<ResolvedSetOperationItem>(new ResolvedSetOperationItem(
        std::move(scan),
        output_column_list,
        ResolvedSetOperationItem::NEW_CONSTRUCTOR));
}

inline std::unique_ptr<ResolvedSetOperationItem> MakeResolvedSetOperationItem() {
  return std::unique_ptr<ResolvedSetOperationItem>(
      new ResolvedSetOperationItem());
}

// Apply a set operation (specified by <op_type>) on two or more input scans.
//
// <scan_list> will have at least two elements.
//
// <column_list> is a set of new ResolvedColumns created by this scan.
// Each input ResolvedSetOperationItem has an <output_column_list> which
// matches 1:1 with <column_list> and specifies how the input <scan>'s
// columns map into the final <column_list>.
//
// - Results of {UNION, INTERSECT, EXCEPT} ALL can include duplicate rows.
//   More precisely, with two input scans, if a given row R appears exactly
//   m times in first input and n times in second input (m >= 0, n >= 0):
//   For UNION ALL, R will appear exactly m + n times in the result.
//   For INTERSECT ALL, R will appear exactly min(m, n) in the result.
//   For EXCEPT ALL, R will appear exactly max(m - n, 0) in the result.
//
// - Results of {UNION, INTERSECT, EXCEPT} DISTINCT cannot contain any
//   duplicate rows. For UNION and INTERSECT, the DISTINCT is computed
//   after the result above is computed.  For EXCEPT DISTINCT, row R will
//   appear once in the output if m > 0 and n = 0.
//
// - For n (>2) input scans, the above operations generalize so the output is
//   the same as if the inputs were combined incrementally from left to right.
class ResolvedSetOperationScan final : public ResolvedScan {
 public:
  typedef ResolvedScan SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_SET_OPERATION_SCAN;

  typedef ResolvedSetOperationScanEnums::SetOperationType SetOperationType;
  static const SetOperationType UNION_ALL = ResolvedSetOperationScanEnums::UNION_ALL;
  static const SetOperationType UNION_DISTINCT = ResolvedSetOperationScanEnums::UNION_DISTINCT;
  static const SetOperationType INTERSECT_ALL = ResolvedSetOperationScanEnums::INTERSECT_ALL;
  static const SetOperationType INTERSECT_DISTINCT = ResolvedSetOperationScanEnums::INTERSECT_DISTINCT;
  static const SetOperationType EXCEPT_ALL = ResolvedSetOperationScanEnums::EXCEPT_ALL;
  static const SetOperationType EXCEPT_DISTINCT = ResolvedSetOperationScanEnums::EXCEPT_DISTINCT;

  friend std::unique_ptr<ResolvedSetOperationScan> MakeResolvedSetOperationScan();
 protected:
  ResolvedSetOperationScan()
      : ResolvedScan()
      , op_type_()
      , input_item_list_()
  {}
 public:

  ResolvedSetOperationScan(const ResolvedSetOperationScan&) = delete;
  ResolvedSetOperationScan& operator=(const ResolvedSetOperationScan&) = delete;

  friend std::unique_ptr<ResolvedSetOperationScan> MakeResolvedSetOperationScan(
      const std::vector<ResolvedColumn>& column_list,
      SetOperationType op_type,
      std::vector<std::unique_ptr<const ResolvedSetOperationItem>> input_item_list
  );
  ~ResolvedSetOperationScan() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_SET_OPERATION_SCAN; }
  std::string node_kind_string() const final { return "SetOperationScan"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedSetOperationScanProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedScanProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedSetOperationScan>> RestoreFrom(
      const ResolvedSetOperationScanProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  SetOperationType op_type() const {
    accessed_ |= (1<<0);
    return op_type_;
  }
  void set_op_type(SetOperationType v) {
    op_type_ = v;
  }

  const std::vector<std::unique_ptr<const ResolvedSetOperationItem>>& input_item_list() const {
    accessed_ |= (1<<1);
    return input_item_list_;
  }
  int input_item_list_size() const {
    if (input_item_list_.empty()) accessed_ |= (1<<1);
    return static_cast<int>(input_item_list_.size());
  }
  const ResolvedSetOperationItem* input_item_list(int i) const {
    accessed_ |= (1<<1);
    return input_item_list_.at(i).get();
  }
  void add_input_item_list(std::unique_ptr<const ResolvedSetOperationItem> v) {
    input_item_list_.emplace_back(std::move(v));
  }
  void set_input_item_list(std::vector<std::unique_ptr<const ResolvedSetOperationItem>> v) {
    input_item_list_ = std::move(v);
  }

  std::vector<std::unique_ptr<const ResolvedSetOperationItem>> release_input_item_list() {
    std::vector<std::unique_ptr<const ResolvedSetOperationItem>> tmp;
    input_item_list_.swap(tmp);
    return tmp;
  }

 protected:
  explicit ResolvedSetOperationScan(
      const std::vector<ResolvedColumn>& column_list,
      SetOperationType op_type,
      std::vector<std::unique_ptr<const ResolvedSetOperationItem>> input_item_list,
      ConstructorOverload)
      : ResolvedScan(
            column_list,
            ConstructorOverload::NEW_CONSTRUCTOR),
      op_type_(op_type),
      input_item_list_(std::move(input_item_list)) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  SetOperationType op_type_;
  std::vector<std::unique_ptr<const ResolvedSetOperationItem>> input_item_list_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedSetOperationScan> MakeResolvedSetOperationScan(
    const std::vector<ResolvedColumn>& column_list,
    ResolvedSetOperationScan::SetOperationType op_type,
    std::vector<std::unique_ptr<const ResolvedSetOperationItem>> input_item_list) {
  return std::unique_ptr<ResolvedSetOperationScan>(new ResolvedSetOperationScan(
        column_list,
        op_type,
        std::move(input_item_list),
        ResolvedSetOperationScan::NEW_CONSTRUCTOR));
}

// Overloaded factory method for the construction of ResolvedSetOperationScan with
// a wider range of inputs for node-vector inputs.  In particular allows:
// 1. unique_ptr element type can be non-const.
// 2. unique_ptr element type can be any descendant of the required type.
// 3. input container can be any object with a `begin()` and `end()`.
//
// Note, initializer lists cannot be used to pass
//  input_item_list
// due to incompatibility with unique_ptr.  Use zetasql::MakeNodeVector
// instead.
template <
  typename input_item_list_t
      = std::vector<std::unique_ptr<const ResolvedSetOperationItem>>>
std::unique_ptr<ResolvedSetOperationScan> MakeResolvedSetOperationScan(
    const std::vector<ResolvedColumn>& column_list,
    ResolvedSetOperationScan::SetOperationType op_type,
    input_item_list_t input_item_list) {
  static_assert(std::is_base_of<
      ResolvedSetOperationItem,
      typename std::decay<decltype(**(input_item_list.begin()))>::type>::value,
      "input_item_list must be a container of unique_ptr with elements of type "
      "ResolvedSetOperationItem (or its descendants).");
  return MakeResolvedSetOperationScan(
      column_list,
      op_type,
      {std::make_move_iterator(input_item_list.begin()),
       std::make_move_iterator(input_item_list.end())});
}

inline std::unique_ptr<ResolvedSetOperationScan> MakeResolvedSetOperationScan() {
  return std::unique_ptr<ResolvedSetOperationScan>(
      new ResolvedSetOperationScan());
}

// Apply ordering to rows produced from input_scan, and output ordered
// rows.
//
// The <order_by_item_list> must not be empty.  Each element identifies
// a sort column and indicates direction (ascending or descending).
//
// Order Preservation:
//   A ResolvedScan produces an ordered output if it has <is_ordered>=true.
//   If <is_ordered>=false, the scan may discard order.  This can happen
//   even for a ResolvedOrderByScan, if it is the top-level scan in a
//   subquery (which discards order).
//
// The following Scan nodes may have <is_ordered>=true, producing or
// propagating an ordering:
//   * ResolvedOrderByScan
//   * ResolvedLimitOffsetScan
//   * ResolvedProjectScan
//   * ResolvedWithScan
// Other Scan nodes will always discard ordering.
class ResolvedOrderByScan final : public ResolvedScan {
 public:
  typedef ResolvedScan SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_ORDER_BY_SCAN;

  friend std::unique_ptr<ResolvedOrderByScan> MakeResolvedOrderByScan();
 protected:
  ResolvedOrderByScan()
      : ResolvedScan()
      , input_scan_()
      , order_by_item_list_()
  {}
 public:

  ResolvedOrderByScan(const ResolvedOrderByScan&) = delete;
  ResolvedOrderByScan& operator=(const ResolvedOrderByScan&) = delete;

  friend std::unique_ptr<ResolvedOrderByScan> MakeResolvedOrderByScan(
      const std::vector<ResolvedColumn>& column_list,
      std::unique_ptr<const ResolvedScan> input_scan,
      std::vector<std::unique_ptr<const ResolvedOrderByItem>> order_by_item_list
  );
  ~ResolvedOrderByScan() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_ORDER_BY_SCAN; }
  std::string node_kind_string() const final { return "OrderByScan"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedOrderByScanProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedScanProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedOrderByScan>> RestoreFrom(
      const ResolvedOrderByScanProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  const ResolvedScan* input_scan() const {
    accessed_ |= (1<<0);
    return input_scan_.get();
  }
  void set_input_scan(std::unique_ptr<const ResolvedScan> v) {
    input_scan_ = std::move(v);
  }

  std::unique_ptr<const ResolvedScan> release_input_scan() {
    return std::move(input_scan_);
  }

  const std::vector<std::unique_ptr<const ResolvedOrderByItem>>& order_by_item_list() const {
    accessed_ |= (1<<1);
    return order_by_item_list_;
  }
  int order_by_item_list_size() const {
    if (order_by_item_list_.empty()) accessed_ |= (1<<1);
    return static_cast<int>(order_by_item_list_.size());
  }
  const ResolvedOrderByItem* order_by_item_list(int i) const {
    accessed_ |= (1<<1);
    return order_by_item_list_.at(i).get();
  }
  void add_order_by_item_list(std::unique_ptr<const ResolvedOrderByItem> v) {
    order_by_item_list_.emplace_back(std::move(v));
  }
  void set_order_by_item_list(std::vector<std::unique_ptr<const ResolvedOrderByItem>> v) {
    order_by_item_list_ = std::move(v);
  }

  std::vector<std::unique_ptr<const ResolvedOrderByItem>> release_order_by_item_list() {
    std::vector<std::unique_ptr<const ResolvedOrderByItem>> tmp;
    order_by_item_list_.swap(tmp);
    return tmp;
  }

 protected:
  explicit ResolvedOrderByScan(
      const std::vector<ResolvedColumn>& column_list,
      std::unique_ptr<const ResolvedScan> input_scan,
      std::vector<std::unique_ptr<const ResolvedOrderByItem>> order_by_item_list,
      ConstructorOverload)
      : ResolvedScan(
            column_list,
            ConstructorOverload::NEW_CONSTRUCTOR),
      input_scan_(std::move(input_scan)),
      order_by_item_list_(std::move(order_by_item_list)) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  std::unique_ptr<const ResolvedScan> input_scan_;
  std::vector<std::unique_ptr<const ResolvedOrderByItem>> order_by_item_list_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedOrderByScan> MakeResolvedOrderByScan(
    const std::vector<ResolvedColumn>& column_list,
    std::unique_ptr<const ResolvedScan> input_scan,
    std::vector<std::unique_ptr<const ResolvedOrderByItem>> order_by_item_list) {
  return std::unique_ptr<ResolvedOrderByScan>(new ResolvedOrderByScan(
        column_list,
        std::move(input_scan),
        std::move(order_by_item_list),
        ResolvedOrderByScan::NEW_CONSTRUCTOR));
}

// Overloaded factory method for the construction of ResolvedOrderByScan with
// a wider range of inputs for node-vector inputs.  In particular allows:
// 1. unique_ptr element type can be non-const.
// 2. unique_ptr element type can be any descendant of the required type.
// 3. input container can be any object with a `begin()` and `end()`.
//
// Note, initializer lists cannot be used to pass
//  order_by_item_list
// due to incompatibility with unique_ptr.  Use zetasql::MakeNodeVector
// instead.
template <
  typename order_by_item_list_t
      = std::vector<std::unique_ptr<const ResolvedOrderByItem>>>
std::unique_ptr<ResolvedOrderByScan> MakeResolvedOrderByScan(
    const std::vector<ResolvedColumn>& column_list,
    std::unique_ptr<const ResolvedScan> input_scan,
    order_by_item_list_t order_by_item_list) {
  static_assert(std::is_base_of<
      ResolvedOrderByItem,
      typename std::decay<decltype(**(order_by_item_list.begin()))>::type>::value,
      "order_by_item_list must be a container of unique_ptr with elements of type "
      "ResolvedOrderByItem (or its descendants).");
  return MakeResolvedOrderByScan(
      column_list,
      std::move(input_scan),
      {std::make_move_iterator(order_by_item_list.begin()),
       std::make_move_iterator(order_by_item_list.end())});
}

inline std::unique_ptr<ResolvedOrderByScan> MakeResolvedOrderByScan() {
  return std::unique_ptr<ResolvedOrderByScan>(
      new ResolvedOrderByScan());
}

// Apply a LIMIT and optional OFFSET to the rows from input_scan. Emit all
// rows after OFFSET rows have been scanned and up to LIMIT total rows
// emitted. The offset is the number of rows to skip.
// E.g., OFFSET 1 means to skip one row, so the first row emitted will be the
// second ROW, provided the LIMIT is greater than zero.
//
// The arguments to LIMIT <int64> OFFSET <int64> must be non-negative
// integer literals or (possibly casted) query parameters.  Query
// parameter values must be checked at run-time by ZetaSQL compliant
// backend systems.
//
// OFFSET is optional and the absence of OFFSET implies OFFSET 0.
class ResolvedLimitOffsetScan final : public ResolvedScan {
 public:
  typedef ResolvedScan SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_LIMIT_OFFSET_SCAN;

  friend std::unique_ptr<ResolvedLimitOffsetScan> MakeResolvedLimitOffsetScan();
 protected:
  ResolvedLimitOffsetScan()
      : ResolvedScan()
      , input_scan_()
      , limit_()
      , offset_()
  {}
 public:

  ResolvedLimitOffsetScan(const ResolvedLimitOffsetScan&) = delete;
  ResolvedLimitOffsetScan& operator=(const ResolvedLimitOffsetScan&) = delete;

  friend std::unique_ptr<ResolvedLimitOffsetScan> MakeResolvedLimitOffsetScan(
      const std::vector<ResolvedColumn>& column_list,
      std::unique_ptr<const ResolvedScan> input_scan,
      std::unique_ptr<const ResolvedExpr> limit,
      std::unique_ptr<const ResolvedExpr> offset
  );
  ~ResolvedLimitOffsetScan() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_LIMIT_OFFSET_SCAN; }
  std::string node_kind_string() const final { return "LimitOffsetScan"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedLimitOffsetScanProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedScanProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedLimitOffsetScan>> RestoreFrom(
      const ResolvedLimitOffsetScanProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  const ResolvedScan* input_scan() const {
    accessed_ |= (1<<0);
    return input_scan_.get();
  }
  void set_input_scan(std::unique_ptr<const ResolvedScan> v) {
    input_scan_ = std::move(v);
    set_is_ordered(input_scan_->is_ordered());
  }

  std::unique_ptr<const ResolvedScan> release_input_scan() {
    return std::move(input_scan_);
  }

  const ResolvedExpr* limit() const {
    accessed_ |= (1<<1);
    return limit_.get();
  }
  void set_limit(std::unique_ptr<const ResolvedExpr> v) {
    limit_ = std::move(v);
  }

  std::unique_ptr<const ResolvedExpr> release_limit() {
    return std::move(limit_);
  }

  const ResolvedExpr* offset() const {
    accessed_ |= (1<<2);
    return offset_.get();
  }
  void set_offset(std::unique_ptr<const ResolvedExpr> v) {
    offset_ = std::move(v);
  }

  std::unique_ptr<const ResolvedExpr> release_offset() {
    return std::move(offset_);
  }

 protected:
  explicit ResolvedLimitOffsetScan(
      const std::vector<ResolvedColumn>& column_list,
      std::unique_ptr<const ResolvedScan> input_scan,
      std::unique_ptr<const ResolvedExpr> limit,
      std::unique_ptr<const ResolvedExpr> offset,
      ConstructorOverload)
      : ResolvedScan(
            column_list,
            ConstructorOverload::NEW_CONSTRUCTOR),
      input_scan_(std::move(input_scan)),
      limit_(std::move(limit)),
      offset_(std::move(offset)) {
    set_is_ordered(input_scan_->is_ordered());
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  std::unique_ptr<const ResolvedScan> input_scan_;
  std::unique_ptr<const ResolvedExpr> limit_;
  std::unique_ptr<const ResolvedExpr> offset_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedLimitOffsetScan> MakeResolvedLimitOffsetScan(
    const std::vector<ResolvedColumn>& column_list,
    std::unique_ptr<const ResolvedScan> input_scan,
    std::unique_ptr<const ResolvedExpr> limit,
    std::unique_ptr<const ResolvedExpr> offset) {
  return std::unique_ptr<ResolvedLimitOffsetScan>(new ResolvedLimitOffsetScan(
        column_list,
        std::move(input_scan),
        std::move(limit),
        std::move(offset),
        ResolvedLimitOffsetScan::NEW_CONSTRUCTOR));
}

inline std::unique_ptr<ResolvedLimitOffsetScan> MakeResolvedLimitOffsetScan() {
  return std::unique_ptr<ResolvedLimitOffsetScan>(
      new ResolvedLimitOffsetScan());
}

// Scan the subquery defined in a WITH statement.
// See ResolvedWithScan for more detail.
// The column_list produced here will match 1:1 with the column_list produced
// by the referenced subquery and will given a new unique name to each
// column produced for this scan.
class ResolvedWithRefScan final : public ResolvedScan {
 public:
  typedef ResolvedScan SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_WITH_REF_SCAN;

  friend std::unique_ptr<ResolvedWithRefScan> MakeResolvedWithRefScan();
 protected:
  ResolvedWithRefScan()
      : ResolvedScan()
      , with_query_name_()
  {}
 public:

  ResolvedWithRefScan(const ResolvedWithRefScan&) = delete;
  ResolvedWithRefScan& operator=(const ResolvedWithRefScan&) = delete;

  friend std::unique_ptr<ResolvedWithRefScan> MakeResolvedWithRefScan(
      const std::vector<ResolvedColumn>& column_list,
      const std::string& with_query_name
  );
  ~ResolvedWithRefScan() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_WITH_REF_SCAN; }
  std::string node_kind_string() const final { return "WithRefScan"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedWithRefScanProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedScanProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedWithRefScan>> RestoreFrom(
      const ResolvedWithRefScanProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  const std::string& with_query_name() const {
    accessed_ |= (1<<0);
    return with_query_name_;
  }
  void set_with_query_name(const std::string& v) {
    with_query_name_ = v;
  }

 protected:
  explicit ResolvedWithRefScan(
      const std::vector<ResolvedColumn>& column_list,
      const std::string& with_query_name,
      ConstructorOverload)
      : ResolvedScan(
            column_list,
            ConstructorOverload::NEW_CONSTRUCTOR),
      with_query_name_(with_query_name) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  std::string with_query_name_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedWithRefScan> MakeResolvedWithRefScan(
    const std::vector<ResolvedColumn>& column_list,
    const std::string& with_query_name) {
  return std::unique_ptr<ResolvedWithRefScan>(new ResolvedWithRefScan(
        column_list,
        with_query_name,
        ResolvedWithRefScan::NEW_CONSTRUCTOR));
}

inline std::unique_ptr<ResolvedWithRefScan> MakeResolvedWithRefScan() {
  return std::unique_ptr<ResolvedWithRefScan>(
      new ResolvedWithRefScan());
}

// Apply analytic functions to rows produced from input_scan.
//
// The set of analytic functions are partitioned into a list of analytic
// function groups <function_group_list> by the window PARTITION BY and the
// window ORDER BY.
//
// The output <column_list> contains all columns from <input_scan>,
// one column per analytic function. It may also conain partitioning/ordering
// expression columns if they reference to select columns.
class ResolvedAnalyticScan final : public ResolvedScan {
 public:
  typedef ResolvedScan SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_ANALYTIC_SCAN;

  friend std::unique_ptr<ResolvedAnalyticScan> MakeResolvedAnalyticScan();
 protected:
  ResolvedAnalyticScan()
      : ResolvedScan()
      , input_scan_()
      , function_group_list_()
  {}
 public:

  ResolvedAnalyticScan(const ResolvedAnalyticScan&) = delete;
  ResolvedAnalyticScan& operator=(const ResolvedAnalyticScan&) = delete;

  friend std::unique_ptr<ResolvedAnalyticScan> MakeResolvedAnalyticScan(
      const std::vector<ResolvedColumn>& column_list,
      std::unique_ptr<const ResolvedScan> input_scan,
      std::vector<std::unique_ptr<const ResolvedAnalyticFunctionGroup>> function_group_list
  );
  ~ResolvedAnalyticScan() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_ANALYTIC_SCAN; }
  std::string node_kind_string() const final { return "AnalyticScan"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedAnalyticScanProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedScanProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedAnalyticScan>> RestoreFrom(
      const ResolvedAnalyticScanProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  const ResolvedScan* input_scan() const {
    accessed_ |= (1<<0);
    return input_scan_.get();
  }
  void set_input_scan(std::unique_ptr<const ResolvedScan> v) {
    input_scan_ = std::move(v);
  }

  std::unique_ptr<const ResolvedScan> release_input_scan() {
    return std::move(input_scan_);
  }

  const std::vector<std::unique_ptr<const ResolvedAnalyticFunctionGroup>>& function_group_list() const {
    accessed_ |= (1<<1);
    return function_group_list_;
  }
  int function_group_list_size() const {
    if (function_group_list_.empty()) accessed_ |= (1<<1);
    return static_cast<int>(function_group_list_.size());
  }
  const ResolvedAnalyticFunctionGroup* function_group_list(int i) const {
    accessed_ |= (1<<1);
    return function_group_list_.at(i).get();
  }
  void add_function_group_list(std::unique_ptr<const ResolvedAnalyticFunctionGroup> v) {
    function_group_list_.emplace_back(std::move(v));
  }
  void set_function_group_list(std::vector<std::unique_ptr<const ResolvedAnalyticFunctionGroup>> v) {
    function_group_list_ = std::move(v);
  }

  std::vector<std::unique_ptr<const ResolvedAnalyticFunctionGroup>> release_function_group_list() {
    std::vector<std::unique_ptr<const ResolvedAnalyticFunctionGroup>> tmp;
    function_group_list_.swap(tmp);
    return tmp;
  }

 protected:
  explicit ResolvedAnalyticScan(
      const std::vector<ResolvedColumn>& column_list,
      std::unique_ptr<const ResolvedScan> input_scan,
      std::vector<std::unique_ptr<const ResolvedAnalyticFunctionGroup>> function_group_list,
      ConstructorOverload)
      : ResolvedScan(
            column_list,
            ConstructorOverload::NEW_CONSTRUCTOR),
      input_scan_(std::move(input_scan)),
      function_group_list_(std::move(function_group_list)) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  std::unique_ptr<const ResolvedScan> input_scan_;
  std::vector<std::unique_ptr<const ResolvedAnalyticFunctionGroup>> function_group_list_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedAnalyticScan> MakeResolvedAnalyticScan(
    const std::vector<ResolvedColumn>& column_list,
    std::unique_ptr<const ResolvedScan> input_scan,
    std::vector<std::unique_ptr<const ResolvedAnalyticFunctionGroup>> function_group_list) {
  return std::unique_ptr<ResolvedAnalyticScan>(new ResolvedAnalyticScan(
        column_list,
        std::move(input_scan),
        std::move(function_group_list),
        ResolvedAnalyticScan::NEW_CONSTRUCTOR));
}

// Overloaded factory method for the construction of ResolvedAnalyticScan with
// a wider range of inputs for node-vector inputs.  In particular allows:
// 1. unique_ptr element type can be non-const.
// 2. unique_ptr element type can be any descendant of the required type.
// 3. input container can be any object with a `begin()` and `end()`.
//
// Note, initializer lists cannot be used to pass
//  function_group_list
// due to incompatibility with unique_ptr.  Use zetasql::MakeNodeVector
// instead.
template <
  typename function_group_list_t
      = std::vector<std::unique_ptr<const ResolvedAnalyticFunctionGroup>>>
std::unique_ptr<ResolvedAnalyticScan> MakeResolvedAnalyticScan(
    const std::vector<ResolvedColumn>& column_list,
    std::unique_ptr<const ResolvedScan> input_scan,
    function_group_list_t function_group_list) {
  static_assert(std::is_base_of<
      ResolvedAnalyticFunctionGroup,
      typename std::decay<decltype(**(function_group_list.begin()))>::type>::value,
      "function_group_list must be a container of unique_ptr with elements of type "
      "ResolvedAnalyticFunctionGroup (or its descendants).");
  return MakeResolvedAnalyticScan(
      column_list,
      std::move(input_scan),
      {std::make_move_iterator(function_group_list.begin()),
       std::make_move_iterator(function_group_list.end())});
}

inline std::unique_ptr<ResolvedAnalyticScan> MakeResolvedAnalyticScan() {
  return std::unique_ptr<ResolvedAnalyticScan>(
      new ResolvedAnalyticScan());
}

// Samples rows from <input_scan>.
// Specs: (broken link)
// Specs for WITH WEIGHT and PARTITION BY: (broken link)
//
// <method> is the identifier for the sampling algorithm and will always be
// in lowercase.
// For example BERNOULLI, RESERVOIR, SYSTEM. Engines can also support their
// own implementation-specific set of sampling algorithms.
//
// <size> and <unit> specifies the sample size.
// If <unit> is "ROWS", <size> must be an <int64> and non-negative.
// If <unit> is "PERCENT", <size> must either be a <double> or an <int64> and
// in the range [0, 100].
// <size> can only be a literal value or a (possibly casted) parameter.
//
// <repeatable_argument> is present if we had a REPEATABLE(<argument>) in the
// TABLESAMPLE clause and can only be a literal value or a (possibly
// casted) parameter.
//
// If present, <weight_column> defines the column produced by this scan that
// stores the scaling weight for the corresponding sampled row.
//
// <partition_by_list> can be empty. If <partition_by_list> is not empty,
// <unit> must be ROWS and <method> must be RESERVOIR.
class ResolvedSampleScan final : public ResolvedScan {
 public:
  typedef ResolvedScan SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_SAMPLE_SCAN;

  typedef ResolvedSampleScanEnums::SampleUnit SampleUnit;
  static const SampleUnit ROWS = ResolvedSampleScanEnums::ROWS;
  static const SampleUnit PERCENT = ResolvedSampleScanEnums::PERCENT;

  friend std::unique_ptr<ResolvedSampleScan> MakeResolvedSampleScan();
 protected:
  ResolvedSampleScan()
      : ResolvedScan()
      , input_scan_()
      , method_()
      , size_()
      , unit_()
      , repeatable_argument_()
      , weight_column_()
      , partition_by_list_()
  {}
 public:

  ResolvedSampleScan(const ResolvedSampleScan&) = delete;
  ResolvedSampleScan& operator=(const ResolvedSampleScan&) = delete;

  friend std::unique_ptr<ResolvedSampleScan> MakeResolvedSampleScan(
      const std::vector<ResolvedColumn>& column_list,
      std::unique_ptr<const ResolvedScan> input_scan,
      const std::string& method,
      std::unique_ptr<const ResolvedExpr> size,
      SampleUnit unit,
      std::unique_ptr<const ResolvedExpr> repeatable_argument,
      std::unique_ptr<const ResolvedColumnHolder> weight_column,
      std::vector<std::unique_ptr<const ResolvedExpr>> partition_by_list
  );
  ~ResolvedSampleScan() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_SAMPLE_SCAN; }
  std::string node_kind_string() const final { return "SampleScan"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedSampleScanProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedScanProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedSampleScan>> RestoreFrom(
      const ResolvedSampleScanProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  const ResolvedScan* input_scan() const {
    accessed_ |= (1<<0);
    return input_scan_.get();
  }
  void set_input_scan(std::unique_ptr<const ResolvedScan> v) {
    input_scan_ = std::move(v);
  }

  std::unique_ptr<const ResolvedScan> release_input_scan() {
    return std::move(input_scan_);
  }

  const std::string& method() const {
    accessed_ |= (1<<1);
    return method_;
  }
  void set_method(const std::string& v) {
    method_ = v;
  }

  const ResolvedExpr* size() const {
    accessed_ |= (1<<2);
    return size_.get();
  }
  void set_size(std::unique_ptr<const ResolvedExpr> v) {
    size_ = std::move(v);
  }

  std::unique_ptr<const ResolvedExpr> release_size() {
    return std::move(size_);
  }

  SampleUnit unit() const {
    accessed_ |= (1<<3);
    return unit_;
  }
  void set_unit(SampleUnit v) {
    unit_ = v;
  }

  const ResolvedExpr* repeatable_argument() const {
    accessed_ |= (1<<4);
    return repeatable_argument_.get();
  }
  void set_repeatable_argument(std::unique_ptr<const ResolvedExpr> v) {
    repeatable_argument_ = std::move(v);
  }

  std::unique_ptr<const ResolvedExpr> release_repeatable_argument() {
    return std::move(repeatable_argument_);
  }

  const ResolvedColumnHolder* weight_column() const {
    accessed_ |= (1<<5);
    return weight_column_.get();
  }
  void set_weight_column(std::unique_ptr<const ResolvedColumnHolder> v) {
    weight_column_ = std::move(v);
  }

  std::unique_ptr<const ResolvedColumnHolder> release_weight_column() {
    return std::move(weight_column_);
  }

  const std::vector<std::unique_ptr<const ResolvedExpr>>& partition_by_list() const {
    accessed_ |= (1<<6);
    return partition_by_list_;
  }
  int partition_by_list_size() const {
    if (partition_by_list_.empty()) accessed_ |= (1<<6);
    return static_cast<int>(partition_by_list_.size());
  }
  const ResolvedExpr* partition_by_list(int i) const {
    accessed_ |= (1<<6);
    return partition_by_list_.at(i).get();
  }
  void add_partition_by_list(std::unique_ptr<const ResolvedExpr> v) {
    partition_by_list_.emplace_back(std::move(v));
  }
  void set_partition_by_list(std::vector<std::unique_ptr<const ResolvedExpr>> v) {
    partition_by_list_ = std::move(v);
  }

  std::vector<std::unique_ptr<const ResolvedExpr>> release_partition_by_list() {
    std::vector<std::unique_ptr<const ResolvedExpr>> tmp;
    partition_by_list_.swap(tmp);
    return tmp;
  }

 protected:
  explicit ResolvedSampleScan(
      const std::vector<ResolvedColumn>& column_list,
      std::unique_ptr<const ResolvedScan> input_scan,
      const std::string& method,
      std::unique_ptr<const ResolvedExpr> size,
      SampleUnit unit,
      std::unique_ptr<const ResolvedExpr> repeatable_argument,
      std::unique_ptr<const ResolvedColumnHolder> weight_column,
      std::vector<std::unique_ptr<const ResolvedExpr>> partition_by_list,
      ConstructorOverload)
      : ResolvedScan(
            column_list,
            ConstructorOverload::NEW_CONSTRUCTOR),
      input_scan_(std::move(input_scan)),
      method_(method),
      size_(std::move(size)),
      unit_(unit),
      repeatable_argument_(std::move(repeatable_argument)),
      weight_column_(std::move(weight_column)),
      partition_by_list_(std::move(partition_by_list)) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  std::unique_ptr<const ResolvedScan> input_scan_;
  std::string method_;
  std::unique_ptr<const ResolvedExpr> size_;
  SampleUnit unit_;
  std::unique_ptr<const ResolvedExpr> repeatable_argument_;
  std::unique_ptr<const ResolvedColumnHolder> weight_column_;
  std::vector<std::unique_ptr<const ResolvedExpr>> partition_by_list_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedSampleScan> MakeResolvedSampleScan(
    const std::vector<ResolvedColumn>& column_list,
    std::unique_ptr<const ResolvedScan> input_scan,
    const std::string& method,
    std::unique_ptr<const ResolvedExpr> size,
    ResolvedSampleScan::SampleUnit unit,
    std::unique_ptr<const ResolvedExpr> repeatable_argument,
    std::unique_ptr<const ResolvedColumnHolder> weight_column,
    std::vector<std::unique_ptr<const ResolvedExpr>> partition_by_list) {
  return std::unique_ptr<ResolvedSampleScan>(new ResolvedSampleScan(
        column_list,
        std::move(input_scan),
        method,
        std::move(size),
        unit,
        std::move(repeatable_argument),
        std::move(weight_column),
        std::move(partition_by_list),
        ResolvedSampleScan::NEW_CONSTRUCTOR));
}

// Overloaded factory method for the construction of ResolvedSampleScan with
// a wider range of inputs for node-vector inputs.  In particular allows:
// 1. unique_ptr element type can be non-const.
// 2. unique_ptr element type can be any descendant of the required type.
// 3. input container can be any object with a `begin()` and `end()`.
//
// Note, initializer lists cannot be used to pass
//  partition_by_list
// due to incompatibility with unique_ptr.  Use zetasql::MakeNodeVector
// instead.
template <
  typename partition_by_list_t
      = std::vector<std::unique_ptr<const ResolvedExpr>>>
std::unique_ptr<ResolvedSampleScan> MakeResolvedSampleScan(
    const std::vector<ResolvedColumn>& column_list,
    std::unique_ptr<const ResolvedScan> input_scan,
    const std::string& method,
    std::unique_ptr<const ResolvedExpr> size,
    ResolvedSampleScan::SampleUnit unit,
    std::unique_ptr<const ResolvedExpr> repeatable_argument,
    std::unique_ptr<const ResolvedColumnHolder> weight_column,
    partition_by_list_t partition_by_list) {
  static_assert(std::is_base_of<
      ResolvedExpr,
      typename std::decay<decltype(**(partition_by_list.begin()))>::type>::value,
      "partition_by_list must be a container of unique_ptr with elements of type "
      "ResolvedExpr (or its descendants).");
  return MakeResolvedSampleScan(
      column_list,
      std::move(input_scan),
      method,
      std::move(size),
      unit,
      std::move(repeatable_argument),
      std::move(weight_column),
      {std::make_move_iterator(partition_by_list.begin()),
       std::make_move_iterator(partition_by_list.end())});
}

inline std::unique_ptr<ResolvedSampleScan> MakeResolvedSampleScan() {
  return std::unique_ptr<ResolvedSampleScan>(
      new ResolvedSampleScan());
}

// This is used when an expression is computed and given a name (a new
// ResolvedColumn) that can be referenced elsewhere.  The new ResolvedColumn
// can appear in a column_list or in ResolvedColumnRefs in other expressions,
// when appropriate.  This node is not an expression itself - it is a
// container that holds an expression.
class ResolvedComputedColumn final : public ResolvedArgument {
 public:
  typedef ResolvedArgument SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_COMPUTED_COLUMN;

  friend std::unique_ptr<ResolvedComputedColumn> MakeResolvedComputedColumn();
 protected:
  ResolvedComputedColumn()
      : ResolvedArgument()
      , column_()
      , expr_()
  {}
 public:

  ResolvedComputedColumn(const ResolvedComputedColumn&) = delete;
  ResolvedComputedColumn& operator=(const ResolvedComputedColumn&) = delete;

  friend std::unique_ptr<ResolvedComputedColumn> MakeResolvedComputedColumn(
      const ResolvedColumn& column,
      std::unique_ptr<const ResolvedExpr> expr
  );
  ~ResolvedComputedColumn() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_COMPUTED_COLUMN; }
  std::string node_kind_string() const final { return "ComputedColumn"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedComputedColumnProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedArgumentProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedComputedColumn>> RestoreFrom(
      const ResolvedComputedColumnProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  const ResolvedColumn& column() const {
    accessed_ |= (1<<0);
    return column_;
  }
  void set_column(const ResolvedColumn& v) {
    column_ = v;
  }

  const ResolvedExpr* expr() const {
    accessed_ |= (1<<1);
    return expr_.get();
  }
  void set_expr(std::unique_ptr<const ResolvedExpr> v) {
    expr_ = std::move(v);
  }

  std::unique_ptr<const ResolvedExpr> release_expr() {
    return std::move(expr_);
  }

 protected:
  explicit ResolvedComputedColumn(
      const ResolvedColumn& column,
      std::unique_ptr<const ResolvedExpr> expr,
      ConstructorOverload)
      : ResolvedArgument(
            ConstructorOverload::NEW_CONSTRUCTOR),
      column_(column),
      expr_(std::move(expr)) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
  std::string GetNameForDebugString() const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  ResolvedColumn column_;
  std::unique_ptr<const ResolvedExpr> expr_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedComputedColumn> MakeResolvedComputedColumn(
    const ResolvedColumn& column,
    std::unique_ptr<const ResolvedExpr> expr) {
  return std::unique_ptr<ResolvedComputedColumn>(new ResolvedComputedColumn(
        column,
        std::move(expr),
        ResolvedComputedColumn::NEW_CONSTRUCTOR));
}

inline std::unique_ptr<ResolvedComputedColumn> MakeResolvedComputedColumn() {
  return std::unique_ptr<ResolvedComputedColumn>(
      new ResolvedComputedColumn());
}

// This represents one column of an ORDER BY clause, with the requested
// ordering direction.
//
// <collation_name> indicates the COLLATE specific rules of ordering.
// If non-NULL, must be a string literal or a string parameter.
// See (broken link).
class ResolvedOrderByItem final : public ResolvedArgument {
 public:
  typedef ResolvedArgument SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_ORDER_BY_ITEM;

  friend std::unique_ptr<ResolvedOrderByItem> MakeResolvedOrderByItem();
 protected:
  ResolvedOrderByItem()
      : ResolvedArgument()
      , column_ref_()
      , collation_name_()
      , is_descending_()
  {}
 public:

  ResolvedOrderByItem(const ResolvedOrderByItem&) = delete;
  ResolvedOrderByItem& operator=(const ResolvedOrderByItem&) = delete;

  friend std::unique_ptr<ResolvedOrderByItem> MakeResolvedOrderByItem(
      std::unique_ptr<const ResolvedColumnRef> column_ref,
      std::unique_ptr<const ResolvedExpr> collation_name,
      bool is_descending
  );
  ~ResolvedOrderByItem() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_ORDER_BY_ITEM; }
  std::string node_kind_string() const final { return "OrderByItem"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedOrderByItemProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedArgumentProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedOrderByItem>> RestoreFrom(
      const ResolvedOrderByItemProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  const ResolvedColumnRef* column_ref() const {
    accessed_ |= (1<<0);
    return column_ref_.get();
  }
  void set_column_ref(std::unique_ptr<const ResolvedColumnRef> v) {
    column_ref_ = std::move(v);
  }

  std::unique_ptr<const ResolvedColumnRef> release_column_ref() {
    return std::move(column_ref_);
  }

  const ResolvedExpr* collation_name() const {
    accessed_ |= (1<<1);
    return collation_name_.get();
  }
  void set_collation_name(std::unique_ptr<const ResolvedExpr> v) {
    collation_name_ = std::move(v);
  }

  std::unique_ptr<const ResolvedExpr> release_collation_name() {
    return std::move(collation_name_);
  }

  bool is_descending() const {
    accessed_ |= (1<<2);
    return is_descending_;
  }
  void set_is_descending(bool v) {
    is_descending_ = v;
  }

 protected:
  explicit ResolvedOrderByItem(
      std::unique_ptr<const ResolvedColumnRef> column_ref,
      std::unique_ptr<const ResolvedExpr> collation_name,
      bool is_descending,
      ConstructorOverload)
      : ResolvedArgument(
            ConstructorOverload::NEW_CONSTRUCTOR),
      column_ref_(std::move(column_ref)),
      collation_name_(std::move(collation_name)),
      is_descending_(is_descending) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  std::unique_ptr<const ResolvedColumnRef> column_ref_;
  std::unique_ptr<const ResolvedExpr> collation_name_;
  bool is_descending_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedOrderByItem> MakeResolvedOrderByItem(
    std::unique_ptr<const ResolvedColumnRef> column_ref,
    std::unique_ptr<const ResolvedExpr> collation_name,
    bool is_descending) {
  return std::unique_ptr<ResolvedOrderByItem>(new ResolvedOrderByItem(
        std::move(column_ref),
        std::move(collation_name),
        is_descending,
        ResolvedOrderByItem::NEW_CONSTRUCTOR));
}

inline std::unique_ptr<ResolvedOrderByItem> MakeResolvedOrderByItem() {
  return std::unique_ptr<ResolvedOrderByItem>(
      new ResolvedOrderByItem());
}

// This is used in CREATE TABLE statements to provide column annotations
// such as NOT NULL and OPTIONS().
//
// This class is recursive. It mirrors the structure of the column type
// except that child_list might be truncated.
//
// For ARRAY:
//   If the element or its subfield has annotations, then child_list.size()
//   is 1, and child_list(0) stores the element annotations.
//   Otherwise child_list is empty.
// For STRUCT:
//   If the i-th field has annotations then child_list(i) stores the
//   field annotations.
//   Otherwise either child_list.size() <= i or child_list(i) is trivial.
//   If none of the fields and none of their subfields has annotations, then
//   child_list is empty.
// For other types, child_list is empty.
class ResolvedColumnAnnotations final : public ResolvedArgument {
 public:
  typedef ResolvedArgument SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_COLUMN_ANNOTATIONS;

  friend std::unique_ptr<ResolvedColumnAnnotations> MakeResolvedColumnAnnotations();
 protected:
  ResolvedColumnAnnotations()
      : ResolvedArgument()
      , not_null_()
      , option_list_()
      , child_list_()
  {}
 public:

  ResolvedColumnAnnotations(const ResolvedColumnAnnotations&) = delete;
  ResolvedColumnAnnotations& operator=(const ResolvedColumnAnnotations&) = delete;

  friend std::unique_ptr<ResolvedColumnAnnotations> MakeResolvedColumnAnnotations(
      bool not_null,
      std::vector<std::unique_ptr<const ResolvedOption>> option_list,
      std::vector<std::unique_ptr<const ResolvedColumnAnnotations>> child_list
  );
  ~ResolvedColumnAnnotations() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_COLUMN_ANNOTATIONS; }
  std::string node_kind_string() const final { return "ColumnAnnotations"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedColumnAnnotationsProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedArgumentProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedColumnAnnotations>> RestoreFrom(
      const ResolvedColumnAnnotationsProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  bool not_null() const {
    accessed_ |= (1<<0);
    return not_null_;
  }
  void set_not_null(bool v) {
    not_null_ = v;
  }

  const std::vector<std::unique_ptr<const ResolvedOption>>& option_list() const {
    accessed_ |= (1<<1);
    return option_list_;
  }
  int option_list_size() const {
    if (option_list_.empty()) accessed_ |= (1<<1);
    return static_cast<int>(option_list_.size());
  }
  const ResolvedOption* option_list(int i) const {
    accessed_ |= (1<<1);
    return option_list_.at(i).get();
  }
  void add_option_list(std::unique_ptr<const ResolvedOption> v) {
    option_list_.emplace_back(std::move(v));
  }
  void set_option_list(std::vector<std::unique_ptr<const ResolvedOption>> v) {
    option_list_ = std::move(v);
  }

  std::vector<std::unique_ptr<const ResolvedOption>> release_option_list() {
    std::vector<std::unique_ptr<const ResolvedOption>> tmp;
    option_list_.swap(tmp);
    return tmp;
  }

  const std::vector<std::unique_ptr<const ResolvedColumnAnnotations>>& child_list() const {
    accessed_ |= (1<<2);
    return child_list_;
  }
  int child_list_size() const {
    if (child_list_.empty()) accessed_ |= (1<<2);
    return static_cast<int>(child_list_.size());
  }
  const ResolvedColumnAnnotations* child_list(int i) const {
    accessed_ |= (1<<2);
    return child_list_.at(i).get();
  }
  void add_child_list(std::unique_ptr<const ResolvedColumnAnnotations> v) {
    child_list_.emplace_back(std::move(v));
  }
  void set_child_list(std::vector<std::unique_ptr<const ResolvedColumnAnnotations>> v) {
    child_list_ = std::move(v);
  }

  std::vector<std::unique_ptr<const ResolvedColumnAnnotations>> release_child_list() {
    std::vector<std::unique_ptr<const ResolvedColumnAnnotations>> tmp;
    child_list_.swap(tmp);
    return tmp;
  }

 protected:
  explicit ResolvedColumnAnnotations(
      bool not_null,
      std::vector<std::unique_ptr<const ResolvedOption>> option_list,
      std::vector<std::unique_ptr<const ResolvedColumnAnnotations>> child_list,
      ConstructorOverload)
      : ResolvedArgument(
            ConstructorOverload::NEW_CONSTRUCTOR),
      not_null_(not_null),
      option_list_(std::move(option_list)),
      child_list_(std::move(child_list)) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  bool not_null_;
  std::vector<std::unique_ptr<const ResolvedOption>> option_list_;
  std::vector<std::unique_ptr<const ResolvedColumnAnnotations>> child_list_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedColumnAnnotations> MakeResolvedColumnAnnotations(
    bool not_null,
    std::vector<std::unique_ptr<const ResolvedOption>> option_list,
    std::vector<std::unique_ptr<const ResolvedColumnAnnotations>> child_list) {
  return std::unique_ptr<ResolvedColumnAnnotations>(new ResolvedColumnAnnotations(
        not_null,
        std::move(option_list),
        std::move(child_list),
        ResolvedColumnAnnotations::NEW_CONSTRUCTOR));
}

// Overloaded factory method for the construction of ResolvedColumnAnnotations with
// a wider range of inputs for node-vector inputs.  In particular allows:
// 1. unique_ptr element type can be non-const.
// 2. unique_ptr element type can be any descendant of the required type.
// 3. input container can be any object with a `begin()` and `end()`.
//
// Note, initializer lists cannot be used to pass
//  option_list, child_list
// due to incompatibility with unique_ptr.  Use zetasql::MakeNodeVector
// instead.
template <
  typename option_list_t
      = std::vector<std::unique_ptr<const ResolvedOption>>,
  typename child_list_t
      = std::vector<std::unique_ptr<const ResolvedColumnAnnotations>>>
std::unique_ptr<ResolvedColumnAnnotations> MakeResolvedColumnAnnotations(
    bool not_null,
    option_list_t option_list,
    child_list_t child_list) {
  static_assert(std::is_base_of<
      ResolvedOption,
      typename std::decay<decltype(**(option_list.begin()))>::type>::value,
      "option_list must be a container of unique_ptr with elements of type "
      "ResolvedOption (or its descendants).");
  static_assert(std::is_base_of<
      ResolvedColumnAnnotations,
      typename std::decay<decltype(**(child_list.begin()))>::type>::value,
      "child_list must be a container of unique_ptr with elements of type "
      "ResolvedColumnAnnotations (or its descendants).");
  return MakeResolvedColumnAnnotations(
      not_null,
      {std::make_move_iterator(option_list.begin()),
       std::make_move_iterator(option_list.end())},
      {std::make_move_iterator(child_list.begin()),
       std::make_move_iterator(child_list.end())});
}

inline std::unique_ptr<ResolvedColumnAnnotations> MakeResolvedColumnAnnotations() {
  return std::unique_ptr<ResolvedColumnAnnotations>(
      new ResolvedColumnAnnotations());
}

// <expression> indicates the expression that defines the column. The type of
// the expression will always match the type of the column.
//   - The <expression> can contain ResolvedColumnRefs corresponding to
//   ResolvedColumnDefinition.<column> for any of the
//   ResolvedColumnDefinitions in the enclosing statement.
//   - The expression can never include a subquery.
//
// <is_stored> indicates whether the value of the expression should be stored
// or not. When is_stored is true, <expression> cannot contain a volatile
// function (e.g. RAND).
//
// See (broken link).
class ResolvedGeneratedColumnInfo final : public ResolvedArgument {
 public:
  typedef ResolvedArgument SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_GENERATED_COLUMN_INFO;

  friend std::unique_ptr<ResolvedGeneratedColumnInfo> MakeResolvedGeneratedColumnInfo();
 protected:
  ResolvedGeneratedColumnInfo()
      : ResolvedArgument()
      , expression_()
      , is_stored_()
  {}
 public:

  ResolvedGeneratedColumnInfo(const ResolvedGeneratedColumnInfo&) = delete;
  ResolvedGeneratedColumnInfo& operator=(const ResolvedGeneratedColumnInfo&) = delete;

  friend std::unique_ptr<ResolvedGeneratedColumnInfo> MakeResolvedGeneratedColumnInfo(
      std::unique_ptr<const ResolvedExpr> expression,
      bool is_stored
  );
  ~ResolvedGeneratedColumnInfo() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_GENERATED_COLUMN_INFO; }
  std::string node_kind_string() const final { return "GeneratedColumnInfo"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedGeneratedColumnInfoProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedArgumentProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedGeneratedColumnInfo>> RestoreFrom(
      const ResolvedGeneratedColumnInfoProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  const ResolvedExpr* expression() const {
    accessed_ |= (1<<0);
    return expression_.get();
  }
  void set_expression(std::unique_ptr<const ResolvedExpr> v) {
    expression_ = std::move(v);
  }

  std::unique_ptr<const ResolvedExpr> release_expression() {
    return std::move(expression_);
  }

  bool is_stored() const {
    accessed_ |= (1<<1);
    return is_stored_;
  }
  void set_is_stored(bool v) {
    is_stored_ = v;
  }

 protected:
  explicit ResolvedGeneratedColumnInfo(
      std::unique_ptr<const ResolvedExpr> expression,
      bool is_stored,
      ConstructorOverload)
      : ResolvedArgument(
            ConstructorOverload::NEW_CONSTRUCTOR),
      expression_(std::move(expression)),
      is_stored_(is_stored) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  std::unique_ptr<const ResolvedExpr> expression_;
  bool is_stored_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedGeneratedColumnInfo> MakeResolvedGeneratedColumnInfo(
    std::unique_ptr<const ResolvedExpr> expression,
    bool is_stored) {
  return std::unique_ptr<ResolvedGeneratedColumnInfo>(new ResolvedGeneratedColumnInfo(
        std::move(expression),
        is_stored,
        ResolvedGeneratedColumnInfo::NEW_CONSTRUCTOR));
}

inline std::unique_ptr<ResolvedGeneratedColumnInfo> MakeResolvedGeneratedColumnInfo() {
  return std::unique_ptr<ResolvedGeneratedColumnInfo>(
      new ResolvedGeneratedColumnInfo());
}

// This is used in CREATE TABLE statements to provide an explicit column
// definition.
//
// if <is_hidden> is TRUE, then the column won't show up in SELECT * queries.
//
// if <generated_column_info> is non-NULL, then this table column is a
// generated column.
//
// <column> defines an ID for the column, which may appear in expressions in
// the PARTITION BY, CLUSTER BY clause or <generated_column_info> if either
// is present.
class ResolvedColumnDefinition final : public ResolvedArgument {
 public:
  typedef ResolvedArgument SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_COLUMN_DEFINITION;

  friend std::unique_ptr<ResolvedColumnDefinition> MakeResolvedColumnDefinition();
 protected:
  ResolvedColumnDefinition()
      : ResolvedArgument()
      , name_()
      , type_()
      , annotations_()
      , is_hidden_()
      , column_()
      , generated_column_info_()
  {}
 public:

  ResolvedColumnDefinition(const ResolvedColumnDefinition&) = delete;
  ResolvedColumnDefinition& operator=(const ResolvedColumnDefinition&) = delete;

  friend std::unique_ptr<ResolvedColumnDefinition> MakeResolvedColumnDefinition(
      const std::string& name,
      const Type* type,
      std::unique_ptr<const ResolvedColumnAnnotations> annotations,
      bool is_hidden,
      const ResolvedColumn& column,
      std::unique_ptr<const ResolvedGeneratedColumnInfo> generated_column_info
  );
  ~ResolvedColumnDefinition() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_COLUMN_DEFINITION; }
  std::string node_kind_string() const final { return "ColumnDefinition"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedColumnDefinitionProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedArgumentProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedColumnDefinition>> RestoreFrom(
      const ResolvedColumnDefinitionProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  const std::string& name() const {
    accessed_ |= (1<<0);
    return name_;
  }
  void set_name(const std::string& v) {
    name_ = v;
  }

  const Type* type() const {
    accessed_ |= (1<<1);
    return type_;
  }
  void set_type(const Type* v) {
    type_ = v;
  }

  const ResolvedColumnAnnotations* annotations() const {
    accessed_ |= (1<<2);
    return annotations_.get();
  }
  void set_annotations(std::unique_ptr<const ResolvedColumnAnnotations> v) {
    annotations_ = std::move(v);
  }

  std::unique_ptr<const ResolvedColumnAnnotations> release_annotations() {
    return std::move(annotations_);
  }

  bool is_hidden() const {
    accessed_ |= (1<<3);
    return is_hidden_;
  }
  void set_is_hidden(bool v) {
    is_hidden_ = v;
  }

  const ResolvedColumn& column() const {
    accessed_ |= (1<<4);
    return column_;
  }
  void set_column(const ResolvedColumn& v) {
    column_ = v;
  }

  const ResolvedGeneratedColumnInfo* generated_column_info() const {
    accessed_ |= (1<<5);
    return generated_column_info_.get();
  }
  void set_generated_column_info(std::unique_ptr<const ResolvedGeneratedColumnInfo> v) {
    generated_column_info_ = std::move(v);
  }

  std::unique_ptr<const ResolvedGeneratedColumnInfo> release_generated_column_info() {
    return std::move(generated_column_info_);
  }

 protected:
  explicit ResolvedColumnDefinition(
      const std::string& name,
      const Type* type,
      std::unique_ptr<const ResolvedColumnAnnotations> annotations,
      bool is_hidden,
      const ResolvedColumn& column,
      std::unique_ptr<const ResolvedGeneratedColumnInfo> generated_column_info,
      ConstructorOverload)
      : ResolvedArgument(
            ConstructorOverload::NEW_CONSTRUCTOR),
      name_(name),
      type_(type),
      annotations_(std::move(annotations)),
      is_hidden_(is_hidden),
      column_(column),
      generated_column_info_(std::move(generated_column_info)) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  std::string name_;
  const Type* type_;
  std::unique_ptr<const ResolvedColumnAnnotations> annotations_;
  bool is_hidden_;
  ResolvedColumn column_;
  std::unique_ptr<const ResolvedGeneratedColumnInfo> generated_column_info_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedColumnDefinition> MakeResolvedColumnDefinition(
    const std::string& name,
    const Type* type,
    std::unique_ptr<const ResolvedColumnAnnotations> annotations,
    bool is_hidden,
    const ResolvedColumn& column,
    std::unique_ptr<const ResolvedGeneratedColumnInfo> generated_column_info) {
  return std::unique_ptr<ResolvedColumnDefinition>(new ResolvedColumnDefinition(
        name,
        type,
        std::move(annotations),
        is_hidden,
        column,
        std::move(generated_column_info),
        ResolvedColumnDefinition::NEW_CONSTRUCTOR));
}

inline std::unique_ptr<ResolvedColumnDefinition> MakeResolvedColumnDefinition() {
  return std::unique_ptr<ResolvedColumnDefinition>(
      new ResolvedColumnDefinition());
}

// This represents the PRIMARY KEY constraint on a table.
// <column_offset_list> provides the offsets of the column definitions that
//                      comprise the primary key. This is empty when a
//                      0-element primary key is defined.
class ResolvedPrimaryKey final : public ResolvedArgument {
 public:
  typedef ResolvedArgument SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_PRIMARY_KEY;

  friend std::unique_ptr<ResolvedPrimaryKey> MakeResolvedPrimaryKey();
 protected:
  ResolvedPrimaryKey()
      : ResolvedArgument()
      , column_offset_list_()
      , option_list_()
  {}
 public:

  ResolvedPrimaryKey(const ResolvedPrimaryKey&) = delete;
  ResolvedPrimaryKey& operator=(const ResolvedPrimaryKey&) = delete;

  friend std::unique_ptr<ResolvedPrimaryKey> MakeResolvedPrimaryKey(
      const std::vector<int>& column_offset_list,
      std::vector<std::unique_ptr<const ResolvedOption>> option_list
  );
  ~ResolvedPrimaryKey() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_PRIMARY_KEY; }
  std::string node_kind_string() const final { return "PrimaryKey"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedPrimaryKeyProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedArgumentProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedPrimaryKey>> RestoreFrom(
      const ResolvedPrimaryKeyProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  const std::vector<int>& column_offset_list() const {
    accessed_ |= (1<<0);
    return column_offset_list_;
  }
  int column_offset_list_size() const {
    if (column_offset_list_.empty()) accessed_ |= (1<<0);
    return static_cast<int>(column_offset_list_.size());
  }
  int column_offset_list(int i) const {
    accessed_ |= (1<<0);
    return column_offset_list_.at(i);
  }
  void add_column_offset_list(int v) {
    column_offset_list_.push_back(int(v));
  }
  void set_column_offset_list(const std::vector<int>& v) {
    column_offset_list_ = v;
  }
  std::vector<int>* mutable_column_offset_list() {
    accessed_ |= (1<<0);
    return &column_offset_list_;
  }

  const std::vector<std::unique_ptr<const ResolvedOption>>& option_list() const {
    accessed_ |= (1<<1);
    return option_list_;
  }
  int option_list_size() const {
    if (option_list_.empty()) accessed_ |= (1<<1);
    return static_cast<int>(option_list_.size());
  }
  const ResolvedOption* option_list(int i) const {
    accessed_ |= (1<<1);
    return option_list_.at(i).get();
  }
  void add_option_list(std::unique_ptr<const ResolvedOption> v) {
    option_list_.emplace_back(std::move(v));
  }
  void set_option_list(std::vector<std::unique_ptr<const ResolvedOption>> v) {
    option_list_ = std::move(v);
  }

  std::vector<std::unique_ptr<const ResolvedOption>> release_option_list() {
    std::vector<std::unique_ptr<const ResolvedOption>> tmp;
    option_list_.swap(tmp);
    return tmp;
  }

 protected:
  explicit ResolvedPrimaryKey(
      const std::vector<int>& column_offset_list,
      std::vector<std::unique_ptr<const ResolvedOption>> option_list,
      ConstructorOverload)
      : ResolvedArgument(
            ConstructorOverload::NEW_CONSTRUCTOR),
      column_offset_list_(column_offset_list),
      option_list_(std::move(option_list)) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  std::vector<int> column_offset_list_;
  std::vector<std::unique_ptr<const ResolvedOption>> option_list_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedPrimaryKey> MakeResolvedPrimaryKey(
    const std::vector<int>& column_offset_list,
    std::vector<std::unique_ptr<const ResolvedOption>> option_list) {
  return std::unique_ptr<ResolvedPrimaryKey>(new ResolvedPrimaryKey(
        column_offset_list,
        std::move(option_list),
        ResolvedPrimaryKey::NEW_CONSTRUCTOR));
}

// Overloaded factory method for the construction of ResolvedPrimaryKey with
// a wider range of inputs for node-vector inputs.  In particular allows:
// 1. unique_ptr element type can be non-const.
// 2. unique_ptr element type can be any descendant of the required type.
// 3. input container can be any object with a `begin()` and `end()`.
//
// Note, initializer lists cannot be used to pass
//  option_list
// due to incompatibility with unique_ptr.  Use zetasql::MakeNodeVector
// instead.
template <
  typename option_list_t
      = std::vector<std::unique_ptr<const ResolvedOption>>>
std::unique_ptr<ResolvedPrimaryKey> MakeResolvedPrimaryKey(
    const std::vector<int>& column_offset_list,
    option_list_t option_list) {
  static_assert(std::is_base_of<
      ResolvedOption,
      typename std::decay<decltype(**(option_list.begin()))>::type>::value,
      "option_list must be a container of unique_ptr with elements of type "
      "ResolvedOption (or its descendants).");
  return MakeResolvedPrimaryKey(
      column_offset_list,
      {std::make_move_iterator(option_list.begin()),
       std::make_move_iterator(option_list.end())});
}

inline std::unique_ptr<ResolvedPrimaryKey> MakeResolvedPrimaryKey() {
  return std::unique_ptr<ResolvedPrimaryKey>(
      new ResolvedPrimaryKey());
}

// This represents the FOREIGN KEY constraint on a table. It is of the form:
//
//   CONSTRAINT <constraint_name>
//   FOREIGN KEY <referencing_column_offset_list>
//   REFERENCES <referenced_table> <referenced_column_offset_list>
//   <match_mode>
//   <update_action>
//   <delete_action>
//   <enforced>
//   <option_list>
//
// <constraint_name> uniquely identifies the constraint.
//
// <referencing_column_offset_list> provides the offsets of the column
// definitions for the table defining the foreign key.
//
// <referenced_table> identifies the table this constraint references.
//
// <referenced_column_offset_list> provides the offsets of the column
// definitions for the table referenced by the foreign key.
//
// <match_mode> specifies how referencing keys with null values are handled.
//
// <update_action> specifies what action to take, if any, when a referenced
// value is updated.
//
// <delete_action> specifies what action to take, if any, when a row with a
// referenced values is deleted.
//
// <enforced> specifies whether or not the constraint is enforced.
//
// <option_list> for foreign key table constraints. Empty for foreign key
// column attributes (see instead ResolvedColumnAnnotations).
class ResolvedForeignKey final : public ResolvedArgument {
 public:
  typedef ResolvedArgument SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_FOREIGN_KEY;

  typedef ResolvedForeignKeyEnums::MatchMode MatchMode;
  typedef ResolvedForeignKeyEnums::ActionOperation ActionOperation;
  static const MatchMode SIMPLE = ResolvedForeignKeyEnums::SIMPLE;
  static const MatchMode FULL = ResolvedForeignKeyEnums::FULL;
  static const MatchMode NOT_DISTINCT = ResolvedForeignKeyEnums::NOT_DISTINCT;
  static const ActionOperation NO_ACTION = ResolvedForeignKeyEnums::NO_ACTION;
  static const ActionOperation RESTRICT = ResolvedForeignKeyEnums::RESTRICT;
  static const ActionOperation CASCADE = ResolvedForeignKeyEnums::CASCADE;
  static const ActionOperation SET_NULL = ResolvedForeignKeyEnums::SET_NULL;

  friend std::unique_ptr<ResolvedForeignKey> MakeResolvedForeignKey();
 protected:
  ResolvedForeignKey()
      : ResolvedArgument()
      , constraint_name_()
      , referencing_column_offset_list_()
      , referenced_table_()
      , referenced_column_offset_list_()
      , match_mode_()
      , update_action_()
      , delete_action_()
      , enforced_()
      , option_list_()
  {}
 public:

  ResolvedForeignKey(const ResolvedForeignKey&) = delete;
  ResolvedForeignKey& operator=(const ResolvedForeignKey&) = delete;

  friend std::unique_ptr<ResolvedForeignKey> MakeResolvedForeignKey(
      const std::string& constraint_name,
      const std::vector<int>& referencing_column_offset_list,
      const Table* referenced_table,
      const std::vector<int>& referenced_column_offset_list,
      MatchMode match_mode,
      ActionOperation update_action,
      ActionOperation delete_action,
      bool enforced,
      std::vector<std::unique_ptr<const ResolvedOption>> option_list
  );
  ~ResolvedForeignKey() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_FOREIGN_KEY; }
  std::string node_kind_string() const final { return "ForeignKey"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedForeignKeyProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedArgumentProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedForeignKey>> RestoreFrom(
      const ResolvedForeignKeyProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  const std::string& constraint_name() const {
    accessed_ |= (1<<0);
    return constraint_name_;
  }
  void set_constraint_name(const std::string& v) {
    constraint_name_ = v;
  }

  const std::vector<int>& referencing_column_offset_list() const {
    accessed_ |= (1<<1);
    return referencing_column_offset_list_;
  }
  int referencing_column_offset_list_size() const {
    if (referencing_column_offset_list_.empty()) accessed_ |= (1<<1);
    return static_cast<int>(referencing_column_offset_list_.size());
  }
  int referencing_column_offset_list(int i) const {
    accessed_ |= (1<<1);
    return referencing_column_offset_list_.at(i);
  }
  void add_referencing_column_offset_list(int v) {
    referencing_column_offset_list_.push_back(int(v));
  }
  void set_referencing_column_offset_list(const std::vector<int>& v) {
    referencing_column_offset_list_ = v;
  }
  std::vector<int>* mutable_referencing_column_offset_list() {
    accessed_ |= (1<<1);
    return &referencing_column_offset_list_;
  }

  const Table* referenced_table() const {
    accessed_ |= (1<<2);
    return referenced_table_;
  }
  void set_referenced_table(const Table* v) {
    referenced_table_ = v;
  }

  const std::vector<int>& referenced_column_offset_list() const {
    accessed_ |= (1<<3);
    return referenced_column_offset_list_;
  }
  int referenced_column_offset_list_size() const {
    if (referenced_column_offset_list_.empty()) accessed_ |= (1<<3);
    return static_cast<int>(referenced_column_offset_list_.size());
  }
  int referenced_column_offset_list(int i) const {
    accessed_ |= (1<<3);
    return referenced_column_offset_list_.at(i);
  }
  void add_referenced_column_offset_list(int v) {
    referenced_column_offset_list_.push_back(int(v));
  }
  void set_referenced_column_offset_list(const std::vector<int>& v) {
    referenced_column_offset_list_ = v;
  }
  std::vector<int>* mutable_referenced_column_offset_list() {
    accessed_ |= (1<<3);
    return &referenced_column_offset_list_;
  }

  MatchMode match_mode() const {
    accessed_ |= (1<<4);
    return match_mode_;
  }
  void set_match_mode(MatchMode v) {
    match_mode_ = v;
  }

  ActionOperation update_action() const {
    accessed_ |= (1<<5);
    return update_action_;
  }
  void set_update_action(ActionOperation v) {
    update_action_ = v;
  }

  ActionOperation delete_action() const {
    accessed_ |= (1<<6);
    return delete_action_;
  }
  void set_delete_action(ActionOperation v) {
    delete_action_ = v;
  }

  bool enforced() const {
    accessed_ |= (1<<7);
    return enforced_;
  }
  void set_enforced(bool v) {
    enforced_ = v;
  }

  const std::vector<std::unique_ptr<const ResolvedOption>>& option_list() const {
    accessed_ |= (1<<8);
    return option_list_;
  }
  int option_list_size() const {
    if (option_list_.empty()) accessed_ |= (1<<8);
    return static_cast<int>(option_list_.size());
  }
  const ResolvedOption* option_list(int i) const {
    accessed_ |= (1<<8);
    return option_list_.at(i).get();
  }
  void add_option_list(std::unique_ptr<const ResolvedOption> v) {
    option_list_.emplace_back(std::move(v));
  }
  void set_option_list(std::vector<std::unique_ptr<const ResolvedOption>> v) {
    option_list_ = std::move(v);
  }

  std::vector<std::unique_ptr<const ResolvedOption>> release_option_list() {
    std::vector<std::unique_ptr<const ResolvedOption>> tmp;
    option_list_.swap(tmp);
    return tmp;
  }

 protected:
  explicit ResolvedForeignKey(
      const std::string& constraint_name,
      const std::vector<int>& referencing_column_offset_list,
      const Table* referenced_table,
      const std::vector<int>& referenced_column_offset_list,
      MatchMode match_mode,
      ActionOperation update_action,
      ActionOperation delete_action,
      bool enforced,
      std::vector<std::unique_ptr<const ResolvedOption>> option_list,
      ConstructorOverload)
      : ResolvedArgument(
            ConstructorOverload::NEW_CONSTRUCTOR),
      constraint_name_(constraint_name),
      referencing_column_offset_list_(referencing_column_offset_list),
      referenced_table_(referenced_table),
      referenced_column_offset_list_(referenced_column_offset_list),
      match_mode_(match_mode),
      update_action_(update_action),
      delete_action_(delete_action),
      enforced_(enforced),
      option_list_(std::move(option_list)) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  std::string constraint_name_;
  std::vector<int> referencing_column_offset_list_;
  const Table* referenced_table_;
  std::vector<int> referenced_column_offset_list_;
  MatchMode match_mode_;
  ActionOperation update_action_;
  ActionOperation delete_action_;
  bool enforced_;
  std::vector<std::unique_ptr<const ResolvedOption>> option_list_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedForeignKey> MakeResolvedForeignKey(
    const std::string& constraint_name,
    const std::vector<int>& referencing_column_offset_list,
    const Table* referenced_table,
    const std::vector<int>& referenced_column_offset_list,
    ResolvedForeignKey::MatchMode match_mode,
    ResolvedForeignKey::ActionOperation update_action,
    ResolvedForeignKey::ActionOperation delete_action,
    bool enforced,
    std::vector<std::unique_ptr<const ResolvedOption>> option_list) {
  return std::unique_ptr<ResolvedForeignKey>(new ResolvedForeignKey(
        constraint_name,
        referencing_column_offset_list,
        referenced_table,
        referenced_column_offset_list,
        match_mode,
        update_action,
        delete_action,
        enforced,
        std::move(option_list),
        ResolvedForeignKey::NEW_CONSTRUCTOR));
}

// Overloaded factory method for the construction of ResolvedForeignKey with
// a wider range of inputs for node-vector inputs.  In particular allows:
// 1. unique_ptr element type can be non-const.
// 2. unique_ptr element type can be any descendant of the required type.
// 3. input container can be any object with a `begin()` and `end()`.
//
// Note, initializer lists cannot be used to pass
//  option_list
// due to incompatibility with unique_ptr.  Use zetasql::MakeNodeVector
// instead.
template <
  typename option_list_t
      = std::vector<std::unique_ptr<const ResolvedOption>>>
std::unique_ptr<ResolvedForeignKey> MakeResolvedForeignKey(
    const std::string& constraint_name,
    const std::vector<int>& referencing_column_offset_list,
    const Table* referenced_table,
    const std::vector<int>& referenced_column_offset_list,
    ResolvedForeignKey::MatchMode match_mode,
    ResolvedForeignKey::ActionOperation update_action,
    ResolvedForeignKey::ActionOperation delete_action,
    bool enforced,
    option_list_t option_list) {
  static_assert(std::is_base_of<
      ResolvedOption,
      typename std::decay<decltype(**(option_list.begin()))>::type>::value,
      "option_list must be a container of unique_ptr with elements of type "
      "ResolvedOption (or its descendants).");
  return MakeResolvedForeignKey(
      constraint_name,
      referencing_column_offset_list,
      referenced_table,
      referenced_column_offset_list,
      match_mode,
      update_action,
      delete_action,
      enforced,
      {std::make_move_iterator(option_list.begin()),
       std::make_move_iterator(option_list.end())});
}

inline std::unique_ptr<ResolvedForeignKey> MakeResolvedForeignKey() {
  return std::unique_ptr<ResolvedForeignKey>(
      new ResolvedForeignKey());
}

// This represents the CHECK constraint on a table. It is of the form:
//
//   CONSTRAINT <constraint_name>
//   CHECK <expression>
//   <enforced>
//   <option_list>
//
// <constraint_name> uniquely identifies the constraint.
//
// <expression> defines a boolean expression to be evaluated when the row is
// updated. If the result is FALSE, update to the row is not allowed.
//
// <enforced> specifies whether or not the constraint is enforced.
//
// <option_list> list of options for check constraint.
//
// See (broken link).
class ResolvedCheckConstraint final : public ResolvedArgument {
 public:
  typedef ResolvedArgument SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_CHECK_CONSTRAINT;

  friend std::unique_ptr<ResolvedCheckConstraint> MakeResolvedCheckConstraint();
 protected:
  ResolvedCheckConstraint()
      : ResolvedArgument()
      , constraint_name_()
      , expression_()
      , enforced_()
      , option_list_()
  {}
 public:

  ResolvedCheckConstraint(const ResolvedCheckConstraint&) = delete;
  ResolvedCheckConstraint& operator=(const ResolvedCheckConstraint&) = delete;

  friend std::unique_ptr<ResolvedCheckConstraint> MakeResolvedCheckConstraint(
      const std::string& constraint_name,
      std::unique_ptr<const ResolvedExpr> expression,
      bool enforced,
      std::vector<std::unique_ptr<const ResolvedOption>> option_list
  );
  ~ResolvedCheckConstraint() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_CHECK_CONSTRAINT; }
  std::string node_kind_string() const final { return "CheckConstraint"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedCheckConstraintProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedArgumentProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedCheckConstraint>> RestoreFrom(
      const ResolvedCheckConstraintProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  const std::string& constraint_name() const {
    accessed_ |= (1<<0);
    return constraint_name_;
  }
  void set_constraint_name(const std::string& v) {
    constraint_name_ = v;
  }

  const ResolvedExpr* expression() const {
    accessed_ |= (1<<1);
    return expression_.get();
  }
  void set_expression(std::unique_ptr<const ResolvedExpr> v) {
    expression_ = std::move(v);
  }

  std::unique_ptr<const ResolvedExpr> release_expression() {
    return std::move(expression_);
  }

  bool enforced() const {
    accessed_ |= (1<<2);
    return enforced_;
  }
  void set_enforced(bool v) {
    enforced_ = v;
  }

  const std::vector<std::unique_ptr<const ResolvedOption>>& option_list() const {
    accessed_ |= (1<<3);
    return option_list_;
  }
  int option_list_size() const {
    if (option_list_.empty()) accessed_ |= (1<<3);
    return static_cast<int>(option_list_.size());
  }
  const ResolvedOption* option_list(int i) const {
    accessed_ |= (1<<3);
    return option_list_.at(i).get();
  }
  void add_option_list(std::unique_ptr<const ResolvedOption> v) {
    option_list_.emplace_back(std::move(v));
  }
  void set_option_list(std::vector<std::unique_ptr<const ResolvedOption>> v) {
    option_list_ = std::move(v);
  }

  std::vector<std::unique_ptr<const ResolvedOption>> release_option_list() {
    std::vector<std::unique_ptr<const ResolvedOption>> tmp;
    option_list_.swap(tmp);
    return tmp;
  }

 protected:
  explicit ResolvedCheckConstraint(
      const std::string& constraint_name,
      std::unique_ptr<const ResolvedExpr> expression,
      bool enforced,
      std::vector<std::unique_ptr<const ResolvedOption>> option_list,
      ConstructorOverload)
      : ResolvedArgument(
            ConstructorOverload::NEW_CONSTRUCTOR),
      constraint_name_(constraint_name),
      expression_(std::move(expression)),
      enforced_(enforced),
      option_list_(std::move(option_list)) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  std::string constraint_name_;
  std::unique_ptr<const ResolvedExpr> expression_;
  bool enforced_;
  std::vector<std::unique_ptr<const ResolvedOption>> option_list_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedCheckConstraint> MakeResolvedCheckConstraint(
    const std::string& constraint_name,
    std::unique_ptr<const ResolvedExpr> expression,
    bool enforced,
    std::vector<std::unique_ptr<const ResolvedOption>> option_list) {
  return std::unique_ptr<ResolvedCheckConstraint>(new ResolvedCheckConstraint(
        constraint_name,
        std::move(expression),
        enforced,
        std::move(option_list),
        ResolvedCheckConstraint::NEW_CONSTRUCTOR));
}

// Overloaded factory method for the construction of ResolvedCheckConstraint with
// a wider range of inputs for node-vector inputs.  In particular allows:
// 1. unique_ptr element type can be non-const.
// 2. unique_ptr element type can be any descendant of the required type.
// 3. input container can be any object with a `begin()` and `end()`.
//
// Note, initializer lists cannot be used to pass
//  option_list
// due to incompatibility with unique_ptr.  Use zetasql::MakeNodeVector
// instead.
template <
  typename option_list_t
      = std::vector<std::unique_ptr<const ResolvedOption>>>
std::unique_ptr<ResolvedCheckConstraint> MakeResolvedCheckConstraint(
    const std::string& constraint_name,
    std::unique_ptr<const ResolvedExpr> expression,
    bool enforced,
    option_list_t option_list) {
  static_assert(std::is_base_of<
      ResolvedOption,
      typename std::decay<decltype(**(option_list.begin()))>::type>::value,
      "option_list must be a container of unique_ptr with elements of type "
      "ResolvedOption (or its descendants).");
  return MakeResolvedCheckConstraint(
      constraint_name,
      std::move(expression),
      enforced,
      {std::make_move_iterator(option_list.begin()),
       std::make_move_iterator(option_list.end())});
}

inline std::unique_ptr<ResolvedCheckConstraint> MakeResolvedCheckConstraint() {
  return std::unique_ptr<ResolvedCheckConstraint>(
      new ResolvedCheckConstraint());
}

// This is used in ResolvedQueryStmt to provide a user-visible name
// for each output column.
class ResolvedOutputColumn final : public ResolvedArgument {
 public:
  typedef ResolvedArgument SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_OUTPUT_COLUMN;

  friend std::unique_ptr<ResolvedOutputColumn> MakeResolvedOutputColumn();
 protected:
  ResolvedOutputColumn()
      : ResolvedArgument()
      , name_()
      , column_()
  {}
 public:

  ResolvedOutputColumn(const ResolvedOutputColumn&) = delete;
  ResolvedOutputColumn& operator=(const ResolvedOutputColumn&) = delete;

  friend std::unique_ptr<ResolvedOutputColumn> MakeResolvedOutputColumn(
      const std::string& name,
      const ResolvedColumn& column
  );
  ~ResolvedOutputColumn() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_OUTPUT_COLUMN; }
  std::string node_kind_string() const final { return "OutputColumn"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedOutputColumnProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedArgumentProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedOutputColumn>> RestoreFrom(
      const ResolvedOutputColumnProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  const std::string& name() const {
    accessed_ |= (1<<0);
    return name_;
  }
  void set_name(const std::string& v) {
    name_ = v;
  }

  const ResolvedColumn& column() const {
    accessed_ |= (1<<1);
    return column_;
  }
  void set_column(const ResolvedColumn& v) {
    column_ = v;
  }

 protected:
  explicit ResolvedOutputColumn(
      const std::string& name,
      const ResolvedColumn& column,
      ConstructorOverload)
      : ResolvedArgument(
            ConstructorOverload::NEW_CONSTRUCTOR),
      name_(name),
      column_(column) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
  std::string GetNameForDebugString() const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  std::string name_;
  ResolvedColumn column_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedOutputColumn> MakeResolvedOutputColumn(
    const std::string& name,
    const ResolvedColumn& column) {
  return std::unique_ptr<ResolvedOutputColumn>(new ResolvedOutputColumn(
        name,
        column,
        ResolvedOutputColumn::NEW_CONSTRUCTOR));
}

inline std::unique_ptr<ResolvedOutputColumn> MakeResolvedOutputColumn() {
  return std::unique_ptr<ResolvedOutputColumn>(
      new ResolvedOutputColumn());
}

// A Project node computes new expression values, and possibly drops
// columns from the input Scan's column_list.
//
// Each entry in <expr_list> is a new column computed from an expression.
//
// The column_list can include any columns from input_scan, plus these
// newly computed columns.
//
// NOTE: This scan will propagate the is_ordered property of <input_scan>
// by default.  To make this scan unordered, call set_is_ordered(false).
class ResolvedProjectScan final : public ResolvedScan {
 public:
  typedef ResolvedScan SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_PROJECT_SCAN;

  friend std::unique_ptr<ResolvedProjectScan> MakeResolvedProjectScan();
 protected:
  ResolvedProjectScan()
      : ResolvedScan()
      , expr_list_()
      , input_scan_()
  {}
 public:

  ResolvedProjectScan(const ResolvedProjectScan&) = delete;
  ResolvedProjectScan& operator=(const ResolvedProjectScan&) = delete;

  friend std::unique_ptr<ResolvedProjectScan> MakeResolvedProjectScan(
      const std::vector<ResolvedColumn>& column_list,
      std::vector<std::unique_ptr<const ResolvedComputedColumn>> expr_list,
      std::unique_ptr<const ResolvedScan> input_scan
  );
  ~ResolvedProjectScan() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_PROJECT_SCAN; }
  std::string node_kind_string() const final { return "ProjectScan"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedProjectScanProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedScanProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedProjectScan>> RestoreFrom(
      const ResolvedProjectScanProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  const std::vector<std::unique_ptr<const ResolvedComputedColumn>>& expr_list() const {
    accessed_ |= (1<<0);
    return expr_list_;
  }
  int expr_list_size() const {
    if (expr_list_.empty()) accessed_ |= (1<<0);
    return static_cast<int>(expr_list_.size());
  }
  const ResolvedComputedColumn* expr_list(int i) const {
    accessed_ |= (1<<0);
    return expr_list_.at(i).get();
  }
  void add_expr_list(std::unique_ptr<const ResolvedComputedColumn> v) {
    expr_list_.emplace_back(std::move(v));
  }
  void set_expr_list(std::vector<std::unique_ptr<const ResolvedComputedColumn>> v) {
    expr_list_ = std::move(v);
  }

  std::vector<std::unique_ptr<const ResolvedComputedColumn>> release_expr_list() {
    std::vector<std::unique_ptr<const ResolvedComputedColumn>> tmp;
    expr_list_.swap(tmp);
    return tmp;
  }

  const ResolvedScan* input_scan() const {
    accessed_ |= (1<<1);
    return input_scan_.get();
  }
  void set_input_scan(std::unique_ptr<const ResolvedScan> v) {
    input_scan_ = std::move(v);
    set_is_ordered(input_scan_->is_ordered());
  }

  std::unique_ptr<const ResolvedScan> release_input_scan() {
    return std::move(input_scan_);
  }

 protected:
  explicit ResolvedProjectScan(
      const std::vector<ResolvedColumn>& column_list,
      std::vector<std::unique_ptr<const ResolvedComputedColumn>> expr_list,
      std::unique_ptr<const ResolvedScan> input_scan,
      ConstructorOverload)
      : ResolvedScan(
            column_list,
            ConstructorOverload::NEW_CONSTRUCTOR),
      expr_list_(std::move(expr_list)),
      input_scan_(std::move(input_scan)) {
    set_is_ordered(input_scan_->is_ordered());
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  std::vector<std::unique_ptr<const ResolvedComputedColumn>> expr_list_;
  std::unique_ptr<const ResolvedScan> input_scan_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedProjectScan> MakeResolvedProjectScan(
    const std::vector<ResolvedColumn>& column_list,
    std::vector<std::unique_ptr<const ResolvedComputedColumn>> expr_list,
    std::unique_ptr<const ResolvedScan> input_scan) {
  return std::unique_ptr<ResolvedProjectScan>(new ResolvedProjectScan(
        column_list,
        std::move(expr_list),
        std::move(input_scan),
        ResolvedProjectScan::NEW_CONSTRUCTOR));
}

// Overloaded factory method for the construction of ResolvedProjectScan with
// a wider range of inputs for node-vector inputs.  In particular allows:
// 1. unique_ptr element type can be non-const.
// 2. unique_ptr element type can be any descendant of the required type.
// 3. input container can be any object with a `begin()` and `end()`.
//
// Note, initializer lists cannot be used to pass
//  expr_list
// due to incompatibility with unique_ptr.  Use zetasql::MakeNodeVector
// instead.
template <
  typename expr_list_t
      = std::vector<std::unique_ptr<const ResolvedComputedColumn>>>
std::unique_ptr<ResolvedProjectScan> MakeResolvedProjectScan(
    const std::vector<ResolvedColumn>& column_list,
    expr_list_t expr_list,
    std::unique_ptr<const ResolvedScan> input_scan) {
  static_assert(std::is_base_of<
      ResolvedComputedColumn,
      typename std::decay<decltype(**(expr_list.begin()))>::type>::value,
      "expr_list must be a container of unique_ptr with elements of type "
      "ResolvedComputedColumn (or its descendants).");
  return MakeResolvedProjectScan(
      column_list,
      {std::make_move_iterator(expr_list.begin()),
       std::make_move_iterator(expr_list.end())},
      std::move(input_scan));
}

inline std::unique_ptr<ResolvedProjectScan> MakeResolvedProjectScan() {
  return std::unique_ptr<ResolvedProjectScan>(
      new ResolvedProjectScan());
}

// This scan represents a call to a table-valued function (TVF). Each TVF
// returns an entire output relation instead of a single scalar value. The
// enclosing query may refer to the TVF as if it were a table subquery. The
// TVF may accept scalar arguments and/or other input relations.
//
// Scalar arguments work the same way as arguments for non-table-valued
// functions: in the resolved AST, their types are equal to the required
// argument types specified in the function signature.
//
// The function signature may also include relation arguments, and any such
// relation argument may specify a required schema. If such a required schema
// is present, then in the resolved AST, the ResolvedScan for each relational
// ResolvedTVFArgument is guaranteed to have the same number of columns as
// the required schema, and the provided columns match position-wise with the
// required columns. Each provided column has the same name and type as the
// corresponding required column.
//
// <column_list> is a set of new ResolvedColumns created by this scan.
// These output columns match positionally with the columns in the output
// schema of <signature>.
//
// <tvf> The TableValuedFunction entry that the catalog returned for this TVF
//       scan. Contains non-concrete function signatures which may include
//       arguments with templated types.
// <signature> The concrete table function signature for this TVF call,
//             including the types of all scalar arguments and the
//             number and types of columns of all table-valued
//             arguments. An engine may also subclass this object to
//             provide extra custom information and return an instance
//             of the subclass from the TableValuedFunction::Resolve
//             method.
// <argument_list> The vector of resolved arguments for this TVF call.
// <alias> The AS alias for the scan, or empty if none.
class ResolvedTVFScan final : public ResolvedScan {
 public:
  typedef ResolvedScan SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_TVFSCAN;

  friend std::unique_ptr<ResolvedTVFScan> MakeResolvedTVFScan(
      const std::vector<ResolvedColumn>& column_list,
      const TableValuedFunction* tvf,
      const std::shared_ptr<TVFSignature>& signature,
      std::vector<std::unique_ptr<const ResolvedTVFArgument>> argument_list,
      const std::string& alias
  );
  ~ResolvedTVFScan() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_TVFSCAN; }
  std::string node_kind_string() const final { return "TVFScan"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedTVFScanProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedScanProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedTVFScan>> RestoreFrom(
      const ResolvedTVFScanProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  const TableValuedFunction* tvf() const {
    accessed_ |= (1<<0);
    return tvf_;
  }
  void set_tvf(const TableValuedFunction* v) {
    tvf_ = v;
  }

  const std::shared_ptr<TVFSignature>& signature() const {
    accessed_ |= (1<<1);
    return signature_;
  }
  void set_signature(const std::shared_ptr<TVFSignature>& v) {
    signature_ = v;
  }

  const std::vector<std::unique_ptr<const ResolvedTVFArgument>>& argument_list() const {
    accessed_ |= (1<<2);
    return argument_list_;
  }
  int argument_list_size() const {
    if (argument_list_.empty()) accessed_ |= (1<<2);
    return static_cast<int>(argument_list_.size());
  }
  const ResolvedTVFArgument* argument_list(int i) const {
    accessed_ |= (1<<2);
    return argument_list_.at(i).get();
  }
  void add_argument_list(std::unique_ptr<const ResolvedTVFArgument> v) {
    argument_list_.emplace_back(std::move(v));
  }
  void set_argument_list(std::vector<std::unique_ptr<const ResolvedTVFArgument>> v) {
    argument_list_ = std::move(v);
  }

  std::vector<std::unique_ptr<const ResolvedTVFArgument>> release_argument_list() {
    std::vector<std::unique_ptr<const ResolvedTVFArgument>> tmp;
    argument_list_.swap(tmp);
    return tmp;
  }

  const std::string& alias() const {
    accessed_ |= (1<<3);
    return alias_;
  }
  void set_alias(const std::string& v) {
    alias_ = v;
  }

 protected:
  explicit ResolvedTVFScan(
      const std::vector<ResolvedColumn>& column_list,
      const TableValuedFunction* tvf,
      const std::shared_ptr<TVFSignature>& signature,
      std::vector<std::unique_ptr<const ResolvedTVFArgument>> argument_list,
      const std::string& alias,
      ConstructorOverload)
      : ResolvedScan(
            column_list,
            ConstructorOverload::NEW_CONSTRUCTOR),
      tvf_(tvf),
      signature_(signature),
      argument_list_(std::move(argument_list)),
      alias_(alias) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  const TableValuedFunction* tvf_;
  std::shared_ptr<TVFSignature> signature_;
  std::vector<std::unique_ptr<const ResolvedTVFArgument>> argument_list_;
  std::string alias_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedTVFScan> MakeResolvedTVFScan(
    const std::vector<ResolvedColumn>& column_list,
    const TableValuedFunction* tvf,
    const std::shared_ptr<TVFSignature>& signature,
    std::vector<std::unique_ptr<const ResolvedTVFArgument>> argument_list,
    const std::string& alias) {
  return std::unique_ptr<ResolvedTVFScan>(new ResolvedTVFScan(
        column_list,
        tvf,
        signature,
        std::move(argument_list),
        alias,
        ResolvedTVFScan::NEW_CONSTRUCTOR));
}

// Overloaded factory method for the construction of ResolvedTVFScan with
// a wider range of inputs for node-vector inputs.  In particular allows:
// 1. unique_ptr element type can be non-const.
// 2. unique_ptr element type can be any descendant of the required type.
// 3. input container can be any object with a `begin()` and `end()`.
//
// Note, initializer lists cannot be used to pass
//  argument_list
// due to incompatibility with unique_ptr.  Use zetasql::MakeNodeVector
// instead.
template <
  typename argument_list_t
      = std::vector<std::unique_ptr<const ResolvedTVFArgument>>>
std::unique_ptr<ResolvedTVFScan> MakeResolvedTVFScan(
    const std::vector<ResolvedColumn>& column_list,
    const TableValuedFunction* tvf,
    const std::shared_ptr<TVFSignature>& signature,
    argument_list_t argument_list,
    const std::string& alias) {
  static_assert(std::is_base_of<
      ResolvedTVFArgument,
      typename std::decay<decltype(**(argument_list.begin()))>::type>::value,
      "argument_list must be a container of unique_ptr with elements of type "
      "ResolvedTVFArgument (or its descendants).");
  return MakeResolvedTVFScan(
      column_list,
      tvf,
      signature,
      {std::make_move_iterator(argument_list.begin()),
       std::make_move_iterator(argument_list.end())},
      alias);
}

// This represents an argument to a table-valued function (TVF). The argument
// can be semantically scalar, relational or represent a model. Only one of
// the three fields will be set.
//
// <expr> The expression representing a scalar TVF argument.
// <scan> The scan representing a relational TVF argument.
// <model> The model representing an ML model TVF argument.
//
// <argument_column_list> maps columns from <scan> into specific columns
// of the TVF argument's input schema, matching those columns positionally.
// i.e. <scan>'s column_list may have fewer columns or out-of-order columns,
// and this vector maps those columns into specific TVF input columns.
class ResolvedTVFArgument final : public ResolvedArgument {
 public:
  typedef ResolvedArgument SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_TVFARGUMENT;

  friend std::unique_ptr<ResolvedTVFArgument> MakeResolvedTVFArgument();
 protected:
  ResolvedTVFArgument()
      : ResolvedArgument()
      , expr_()
      , scan_()
      , model_()
      , argument_column_list_()
  {}
 public:

  ResolvedTVFArgument(const ResolvedTVFArgument&) = delete;
  ResolvedTVFArgument& operator=(const ResolvedTVFArgument&) = delete;

  friend std::unique_ptr<ResolvedTVFArgument> MakeResolvedTVFArgument(
      std::unique_ptr<const ResolvedExpr> expr,
      std::unique_ptr<const ResolvedScan> scan,
      std::unique_ptr<const ResolvedModel> model,
      const std::vector<ResolvedColumn>& argument_column_list
  );
  ~ResolvedTVFArgument() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_TVFARGUMENT; }
  std::string node_kind_string() const final { return "TVFArgument"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedTVFArgumentProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedArgumentProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedTVFArgument>> RestoreFrom(
      const ResolvedTVFArgumentProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  const ResolvedExpr* expr() const {
    accessed_ |= (1<<0);
    return expr_.get();
  }
  void set_expr(std::unique_ptr<const ResolvedExpr> v) {
    expr_ = std::move(v);
  }

  std::unique_ptr<const ResolvedExpr> release_expr() {
    return std::move(expr_);
  }

  const ResolvedScan* scan() const {
    accessed_ |= (1<<1);
    return scan_.get();
  }
  void set_scan(std::unique_ptr<const ResolvedScan> v) {
    scan_ = std::move(v);
  }

  std::unique_ptr<const ResolvedScan> release_scan() {
    return std::move(scan_);
  }

  const ResolvedModel* model() const {
    accessed_ |= (1<<2);
    return model_.get();
  }
  void set_model(std::unique_ptr<const ResolvedModel> v) {
    model_ = std::move(v);
  }

  std::unique_ptr<const ResolvedModel> release_model() {
    return std::move(model_);
  }

  const std::vector<ResolvedColumn>& argument_column_list() const {
    accessed_ |= (1<<3);
    return argument_column_list_;
  }
  int argument_column_list_size() const {
    if (argument_column_list_.empty()) accessed_ |= (1<<3);
    return static_cast<int>(argument_column_list_.size());
  }
  ResolvedColumn argument_column_list(int i) const {
    accessed_ |= (1<<3);
    return argument_column_list_.at(i);
  }
  void add_argument_column_list(ResolvedColumn v) {
    argument_column_list_.push_back(ResolvedColumn(v));
  }
  void set_argument_column_list(const std::vector<ResolvedColumn>& v) {
    argument_column_list_ = v;
  }
  std::vector<ResolvedColumn>* mutable_argument_column_list() {
    accessed_ |= (1<<3);
    return &argument_column_list_;
  }

 protected:
  explicit ResolvedTVFArgument(
      std::unique_ptr<const ResolvedExpr> expr,
      std::unique_ptr<const ResolvedScan> scan,
      std::unique_ptr<const ResolvedModel> model,
      const std::vector<ResolvedColumn>& argument_column_list,
      ConstructorOverload)
      : ResolvedArgument(
            ConstructorOverload::NEW_CONSTRUCTOR),
      expr_(std::move(expr)),
      scan_(std::move(scan)),
      model_(std::move(model)),
      argument_column_list_(argument_column_list) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  std::unique_ptr<const ResolvedExpr> expr_;
  std::unique_ptr<const ResolvedScan> scan_;
  std::unique_ptr<const ResolvedModel> model_;
  std::vector<ResolvedColumn> argument_column_list_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedTVFArgument> MakeResolvedTVFArgument(
    std::unique_ptr<const ResolvedExpr> expr,
    std::unique_ptr<const ResolvedScan> scan,
    std::unique_ptr<const ResolvedModel> model,
    const std::vector<ResolvedColumn>& argument_column_list) {
  return std::unique_ptr<ResolvedTVFArgument>(new ResolvedTVFArgument(
        std::move(expr),
        std::move(scan),
        std::move(model),
        argument_column_list,
        ResolvedTVFArgument::NEW_CONSTRUCTOR));
}

inline std::unique_ptr<ResolvedTVFArgument> MakeResolvedTVFArgument() {
  return std::unique_ptr<ResolvedTVFArgument>(
      new ResolvedTVFArgument());
}

// The superclass of all ZetaSQL statements.
class ResolvedStatement  : public ResolvedNode {
 public:
  typedef ResolvedNode SUPER;

  // Number of leaf node types that exist as descendants of this abstract type.
  static const int NUM_DESCENDANT_LEAF_TYPES = 46;

  typedef ResolvedStatementEnums::ObjectAccess ObjectAccess;
  static const ObjectAccess NONE = ResolvedStatementEnums::NONE;
  static const ObjectAccess READ = ResolvedStatementEnums::READ;
  static const ObjectAccess WRITE = ResolvedStatementEnums::WRITE;
  static const ObjectAccess READ_WRITE = ResolvedStatementEnums::READ_WRITE;
  bool IsStatement() const final { return true; }

  ResolvedStatement()
      : ResolvedNode()
      , hint_list_()
  {}
 public:

  ResolvedStatement(const ResolvedStatement&) = delete;
  ResolvedStatement& operator=(const ResolvedStatement&) = delete;

  ~ResolvedStatement() override;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const override;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const override;

  zetasql_base::Status CheckFieldsAccessed() const override;
  void ClearFieldsAccessed() const override;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedStatementProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedNodeProto* proto) const final;

  virtual zetasql_base::Status SaveTo(
      Type::FileDescriptorSetMap* file_descriptor_set_map,
      AnyResolvedStatementProto* proto) const = 0;
  static zetasql_base::StatusOr<std::unique_ptr<ResolvedStatement>> RestoreFrom(
      const AnyResolvedStatementProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const override;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) override;

  // Member fields

  const std::vector<std::unique_ptr<const ResolvedOption>>& hint_list() const {
    accessed_ |= (1<<0);
    return hint_list_;
  }
  int hint_list_size() const {
    if (hint_list_.empty()) accessed_ |= (1<<0);
    return static_cast<int>(hint_list_.size());
  }
  const ResolvedOption* hint_list(int i) const {
    accessed_ |= (1<<0);
    return hint_list_.at(i).get();
  }
  void add_hint_list(std::unique_ptr<const ResolvedOption> v) {
    hint_list_.emplace_back(std::move(v));
  }
  void set_hint_list(std::vector<std::unique_ptr<const ResolvedOption>> v) {
    hint_list_ = std::move(v);
  }

  std::vector<std::unique_ptr<const ResolvedOption>> release_hint_list() {
    std::vector<std::unique_ptr<const ResolvedOption>> tmp;
    hint_list_.swap(tmp);
    return tmp;
  }

 protected:
  explicit ResolvedStatement(
      ConstructorOverload)
      : ResolvedNode(
),
      hint_list_() {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const override;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  std::vector<std::unique_ptr<const ResolvedOption>> hint_list_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

// An Explain statement. This is always the root of a statement hierarchy.
// Its child may be any statement type except another ResolvedExplainStmt.
//
// It is implementation dependent what action a back end system takes for an
// ExplainStatement.
class ResolvedExplainStmt final : public ResolvedStatement {
 public:
  typedef ResolvedStatement SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_EXPLAIN_STMT;

  friend std::unique_ptr<ResolvedExplainStmt> MakeResolvedExplainStmt();
 protected:
  ResolvedExplainStmt()
      : ResolvedStatement()
      , statement_()
  {}
 public:

  ResolvedExplainStmt(const ResolvedExplainStmt&) = delete;
  ResolvedExplainStmt& operator=(const ResolvedExplainStmt&) = delete;

  friend std::unique_ptr<ResolvedExplainStmt> MakeResolvedExplainStmt(
      std::unique_ptr<const ResolvedStatement> statement
  );
  ~ResolvedExplainStmt() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_EXPLAIN_STMT; }
  std::string node_kind_string() const final { return "ExplainStmt"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedExplainStmtProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedStatementProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedExplainStmt>> RestoreFrom(
      const ResolvedExplainStmtProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  const ResolvedStatement* statement() const {
    accessed_ |= (1<<0);
    return statement_.get();
  }
  void set_statement(std::unique_ptr<const ResolvedStatement> v) {
    statement_ = std::move(v);
  }

  std::unique_ptr<const ResolvedStatement> release_statement() {
    return std::move(statement_);
  }

 protected:
  explicit ResolvedExplainStmt(
      std::unique_ptr<const ResolvedStatement> statement,
      ConstructorOverload)
      : ResolvedStatement(
            ConstructorOverload::NEW_CONSTRUCTOR),
      statement_(std::move(statement)) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  std::unique_ptr<const ResolvedStatement> statement_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedExplainStmt> MakeResolvedExplainStmt(
    std::unique_ptr<const ResolvedStatement> statement) {
  return std::unique_ptr<ResolvedExplainStmt>(new ResolvedExplainStmt(
        std::move(statement),
        ResolvedExplainStmt::NEW_CONSTRUCTOR));
}

inline std::unique_ptr<ResolvedExplainStmt> MakeResolvedExplainStmt() {
  return std::unique_ptr<ResolvedExplainStmt>(
      new ResolvedExplainStmt());
}

// A SQL query statement.  This is the outermost query statement that runs
// and produces rows of output, like a SELECT.  (The contained query may be
// a Scan corresponding to a non-Select top-level operation like UNION ALL
// or WITH.)
//
// <output_column_list> gives the user-visible column names that should be
// returned in the API or query tools.  There may be duplicate names, and
// multiple output columns may reference the same column from <query>.
class ResolvedQueryStmt final : public ResolvedStatement {
 public:
  typedef ResolvedStatement SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_QUERY_STMT;

  friend std::unique_ptr<ResolvedQueryStmt> MakeResolvedQueryStmt();
 protected:
  ResolvedQueryStmt()
      : ResolvedStatement()
      , output_column_list_()
      , is_value_table_()
      , query_()
  {}
 public:

  ResolvedQueryStmt(const ResolvedQueryStmt&) = delete;
  ResolvedQueryStmt& operator=(const ResolvedQueryStmt&) = delete;

  friend std::unique_ptr<ResolvedQueryStmt> MakeResolvedQueryStmt(
      std::vector<std::unique_ptr<const ResolvedOutputColumn>> output_column_list,
      bool is_value_table,
      std::unique_ptr<const ResolvedScan> query
  );
  ~ResolvedQueryStmt() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_QUERY_STMT; }
  std::string node_kind_string() const final { return "QueryStmt"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedQueryStmtProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedStatementProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedQueryStmt>> RestoreFrom(
      const ResolvedQueryStmtProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  const std::vector<std::unique_ptr<const ResolvedOutputColumn>>& output_column_list() const {
    accessed_ |= (1<<0);
    return output_column_list_;
  }
  int output_column_list_size() const {
    if (output_column_list_.empty()) accessed_ |= (1<<0);
    return static_cast<int>(output_column_list_.size());
  }
  const ResolvedOutputColumn* output_column_list(int i) const {
    accessed_ |= (1<<0);
    return output_column_list_.at(i).get();
  }
  void add_output_column_list(std::unique_ptr<const ResolvedOutputColumn> v) {
    output_column_list_.emplace_back(std::move(v));
  }
  void set_output_column_list(std::vector<std::unique_ptr<const ResolvedOutputColumn>> v) {
    output_column_list_ = std::move(v);
  }

  std::vector<std::unique_ptr<const ResolvedOutputColumn>> release_output_column_list() {
    std::vector<std::unique_ptr<const ResolvedOutputColumn>> tmp;
    output_column_list_.swap(tmp);
    return tmp;
  }

  // If true, the result of this query is a value table. Rather than
  // producing rows with named columns, it produces rows with a single
  // unnamed value type.  output_column_list will have exactly one
  // column, with an empty name. See (broken link).
  bool is_value_table() const {
    accessed_ |= (1<<1);
    return is_value_table_;
  }
  void set_is_value_table(bool v) {
    is_value_table_ = v;
  }

  const ResolvedScan* query() const {
    accessed_ |= (1<<2);
    return query_.get();
  }
  void set_query(std::unique_ptr<const ResolvedScan> v) {
    query_ = std::move(v);
  }

  std::unique_ptr<const ResolvedScan> release_query() {
    return std::move(query_);
  }

 protected:
  explicit ResolvedQueryStmt(
      std::vector<std::unique_ptr<const ResolvedOutputColumn>> output_column_list,
      bool is_value_table,
      std::unique_ptr<const ResolvedScan> query,
      ConstructorOverload)
      : ResolvedStatement(
            ConstructorOverload::NEW_CONSTRUCTOR),
      output_column_list_(std::move(output_column_list)),
      is_value_table_(is_value_table),
      query_(std::move(query)) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  std::vector<std::unique_ptr<const ResolvedOutputColumn>> output_column_list_;
  bool is_value_table_;
  std::unique_ptr<const ResolvedScan> query_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedQueryStmt> MakeResolvedQueryStmt(
    std::vector<std::unique_ptr<const ResolvedOutputColumn>> output_column_list,
    bool is_value_table,
    std::unique_ptr<const ResolvedScan> query) {
  return std::unique_ptr<ResolvedQueryStmt>(new ResolvedQueryStmt(
        std::move(output_column_list),
        is_value_table,
        std::move(query),
        ResolvedQueryStmt::NEW_CONSTRUCTOR));
}

// Overloaded factory method for the construction of ResolvedQueryStmt with
// a wider range of inputs for node-vector inputs.  In particular allows:
// 1. unique_ptr element type can be non-const.
// 2. unique_ptr element type can be any descendant of the required type.
// 3. input container can be any object with a `begin()` and `end()`.
//
// Note, initializer lists cannot be used to pass
//  output_column_list
// due to incompatibility with unique_ptr.  Use zetasql::MakeNodeVector
// instead.
template <
  typename output_column_list_t
      = std::vector<std::unique_ptr<const ResolvedOutputColumn>>>
std::unique_ptr<ResolvedQueryStmt> MakeResolvedQueryStmt(
    output_column_list_t output_column_list,
    bool is_value_table,
    std::unique_ptr<const ResolvedScan> query) {
  static_assert(std::is_base_of<
      ResolvedOutputColumn,
      typename std::decay<decltype(**(output_column_list.begin()))>::type>::value,
      "output_column_list must be a container of unique_ptr with elements of type "
      "ResolvedOutputColumn (or its descendants).");
  return MakeResolvedQueryStmt(
      {std::make_move_iterator(output_column_list.begin()),
       std::make_move_iterator(output_column_list.end())},
      is_value_table,
      std::move(query));
}

inline std::unique_ptr<ResolvedQueryStmt> MakeResolvedQueryStmt() {
  return std::unique_ptr<ResolvedQueryStmt>(
      new ResolvedQueryStmt());
}

// This statement:
//   CREATE DATABASE <name> [OPTIONS (...)]
// <name_path> is a vector giving the identifier path in the database name.
// <option_list> specifies the options of the database.
class ResolvedCreateDatabaseStmt final : public ResolvedStatement {
 public:
  typedef ResolvedStatement SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_CREATE_DATABASE_STMT;

  friend std::unique_ptr<ResolvedCreateDatabaseStmt> MakeResolvedCreateDatabaseStmt();
 protected:
  ResolvedCreateDatabaseStmt()
      : ResolvedStatement()
      , name_path_()
      , option_list_()
  {}
 public:

  ResolvedCreateDatabaseStmt(const ResolvedCreateDatabaseStmt&) = delete;
  ResolvedCreateDatabaseStmt& operator=(const ResolvedCreateDatabaseStmt&) = delete;

  friend std::unique_ptr<ResolvedCreateDatabaseStmt> MakeResolvedCreateDatabaseStmt(
      const std::vector<std::string>& name_path,
      std::vector<std::unique_ptr<const ResolvedOption>> option_list
  );
  ~ResolvedCreateDatabaseStmt() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_CREATE_DATABASE_STMT; }
  std::string node_kind_string() const final { return "CreateDatabaseStmt"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedCreateDatabaseStmtProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedStatementProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedCreateDatabaseStmt>> RestoreFrom(
      const ResolvedCreateDatabaseStmtProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  const std::vector<std::string>& name_path() const {
    accessed_ |= (1<<0);
    return name_path_;
  }
  int name_path_size() const {
    if (name_path_.empty()) accessed_ |= (1<<0);
    return static_cast<int>(name_path_.size());
  }
  std::string name_path(int i) const {
    accessed_ |= (1<<0);
    return name_path_.at(i);
  }
  void add_name_path(std::string v) {
    name_path_.push_back(std::string(v));
  }
  void set_name_path(const std::vector<std::string>& v) {
    name_path_ = v;
  }
  std::vector<std::string>* mutable_name_path() {
    accessed_ |= (1<<0);
    return &name_path_;
  }

  const std::vector<std::unique_ptr<const ResolvedOption>>& option_list() const {
    accessed_ |= (1<<1);
    return option_list_;
  }
  int option_list_size() const {
    if (option_list_.empty()) accessed_ |= (1<<1);
    return static_cast<int>(option_list_.size());
  }
  const ResolvedOption* option_list(int i) const {
    accessed_ |= (1<<1);
    return option_list_.at(i).get();
  }
  void add_option_list(std::unique_ptr<const ResolvedOption> v) {
    option_list_.emplace_back(std::move(v));
  }
  void set_option_list(std::vector<std::unique_ptr<const ResolvedOption>> v) {
    option_list_ = std::move(v);
  }

  std::vector<std::unique_ptr<const ResolvedOption>> release_option_list() {
    std::vector<std::unique_ptr<const ResolvedOption>> tmp;
    option_list_.swap(tmp);
    return tmp;
  }

 protected:
  explicit ResolvedCreateDatabaseStmt(
      const std::vector<std::string>& name_path,
      std::vector<std::unique_ptr<const ResolvedOption>> option_list,
      ConstructorOverload)
      : ResolvedStatement(
            ConstructorOverload::NEW_CONSTRUCTOR),
      name_path_(name_path),
      option_list_(std::move(option_list)) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  std::vector<std::string> name_path_;
  std::vector<std::unique_ptr<const ResolvedOption>> option_list_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedCreateDatabaseStmt> MakeResolvedCreateDatabaseStmt(
    const std::vector<std::string>& name_path,
    std::vector<std::unique_ptr<const ResolvedOption>> option_list) {
  return std::unique_ptr<ResolvedCreateDatabaseStmt>(new ResolvedCreateDatabaseStmt(
        name_path,
        std::move(option_list),
        ResolvedCreateDatabaseStmt::NEW_CONSTRUCTOR));
}

// Overloaded factory method for the construction of ResolvedCreateDatabaseStmt with
// a wider range of inputs for node-vector inputs.  In particular allows:
// 1. unique_ptr element type can be non-const.
// 2. unique_ptr element type can be any descendant of the required type.
// 3. input container can be any object with a `begin()` and `end()`.
//
// Note, initializer lists cannot be used to pass
//  option_list
// due to incompatibility with unique_ptr.  Use zetasql::MakeNodeVector
// instead.
template <
  typename option_list_t
      = std::vector<std::unique_ptr<const ResolvedOption>>>
std::unique_ptr<ResolvedCreateDatabaseStmt> MakeResolvedCreateDatabaseStmt(
    const std::vector<std::string>& name_path,
    option_list_t option_list) {
  static_assert(std::is_base_of<
      ResolvedOption,
      typename std::decay<decltype(**(option_list.begin()))>::type>::value,
      "option_list must be a container of unique_ptr with elements of type "
      "ResolvedOption (or its descendants).");
  return MakeResolvedCreateDatabaseStmt(
      name_path,
      {std::make_move_iterator(option_list.begin()),
       std::make_move_iterator(option_list.end())});
}

inline std::unique_ptr<ResolvedCreateDatabaseStmt> MakeResolvedCreateDatabaseStmt() {
  return std::unique_ptr<ResolvedCreateDatabaseStmt>(
      new ResolvedCreateDatabaseStmt());
}

// Common superclass for CREATE statements with standard modifiers like
//         CREATE [OR REPLACE] [TEMP|TEMPORARY|PUBLIC|PRIVATE] <object type>
//         [IF NOT EXISTS] <name> ...
//
// <name_path> is a vector giving the identifier path in the table name.
// <create_scope> is the relevant scope, i.e., DEFAULT, TEMP, PUBLIC,
//                or PRIVATE.  PUBLIC/PRIVATE are only valid in module
//                resolution context, see (broken link)
//                for details.
// <create_mode> indicates if this was CREATE, CREATE OR REPLACE, or
//               CREATE IF NOT EXISTS.
class ResolvedCreateStatement  : public ResolvedStatement {
 public:
  typedef ResolvedStatement SUPER;

  // Number of leaf node types that exist as descendants of this abstract type.
  static const int NUM_DESCENDANT_LEAF_TYPES = 11;

  typedef ResolvedCreateStatementEnums::CreateScope CreateScope;
  typedef ResolvedCreateStatementEnums::CreateMode CreateMode;
  typedef ResolvedCreateStatementEnums::SqlSecurity SqlSecurity;
  static const CreateScope CREATE_DEFAULT_SCOPE = ResolvedCreateStatementEnums::CREATE_DEFAULT_SCOPE;
  static const CreateScope CREATE_PRIVATE = ResolvedCreateStatementEnums::CREATE_PRIVATE;
  static const CreateScope CREATE_PUBLIC = ResolvedCreateStatementEnums::CREATE_PUBLIC;
  static const CreateScope CREATE_TEMP = ResolvedCreateStatementEnums::CREATE_TEMP;
  static const CreateMode CREATE_DEFAULT = ResolvedCreateStatementEnums::CREATE_DEFAULT;
  static const CreateMode CREATE_OR_REPLACE = ResolvedCreateStatementEnums::CREATE_OR_REPLACE;
  static const CreateMode CREATE_IF_NOT_EXISTS = ResolvedCreateStatementEnums::CREATE_IF_NOT_EXISTS;
  static const SqlSecurity SQL_SECURITY_UNSPECIFIED = ResolvedCreateStatementEnums::SQL_SECURITY_UNSPECIFIED;
  static const SqlSecurity SQL_SECURITY_DEFINER = ResolvedCreateStatementEnums::SQL_SECURITY_DEFINER;
  static const SqlSecurity SQL_SECURITY_INVOKER = ResolvedCreateStatementEnums::SQL_SECURITY_INVOKER;

  ResolvedCreateStatement()
      : ResolvedStatement()
      , name_path_()
      , create_scope_()
      , create_mode_()
  {}
 public:

  ResolvedCreateStatement(const ResolvedCreateStatement&) = delete;
  ResolvedCreateStatement& operator=(const ResolvedCreateStatement&) = delete;

  ~ResolvedCreateStatement() override;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const override;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const override;

  zetasql_base::Status CheckFieldsAccessed() const override;
  void ClearFieldsAccessed() const override;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedCreateStatementProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedStatementProto* proto) const final;

  virtual zetasql_base::Status SaveTo(
      Type::FileDescriptorSetMap* file_descriptor_set_map,
      AnyResolvedCreateStatementProto* proto) const = 0;
  static zetasql_base::StatusOr<std::unique_ptr<ResolvedCreateStatement>> RestoreFrom(
      const AnyResolvedCreateStatementProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const override;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) override;

  // Member fields

  const std::vector<std::string>& name_path() const {
    accessed_ |= (1<<0);
    return name_path_;
  }
  int name_path_size() const {
    if (name_path_.empty()) accessed_ |= (1<<0);
    return static_cast<int>(name_path_.size());
  }
  std::string name_path(int i) const {
    accessed_ |= (1<<0);
    return name_path_.at(i);
  }
  void add_name_path(std::string v) {
    name_path_.push_back(std::string(v));
  }
  void set_name_path(const std::vector<std::string>& v) {
    name_path_ = v;
  }
  std::vector<std::string>* mutable_name_path() {
    accessed_ |= (1<<0);
    return &name_path_;
  }

  CreateScope create_scope() const {
    accessed_ |= (1<<1);
    return create_scope_;
  }
  void set_create_scope(CreateScope v) {
    create_scope_ = v;
  }

  CreateMode create_mode() const {
    accessed_ |= (1<<2);
    return create_mode_;
  }
  void set_create_mode(CreateMode v) {
    create_mode_ = v;
  }

 protected:
  explicit ResolvedCreateStatement(
      const std::vector<std::string>& name_path,
      CreateScope create_scope,
      CreateMode create_mode,
      ConstructorOverload)
      : ResolvedStatement(
            ConstructorOverload::NEW_CONSTRUCTOR),
      name_path_(name_path),
      create_scope_(create_scope),
      create_mode_(create_mode) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const override;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  std::vector<std::string> name_path_;
  CreateScope create_scope_;
  CreateMode create_mode_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

// Represents one of indexed items in CREATE INDEX statement, with the
// ordering direction specified.
class ResolvedIndexItem final : public ResolvedArgument {
 public:
  typedef ResolvedArgument SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_INDEX_ITEM;

  friend std::unique_ptr<ResolvedIndexItem> MakeResolvedIndexItem();
 protected:
  ResolvedIndexItem()
      : ResolvedArgument()
      , column_ref_()
      , descending_()
  {}
 public:

  ResolvedIndexItem(const ResolvedIndexItem&) = delete;
  ResolvedIndexItem& operator=(const ResolvedIndexItem&) = delete;

  friend std::unique_ptr<ResolvedIndexItem> MakeResolvedIndexItem(
      std::unique_ptr<const ResolvedColumnRef> column_ref,
      bool descending
  );
  ~ResolvedIndexItem() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_INDEX_ITEM; }
  std::string node_kind_string() const final { return "IndexItem"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedIndexItemProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedArgumentProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedIndexItem>> RestoreFrom(
      const ResolvedIndexItemProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  const ResolvedColumnRef* column_ref() const {
    accessed_ |= (1<<0);
    return column_ref_.get();
  }
  void set_column_ref(std::unique_ptr<const ResolvedColumnRef> v) {
    column_ref_ = std::move(v);
  }

  std::unique_ptr<const ResolvedColumnRef> release_column_ref() {
    return std::move(column_ref_);
  }

  bool descending() const {
    accessed_ |= (1<<1);
    return descending_;
  }
  void set_descending(bool v) {
    descending_ = v;
  }

 protected:
  explicit ResolvedIndexItem(
      std::unique_ptr<const ResolvedColumnRef> column_ref,
      bool descending,
      ConstructorOverload)
      : ResolvedArgument(
            ConstructorOverload::NEW_CONSTRUCTOR),
      column_ref_(std::move(column_ref)),
      descending_(descending) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  std::unique_ptr<const ResolvedColumnRef> column_ref_;
  bool descending_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedIndexItem> MakeResolvedIndexItem(
    std::unique_ptr<const ResolvedColumnRef> column_ref,
    bool descending) {
  return std::unique_ptr<ResolvedIndexItem>(new ResolvedIndexItem(
        std::move(column_ref),
        descending,
        ResolvedIndexItem::NEW_CONSTRUCTOR));
}

inline std::unique_ptr<ResolvedIndexItem> MakeResolvedIndexItem() {
  return std::unique_ptr<ResolvedIndexItem>(
      new ResolvedIndexItem());
}

// This is used in CREATE INDEX STMT to represent the unnest operation
// performed on the base table. The produced element columns or array offset
// columns (optional) can appear in other ResolvedUnnestItem or index keys.
//
// <array_expr> is the expression of the array field, e.g., t.array_field.
// <element_column> is the new column produced by this unnest item that
//                  stores the array element value for each row.
// <array_offset_column> is optional. If present, it defines the column
//                       produced by this unnest item that stores the array
//                       offset (0-based) for the corresponding
//                       <element_column>.
class ResolvedUnnestItem final : public ResolvedArgument {
 public:
  typedef ResolvedArgument SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_UNNEST_ITEM;

  friend std::unique_ptr<ResolvedUnnestItem> MakeResolvedUnnestItem();
 protected:
  ResolvedUnnestItem()
      : ResolvedArgument()
      , array_expr_()
      , element_column_()
      , array_offset_column_()
  {}
 public:

  ResolvedUnnestItem(const ResolvedUnnestItem&) = delete;
  ResolvedUnnestItem& operator=(const ResolvedUnnestItem&) = delete;

  friend std::unique_ptr<ResolvedUnnestItem> MakeResolvedUnnestItem(
      std::unique_ptr<const ResolvedExpr> array_expr,
      const ResolvedColumn& element_column,
      std::unique_ptr<const ResolvedColumnHolder> array_offset_column
  );
  ~ResolvedUnnestItem() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_UNNEST_ITEM; }
  std::string node_kind_string() const final { return "UnnestItem"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedUnnestItemProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedArgumentProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedUnnestItem>> RestoreFrom(
      const ResolvedUnnestItemProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  const ResolvedExpr* array_expr() const {
    accessed_ |= (1<<0);
    return array_expr_.get();
  }
  void set_array_expr(std::unique_ptr<const ResolvedExpr> v) {
    array_expr_ = std::move(v);
  }

  std::unique_ptr<const ResolvedExpr> release_array_expr() {
    return std::move(array_expr_);
  }

  const ResolvedColumn& element_column() const {
    accessed_ |= (1<<1);
    return element_column_;
  }
  void set_element_column(const ResolvedColumn& v) {
    element_column_ = v;
  }

  const ResolvedColumnHolder* array_offset_column() const {
    accessed_ |= (1<<2);
    return array_offset_column_.get();
  }
  void set_array_offset_column(std::unique_ptr<const ResolvedColumnHolder> v) {
    array_offset_column_ = std::move(v);
  }

  std::unique_ptr<const ResolvedColumnHolder> release_array_offset_column() {
    return std::move(array_offset_column_);
  }

 protected:
  explicit ResolvedUnnestItem(
      std::unique_ptr<const ResolvedExpr> array_expr,
      const ResolvedColumn& element_column,
      std::unique_ptr<const ResolvedColumnHolder> array_offset_column,
      ConstructorOverload)
      : ResolvedArgument(
            ConstructorOverload::NEW_CONSTRUCTOR),
      array_expr_(std::move(array_expr)),
      element_column_(element_column),
      array_offset_column_(std::move(array_offset_column)) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  std::unique_ptr<const ResolvedExpr> array_expr_;
  ResolvedColumn element_column_;
  std::unique_ptr<const ResolvedColumnHolder> array_offset_column_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedUnnestItem> MakeResolvedUnnestItem(
    std::unique_ptr<const ResolvedExpr> array_expr,
    const ResolvedColumn& element_column,
    std::unique_ptr<const ResolvedColumnHolder> array_offset_column) {
  return std::unique_ptr<ResolvedUnnestItem>(new ResolvedUnnestItem(
        std::move(array_expr),
        element_column,
        std::move(array_offset_column),
        ResolvedUnnestItem::NEW_CONSTRUCTOR));
}

inline std::unique_ptr<ResolvedUnnestItem> MakeResolvedUnnestItem() {
  return std::unique_ptr<ResolvedUnnestItem>(
      new ResolvedUnnestItem());
}

// This statement:
// CREATE [OR REPLACE] [UNIQUE] INDEX [IF NOT EXISTS] <index_name_path>
// ON <table_name_path>
// [STORING (Expression, ...)]
// [UNNEST(path_expression) [[AS] alias] [WITH OFFSET [[AS] alias]], ...]
// (path_expression [ASC|DESC], ...) [OPTIONS (name=value, ...)];
//
// <table_name_path> is the name of table being indexed.
// <table_scan> is a TableScan on the table being indexed.
// <is_unique> specifies if the index has unique entries.
// <index_item_list> has the columns being indexed, specified as references
//                   to 'computed_columns_list' entries or the columns of
//                   'table_scan'.
// <storing_expression_list> has the expressions in the storing clause.
// <option_list> has engine-specific directives for how and where to
//               materialize this index.
// <computed_columns_list> has computed columns derived from the columns of
//                         'table_scan' or 'unnest_expressions_list'. For
//                         example, the extracted field (e.g., x.y.z).
// <unnest_expressions_list> has unnest expressions derived from
//                           'table_scan' or previous unnest expressions in
//                           the list. So the list order is significant.
class ResolvedCreateIndexStmt final : public ResolvedCreateStatement {
 public:
  typedef ResolvedCreateStatement SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_CREATE_INDEX_STMT;

  friend std::unique_ptr<ResolvedCreateIndexStmt> MakeResolvedCreateIndexStmt();
 protected:
  ResolvedCreateIndexStmt()
      : ResolvedCreateStatement()
      , table_name_path_()
      , table_scan_()
      , is_unique_()
      , index_item_list_()
      , storing_expression_list_()
      , option_list_()
      , computed_columns_list_()
      , unnest_expressions_list_()
  {}
 public:

  ResolvedCreateIndexStmt(const ResolvedCreateIndexStmt&) = delete;
  ResolvedCreateIndexStmt& operator=(const ResolvedCreateIndexStmt&) = delete;

  friend std::unique_ptr<ResolvedCreateIndexStmt> MakeResolvedCreateIndexStmt(
      const std::vector<std::string>& name_path,
      CreateScope create_scope,
      CreateMode create_mode,
      const std::vector<std::string>& table_name_path,
      std::unique_ptr<const ResolvedTableScan> table_scan,
      bool is_unique,
      std::vector<std::unique_ptr<const ResolvedIndexItem>> index_item_list,
      std::vector<std::unique_ptr<const ResolvedExpr>> storing_expression_list,
      std::vector<std::unique_ptr<const ResolvedOption>> option_list,
      std::vector<std::unique_ptr<const ResolvedComputedColumn>> computed_columns_list,
      std::vector<std::unique_ptr<const ResolvedUnnestItem>> unnest_expressions_list
  );
  ~ResolvedCreateIndexStmt() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_CREATE_INDEX_STMT; }
  std::string node_kind_string() const final { return "CreateIndexStmt"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedCreateIndexStmtProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedCreateStatementProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedCreateIndexStmt>> RestoreFrom(
      const ResolvedCreateIndexStmtProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  const std::vector<std::string>& table_name_path() const {
    accessed_ |= (1<<0);
    return table_name_path_;
  }
  int table_name_path_size() const {
    if (table_name_path_.empty()) accessed_ |= (1<<0);
    return static_cast<int>(table_name_path_.size());
  }
  std::string table_name_path(int i) const {
    accessed_ |= (1<<0);
    return table_name_path_.at(i);
  }
  void add_table_name_path(std::string v) {
    table_name_path_.push_back(std::string(v));
  }
  void set_table_name_path(const std::vector<std::string>& v) {
    table_name_path_ = v;
  }
  std::vector<std::string>* mutable_table_name_path() {
    accessed_ |= (1<<0);
    return &table_name_path_;
  }

  const ResolvedTableScan* table_scan() const {
    accessed_ |= (1<<1);
    return table_scan_.get();
  }
  void set_table_scan(std::unique_ptr<const ResolvedTableScan> v) {
    table_scan_ = std::move(v);
  }

  std::unique_ptr<const ResolvedTableScan> release_table_scan() {
    return std::move(table_scan_);
  }

  bool is_unique() const {
    accessed_ |= (1<<2);
    return is_unique_;
  }
  void set_is_unique(bool v) {
    is_unique_ = v;
  }

  const std::vector<std::unique_ptr<const ResolvedIndexItem>>& index_item_list() const {
    accessed_ |= (1<<3);
    return index_item_list_;
  }
  int index_item_list_size() const {
    if (index_item_list_.empty()) accessed_ |= (1<<3);
    return static_cast<int>(index_item_list_.size());
  }
  const ResolvedIndexItem* index_item_list(int i) const {
    accessed_ |= (1<<3);
    return index_item_list_.at(i).get();
  }
  void add_index_item_list(std::unique_ptr<const ResolvedIndexItem> v) {
    index_item_list_.emplace_back(std::move(v));
  }
  void set_index_item_list(std::vector<std::unique_ptr<const ResolvedIndexItem>> v) {
    index_item_list_ = std::move(v);
  }

  std::vector<std::unique_ptr<const ResolvedIndexItem>> release_index_item_list() {
    std::vector<std::unique_ptr<const ResolvedIndexItem>> tmp;
    index_item_list_.swap(tmp);
    return tmp;
  }

  const std::vector<std::unique_ptr<const ResolvedExpr>>& storing_expression_list() const {
    accessed_ |= (1<<4);
    return storing_expression_list_;
  }
  int storing_expression_list_size() const {
    if (storing_expression_list_.empty()) accessed_ |= (1<<4);
    return static_cast<int>(storing_expression_list_.size());
  }
  const ResolvedExpr* storing_expression_list(int i) const {
    accessed_ |= (1<<4);
    return storing_expression_list_.at(i).get();
  }
  void add_storing_expression_list(std::unique_ptr<const ResolvedExpr> v) {
    storing_expression_list_.emplace_back(std::move(v));
  }
  void set_storing_expression_list(std::vector<std::unique_ptr<const ResolvedExpr>> v) {
    storing_expression_list_ = std::move(v);
  }

  std::vector<std::unique_ptr<const ResolvedExpr>> release_storing_expression_list() {
    std::vector<std::unique_ptr<const ResolvedExpr>> tmp;
    storing_expression_list_.swap(tmp);
    return tmp;
  }

  const std::vector<std::unique_ptr<const ResolvedOption>>& option_list() const {
    accessed_ |= (1<<5);
    return option_list_;
  }
  int option_list_size() const {
    if (option_list_.empty()) accessed_ |= (1<<5);
    return static_cast<int>(option_list_.size());
  }
  const ResolvedOption* option_list(int i) const {
    accessed_ |= (1<<5);
    return option_list_.at(i).get();
  }
  void add_option_list(std::unique_ptr<const ResolvedOption> v) {
    option_list_.emplace_back(std::move(v));
  }
  void set_option_list(std::vector<std::unique_ptr<const ResolvedOption>> v) {
    option_list_ = std::move(v);
  }

  std::vector<std::unique_ptr<const ResolvedOption>> release_option_list() {
    std::vector<std::unique_ptr<const ResolvedOption>> tmp;
    option_list_.swap(tmp);
    return tmp;
  }

  const std::vector<std::unique_ptr<const ResolvedComputedColumn>>& computed_columns_list() const {
    accessed_ |= (1<<6);
    return computed_columns_list_;
  }
  int computed_columns_list_size() const {
    if (computed_columns_list_.empty()) accessed_ |= (1<<6);
    return static_cast<int>(computed_columns_list_.size());
  }
  const ResolvedComputedColumn* computed_columns_list(int i) const {
    accessed_ |= (1<<6);
    return computed_columns_list_.at(i).get();
  }
  void add_computed_columns_list(std::unique_ptr<const ResolvedComputedColumn> v) {
    computed_columns_list_.emplace_back(std::move(v));
  }
  void set_computed_columns_list(std::vector<std::unique_ptr<const ResolvedComputedColumn>> v) {
    computed_columns_list_ = std::move(v);
  }

  std::vector<std::unique_ptr<const ResolvedComputedColumn>> release_computed_columns_list() {
    std::vector<std::unique_ptr<const ResolvedComputedColumn>> tmp;
    computed_columns_list_.swap(tmp);
    return tmp;
  }

  const std::vector<std::unique_ptr<const ResolvedUnnestItem>>& unnest_expressions_list() const {
    accessed_ |= (1<<7);
    return unnest_expressions_list_;
  }
  int unnest_expressions_list_size() const {
    if (unnest_expressions_list_.empty()) accessed_ |= (1<<7);
    return static_cast<int>(unnest_expressions_list_.size());
  }
  const ResolvedUnnestItem* unnest_expressions_list(int i) const {
    accessed_ |= (1<<7);
    return unnest_expressions_list_.at(i).get();
  }
  void add_unnest_expressions_list(std::unique_ptr<const ResolvedUnnestItem> v) {
    unnest_expressions_list_.emplace_back(std::move(v));
  }
  void set_unnest_expressions_list(std::vector<std::unique_ptr<const ResolvedUnnestItem>> v) {
    unnest_expressions_list_ = std::move(v);
  }

  std::vector<std::unique_ptr<const ResolvedUnnestItem>> release_unnest_expressions_list() {
    std::vector<std::unique_ptr<const ResolvedUnnestItem>> tmp;
    unnest_expressions_list_.swap(tmp);
    return tmp;
  }

 protected:
  explicit ResolvedCreateIndexStmt(
      const std::vector<std::string>& name_path,
      CreateScope create_scope,
      CreateMode create_mode,
      const std::vector<std::string>& table_name_path,
      std::unique_ptr<const ResolvedTableScan> table_scan,
      bool is_unique,
      std::vector<std::unique_ptr<const ResolvedIndexItem>> index_item_list,
      std::vector<std::unique_ptr<const ResolvedExpr>> storing_expression_list,
      std::vector<std::unique_ptr<const ResolvedOption>> option_list,
      std::vector<std::unique_ptr<const ResolvedComputedColumn>> computed_columns_list,
      std::vector<std::unique_ptr<const ResolvedUnnestItem>> unnest_expressions_list,
      ConstructorOverload)
      : ResolvedCreateStatement(
            name_path,
            create_scope,
            create_mode,
            ConstructorOverload::NEW_CONSTRUCTOR),
      table_name_path_(table_name_path),
      table_scan_(std::move(table_scan)),
      is_unique_(is_unique),
      index_item_list_(std::move(index_item_list)),
      storing_expression_list_(std::move(storing_expression_list)),
      option_list_(std::move(option_list)),
      computed_columns_list_(std::move(computed_columns_list)),
      unnest_expressions_list_(std::move(unnest_expressions_list)) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  std::vector<std::string> table_name_path_;
  std::unique_ptr<const ResolvedTableScan> table_scan_;
  bool is_unique_;
  std::vector<std::unique_ptr<const ResolvedIndexItem>> index_item_list_;
  std::vector<std::unique_ptr<const ResolvedExpr>> storing_expression_list_;
  std::vector<std::unique_ptr<const ResolvedOption>> option_list_;
  std::vector<std::unique_ptr<const ResolvedComputedColumn>> computed_columns_list_;
  std::vector<std::unique_ptr<const ResolvedUnnestItem>> unnest_expressions_list_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedCreateIndexStmt> MakeResolvedCreateIndexStmt(
    const std::vector<std::string>& name_path,
    ResolvedCreateStatement::CreateScope create_scope,
    ResolvedCreateStatement::CreateMode create_mode,
    const std::vector<std::string>& table_name_path,
    std::unique_ptr<const ResolvedTableScan> table_scan,
    bool is_unique,
    std::vector<std::unique_ptr<const ResolvedIndexItem>> index_item_list,
    std::vector<std::unique_ptr<const ResolvedExpr>> storing_expression_list,
    std::vector<std::unique_ptr<const ResolvedOption>> option_list,
    std::vector<std::unique_ptr<const ResolvedComputedColumn>> computed_columns_list,
    std::vector<std::unique_ptr<const ResolvedUnnestItem>> unnest_expressions_list) {
  return std::unique_ptr<ResolvedCreateIndexStmt>(new ResolvedCreateIndexStmt(
        name_path,
        create_scope,
        create_mode,
        table_name_path,
        std::move(table_scan),
        is_unique,
        std::move(index_item_list),
        std::move(storing_expression_list),
        std::move(option_list),
        std::move(computed_columns_list),
        std::move(unnest_expressions_list),
        ResolvedCreateIndexStmt::NEW_CONSTRUCTOR));
}

// Overloaded factory method for the construction of ResolvedCreateIndexStmt with
// a wider range of inputs for node-vector inputs.  In particular allows:
// 1. unique_ptr element type can be non-const.
// 2. unique_ptr element type can be any descendant of the required type.
// 3. input container can be any object with a `begin()` and `end()`.
//
// Note, initializer lists cannot be used to pass
//  index_item_list, storing_expression_list, option_list, computed_columns_list, unnest_expressions_list
// due to incompatibility with unique_ptr.  Use zetasql::MakeNodeVector
// instead.
template <
  typename index_item_list_t
      = std::vector<std::unique_ptr<const ResolvedIndexItem>>,
  typename storing_expression_list_t
      = std::vector<std::unique_ptr<const ResolvedExpr>>,
  typename option_list_t
      = std::vector<std::unique_ptr<const ResolvedOption>>,
  typename computed_columns_list_t
      = std::vector<std::unique_ptr<const ResolvedComputedColumn>>,
  typename unnest_expressions_list_t
      = std::vector<std::unique_ptr<const ResolvedUnnestItem>>>
std::unique_ptr<ResolvedCreateIndexStmt> MakeResolvedCreateIndexStmt(
    const std::vector<std::string>& name_path,
    ResolvedCreateStatement::CreateScope create_scope,
    ResolvedCreateStatement::CreateMode create_mode,
    const std::vector<std::string>& table_name_path,
    std::unique_ptr<const ResolvedTableScan> table_scan,
    bool is_unique,
    index_item_list_t index_item_list,
    storing_expression_list_t storing_expression_list,
    option_list_t option_list,
    computed_columns_list_t computed_columns_list,
    unnest_expressions_list_t unnest_expressions_list) {
  static_assert(std::is_base_of<
      ResolvedIndexItem,
      typename std::decay<decltype(**(index_item_list.begin()))>::type>::value,
      "index_item_list must be a container of unique_ptr with elements of type "
      "ResolvedIndexItem (or its descendants).");
  static_assert(std::is_base_of<
      ResolvedExpr,
      typename std::decay<decltype(**(storing_expression_list.begin()))>::type>::value,
      "storing_expression_list must be a container of unique_ptr with elements of type "
      "ResolvedExpr (or its descendants).");
  static_assert(std::is_base_of<
      ResolvedOption,
      typename std::decay<decltype(**(option_list.begin()))>::type>::value,
      "option_list must be a container of unique_ptr with elements of type "
      "ResolvedOption (or its descendants).");
  static_assert(std::is_base_of<
      ResolvedComputedColumn,
      typename std::decay<decltype(**(computed_columns_list.begin()))>::type>::value,
      "computed_columns_list must be a container of unique_ptr with elements of type "
      "ResolvedComputedColumn (or its descendants).");
  static_assert(std::is_base_of<
      ResolvedUnnestItem,
      typename std::decay<decltype(**(unnest_expressions_list.begin()))>::type>::value,
      "unnest_expressions_list must be a container of unique_ptr with elements of type "
      "ResolvedUnnestItem (or its descendants).");
  return MakeResolvedCreateIndexStmt(
      name_path,
      create_scope,
      create_mode,
      table_name_path,
      std::move(table_scan),
      is_unique,
      {std::make_move_iterator(index_item_list.begin()),
       std::make_move_iterator(index_item_list.end())},
      {std::make_move_iterator(storing_expression_list.begin()),
       std::make_move_iterator(storing_expression_list.end())},
      {std::make_move_iterator(option_list.begin()),
       std::make_move_iterator(option_list.end())},
      {std::make_move_iterator(computed_columns_list.begin()),
       std::make_move_iterator(computed_columns_list.end())},
      {std::make_move_iterator(unnest_expressions_list.begin()),
       std::make_move_iterator(unnest_expressions_list.end())});
}

inline std::unique_ptr<ResolvedCreateIndexStmt> MakeResolvedCreateIndexStmt() {
  return std::unique_ptr<ResolvedCreateIndexStmt>(
      new ResolvedCreateIndexStmt());
}

// This statement:
//   CREATE [TEMP] TABLE <name> (column type, ...)
//   [PARTITION BY expr, ...] [CLUSTER BY expr, ...]
//   [OPTIONS (...)]
//
// <option_list> has engine-specific directives for how and where to
//               materialize this table.
// <column_definition_list> has the names and types of the columns in the
//                          created table. If <is_value_table> is true, it
//                          must contain exactly one column, with a generated
//                          name such as "$struct".
// <pseudo_column_list> is a list of some pseudo-columns expected to be
//                      present on the created table (provided by
//                      AnalyzerOptions::SetDdlPseudoColumns*).  These can be
//                      referenced in expressions in <partition_by_list> and
//                      <cluster_by_list>.
// <primary_key> specifies the PRIMARY KEY constraint on the table, it is
//               nullptr when no PRIMARY KEY is specified.
// <foreign_key_list> specifies the FOREIGN KEY constraints on the table.
// <check_constraint_list> specifies the CHECK constraints on the table.
// <partition_by_list> specifies the partitioning expressions for the table.
// <cluster_by_list> specifies the clustering expressions for the table.
// <is_value_table> specifies whether the table is a value table.
//                  See (broken link).
class ResolvedCreateTableStmtBase  : public ResolvedCreateStatement {
 public:
  typedef ResolvedCreateStatement SUPER;

  // Number of leaf node types that exist as descendants of this abstract type.
  static const int NUM_DESCENDANT_LEAF_TYPES = 2;

  ResolvedCreateTableStmtBase()
      : ResolvedCreateStatement()
      , option_list_()
      , column_definition_list_()
      , pseudo_column_list_()
      , primary_key_()
      , foreign_key_list_()
      , check_constraint_list_()
      , partition_by_list_()
      , cluster_by_list_()
      , is_value_table_()
  {}
 public:

  ResolvedCreateTableStmtBase(const ResolvedCreateTableStmtBase&) = delete;
  ResolvedCreateTableStmtBase& operator=(const ResolvedCreateTableStmtBase&) = delete;

  ~ResolvedCreateTableStmtBase() override;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const override;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const override;

  zetasql_base::Status CheckFieldsAccessed() const override;
  void ClearFieldsAccessed() const override;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedCreateTableStmtBaseProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedCreateStatementProto* proto) const final;

  virtual zetasql_base::Status SaveTo(
      Type::FileDescriptorSetMap* file_descriptor_set_map,
      AnyResolvedCreateTableStmtBaseProto* proto) const = 0;
  static zetasql_base::StatusOr<std::unique_ptr<ResolvedCreateTableStmtBase>> RestoreFrom(
      const AnyResolvedCreateTableStmtBaseProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const override;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) override;

  // Member fields

  const std::vector<std::unique_ptr<const ResolvedOption>>& option_list() const {
    accessed_ |= (1<<0);
    return option_list_;
  }
  int option_list_size() const {
    if (option_list_.empty()) accessed_ |= (1<<0);
    return static_cast<int>(option_list_.size());
  }
  const ResolvedOption* option_list(int i) const {
    accessed_ |= (1<<0);
    return option_list_.at(i).get();
  }
  void add_option_list(std::unique_ptr<const ResolvedOption> v) {
    option_list_.emplace_back(std::move(v));
  }
  void set_option_list(std::vector<std::unique_ptr<const ResolvedOption>> v) {
    option_list_ = std::move(v);
  }

  std::vector<std::unique_ptr<const ResolvedOption>> release_option_list() {
    std::vector<std::unique_ptr<const ResolvedOption>> tmp;
    option_list_.swap(tmp);
    return tmp;
  }

  const std::vector<std::unique_ptr<const ResolvedColumnDefinition>>& column_definition_list() const {
    accessed_ |= (1<<1);
    return column_definition_list_;
  }
  int column_definition_list_size() const {
    if (column_definition_list_.empty()) accessed_ |= (1<<1);
    return static_cast<int>(column_definition_list_.size());
  }
  const ResolvedColumnDefinition* column_definition_list(int i) const {
    accessed_ |= (1<<1);
    return column_definition_list_.at(i).get();
  }
  void add_column_definition_list(std::unique_ptr<const ResolvedColumnDefinition> v) {
    column_definition_list_.emplace_back(std::move(v));
  }
  void set_column_definition_list(std::vector<std::unique_ptr<const ResolvedColumnDefinition>> v) {
    column_definition_list_ = std::move(v);
  }

  std::vector<std::unique_ptr<const ResolvedColumnDefinition>> release_column_definition_list() {
    std::vector<std::unique_ptr<const ResolvedColumnDefinition>> tmp;
    column_definition_list_.swap(tmp);
    return tmp;
  }

  const std::vector<ResolvedColumn>& pseudo_column_list() const {
    accessed_ |= (1<<2);
    return pseudo_column_list_;
  }
  int pseudo_column_list_size() const {
    if (pseudo_column_list_.empty()) accessed_ |= (1<<2);
    return static_cast<int>(pseudo_column_list_.size());
  }
  ResolvedColumn pseudo_column_list(int i) const {
    accessed_ |= (1<<2);
    return pseudo_column_list_.at(i);
  }
  void add_pseudo_column_list(ResolvedColumn v) {
    pseudo_column_list_.push_back(ResolvedColumn(v));
  }
  void set_pseudo_column_list(const std::vector<ResolvedColumn>& v) {
    pseudo_column_list_ = v;
  }
  std::vector<ResolvedColumn>* mutable_pseudo_column_list() {
    accessed_ |= (1<<2);
    return &pseudo_column_list_;
  }

  const ResolvedPrimaryKey* primary_key() const {
    accessed_ |= (1<<3);
    return primary_key_.get();
  }
  void set_primary_key(std::unique_ptr<const ResolvedPrimaryKey> v) {
    primary_key_ = std::move(v);
  }

  std::unique_ptr<const ResolvedPrimaryKey> release_primary_key() {
    return std::move(primary_key_);
  }

  const std::vector<std::unique_ptr<const ResolvedForeignKey>>& foreign_key_list() const {
    accessed_ |= (1<<4);
    return foreign_key_list_;
  }
  int foreign_key_list_size() const {
    if (foreign_key_list_.empty()) accessed_ |= (1<<4);
    return static_cast<int>(foreign_key_list_.size());
  }
  const ResolvedForeignKey* foreign_key_list(int i) const {
    accessed_ |= (1<<4);
    return foreign_key_list_.at(i).get();
  }
  void add_foreign_key_list(std::unique_ptr<const ResolvedForeignKey> v) {
    foreign_key_list_.emplace_back(std::move(v));
  }
  void set_foreign_key_list(std::vector<std::unique_ptr<const ResolvedForeignKey>> v) {
    foreign_key_list_ = std::move(v);
  }

  std::vector<std::unique_ptr<const ResolvedForeignKey>> release_foreign_key_list() {
    std::vector<std::unique_ptr<const ResolvedForeignKey>> tmp;
    foreign_key_list_.swap(tmp);
    return tmp;
  }

  const std::vector<std::unique_ptr<const ResolvedCheckConstraint>>& check_constraint_list() const {
    accessed_ |= (1<<5);
    return check_constraint_list_;
  }
  int check_constraint_list_size() const {
    if (check_constraint_list_.empty()) accessed_ |= (1<<5);
    return static_cast<int>(check_constraint_list_.size());
  }
  const ResolvedCheckConstraint* check_constraint_list(int i) const {
    accessed_ |= (1<<5);
    return check_constraint_list_.at(i).get();
  }
  void add_check_constraint_list(std::unique_ptr<const ResolvedCheckConstraint> v) {
    check_constraint_list_.emplace_back(std::move(v));
  }
  void set_check_constraint_list(std::vector<std::unique_ptr<const ResolvedCheckConstraint>> v) {
    check_constraint_list_ = std::move(v);
  }

  std::vector<std::unique_ptr<const ResolvedCheckConstraint>> release_check_constraint_list() {
    std::vector<std::unique_ptr<const ResolvedCheckConstraint>> tmp;
    check_constraint_list_.swap(tmp);
    return tmp;
  }

  const std::vector<std::unique_ptr<const ResolvedExpr>>& partition_by_list() const {
    accessed_ |= (1<<6);
    return partition_by_list_;
  }
  int partition_by_list_size() const {
    if (partition_by_list_.empty()) accessed_ |= (1<<6);
    return static_cast<int>(partition_by_list_.size());
  }
  const ResolvedExpr* partition_by_list(int i) const {
    accessed_ |= (1<<6);
    return partition_by_list_.at(i).get();
  }
  void add_partition_by_list(std::unique_ptr<const ResolvedExpr> v) {
    partition_by_list_.emplace_back(std::move(v));
  }
  void set_partition_by_list(std::vector<std::unique_ptr<const ResolvedExpr>> v) {
    partition_by_list_ = std::move(v);
  }

  std::vector<std::unique_ptr<const ResolvedExpr>> release_partition_by_list() {
    std::vector<std::unique_ptr<const ResolvedExpr>> tmp;
    partition_by_list_.swap(tmp);
    return tmp;
  }

  const std::vector<std::unique_ptr<const ResolvedExpr>>& cluster_by_list() const {
    accessed_ |= (1<<7);
    return cluster_by_list_;
  }
  int cluster_by_list_size() const {
    if (cluster_by_list_.empty()) accessed_ |= (1<<7);
    return static_cast<int>(cluster_by_list_.size());
  }
  const ResolvedExpr* cluster_by_list(int i) const {
    accessed_ |= (1<<7);
    return cluster_by_list_.at(i).get();
  }
  void add_cluster_by_list(std::unique_ptr<const ResolvedExpr> v) {
    cluster_by_list_.emplace_back(std::move(v));
  }
  void set_cluster_by_list(std::vector<std::unique_ptr<const ResolvedExpr>> v) {
    cluster_by_list_ = std::move(v);
  }

  std::vector<std::unique_ptr<const ResolvedExpr>> release_cluster_by_list() {
    std::vector<std::unique_ptr<const ResolvedExpr>> tmp;
    cluster_by_list_.swap(tmp);
    return tmp;
  }

  bool is_value_table() const {
    accessed_ |= (1<<8);
    return is_value_table_;
  }
  void set_is_value_table(bool v) {
    is_value_table_ = v;
  }

 protected:
  explicit ResolvedCreateTableStmtBase(
      const std::vector<std::string>& name_path,
      CreateScope create_scope,
      CreateMode create_mode,
      std::vector<std::unique_ptr<const ResolvedOption>> option_list,
      std::vector<std::unique_ptr<const ResolvedColumnDefinition>> column_definition_list,
      const std::vector<ResolvedColumn>& pseudo_column_list,
      std::unique_ptr<const ResolvedPrimaryKey> primary_key,
      std::vector<std::unique_ptr<const ResolvedForeignKey>> foreign_key_list,
      std::vector<std::unique_ptr<const ResolvedCheckConstraint>> check_constraint_list,
      std::vector<std::unique_ptr<const ResolvedExpr>> partition_by_list,
      std::vector<std::unique_ptr<const ResolvedExpr>> cluster_by_list,
      bool is_value_table,
      ConstructorOverload)
      : ResolvedCreateStatement(
            name_path,
            create_scope,
            create_mode,
            ConstructorOverload::NEW_CONSTRUCTOR),
      option_list_(std::move(option_list)),
      column_definition_list_(std::move(column_definition_list)),
      pseudo_column_list_(pseudo_column_list),
      primary_key_(std::move(primary_key)),
      foreign_key_list_(std::move(foreign_key_list)),
      check_constraint_list_(std::move(check_constraint_list)),
      partition_by_list_(std::move(partition_by_list)),
      cluster_by_list_(std::move(cluster_by_list)),
      is_value_table_(is_value_table) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const override;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  std::vector<std::unique_ptr<const ResolvedOption>> option_list_;
  std::vector<std::unique_ptr<const ResolvedColumnDefinition>> column_definition_list_;
  std::vector<ResolvedColumn> pseudo_column_list_;
  std::unique_ptr<const ResolvedPrimaryKey> primary_key_;
  std::vector<std::unique_ptr<const ResolvedForeignKey>> foreign_key_list_;
  std::vector<std::unique_ptr<const ResolvedCheckConstraint>> check_constraint_list_;
  std::vector<std::unique_ptr<const ResolvedExpr>> partition_by_list_;
  std::vector<std::unique_ptr<const ResolvedExpr>> cluster_by_list_;
  bool is_value_table_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

// This statement:
// CREATE [TEMP] TABLE <name> (column schema, ...)
// [PARTITION BY expr, ...] [CLUSTER BY expr, ...]
// [OPTIONS (...)]
class ResolvedCreateTableStmt final : public ResolvedCreateTableStmtBase {
 public:
  typedef ResolvedCreateTableStmtBase SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_CREATE_TABLE_STMT;

  friend std::unique_ptr<ResolvedCreateTableStmt> MakeResolvedCreateTableStmt();
 protected:
  ResolvedCreateTableStmt()
      : ResolvedCreateTableStmtBase()
  {}
 public:

  ResolvedCreateTableStmt(const ResolvedCreateTableStmt&) = delete;
  ResolvedCreateTableStmt& operator=(const ResolvedCreateTableStmt&) = delete;

  friend std::unique_ptr<ResolvedCreateTableStmt> MakeResolvedCreateTableStmt(
      const std::vector<std::string>& name_path,
      CreateScope create_scope,
      CreateMode create_mode,
      std::vector<std::unique_ptr<const ResolvedOption>> option_list,
      std::vector<std::unique_ptr<const ResolvedColumnDefinition>> column_definition_list,
      const std::vector<ResolvedColumn>& pseudo_column_list,
      std::unique_ptr<const ResolvedPrimaryKey> primary_key,
      std::vector<std::unique_ptr<const ResolvedForeignKey>> foreign_key_list,
      std::vector<std::unique_ptr<const ResolvedCheckConstraint>> check_constraint_list,
      std::vector<std::unique_ptr<const ResolvedExpr>> partition_by_list,
      std::vector<std::unique_ptr<const ResolvedExpr>> cluster_by_list,
      bool is_value_table
  );
  ~ResolvedCreateTableStmt() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_CREATE_TABLE_STMT; }
  std::string node_kind_string() const final { return "CreateTableStmt"; }

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedCreateTableStmtProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedCreateTableStmtBaseProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedCreateTableStmt>> RestoreFrom(
      const ResolvedCreateTableStmtProto& proto,
      const ResolvedNode::RestoreParams& params);

  // Member fields

 protected:
  explicit ResolvedCreateTableStmt(
      const std::vector<std::string>& name_path,
      CreateScope create_scope,
      CreateMode create_mode,
      std::vector<std::unique_ptr<const ResolvedOption>> option_list,
      std::vector<std::unique_ptr<const ResolvedColumnDefinition>> column_definition_list,
      const std::vector<ResolvedColumn>& pseudo_column_list,
      std::unique_ptr<const ResolvedPrimaryKey> primary_key,
      std::vector<std::unique_ptr<const ResolvedForeignKey>> foreign_key_list,
      std::vector<std::unique_ptr<const ResolvedCheckConstraint>> check_constraint_list,
      std::vector<std::unique_ptr<const ResolvedExpr>> partition_by_list,
      std::vector<std::unique_ptr<const ResolvedExpr>> cluster_by_list,
      bool is_value_table,
      ConstructorOverload)
      : ResolvedCreateTableStmtBase(
            name_path,
            create_scope,
            create_mode,
            std::move(option_list),
            std::move(column_definition_list),
            pseudo_column_list,
            std::move(primary_key),
            std::move(foreign_key_list),
            std::move(check_constraint_list),
            std::move(partition_by_list),
            std::move(cluster_by_list),
            is_value_table,
            ConstructorOverload::NEW_CONSTRUCTOR) {
  }

 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

};

inline std::unique_ptr<ResolvedCreateTableStmt> MakeResolvedCreateTableStmt(
    const std::vector<std::string>& name_path,
    ResolvedCreateStatement::CreateScope create_scope,
    ResolvedCreateStatement::CreateMode create_mode,
    std::vector<std::unique_ptr<const ResolvedOption>> option_list,
    std::vector<std::unique_ptr<const ResolvedColumnDefinition>> column_definition_list,
    const std::vector<ResolvedColumn>& pseudo_column_list,
    std::unique_ptr<const ResolvedPrimaryKey> primary_key,
    std::vector<std::unique_ptr<const ResolvedForeignKey>> foreign_key_list,
    std::vector<std::unique_ptr<const ResolvedCheckConstraint>> check_constraint_list,
    std::vector<std::unique_ptr<const ResolvedExpr>> partition_by_list,
    std::vector<std::unique_ptr<const ResolvedExpr>> cluster_by_list,
    bool is_value_table) {
  return std::unique_ptr<ResolvedCreateTableStmt>(new ResolvedCreateTableStmt(
        name_path,
        create_scope,
        create_mode,
        std::move(option_list),
        std::move(column_definition_list),
        pseudo_column_list,
        std::move(primary_key),
        std::move(foreign_key_list),
        std::move(check_constraint_list),
        std::move(partition_by_list),
        std::move(cluster_by_list),
        is_value_table,
        ResolvedCreateTableStmt::NEW_CONSTRUCTOR));
}

// Overloaded factory method for the construction of ResolvedCreateTableStmt with
// a wider range of inputs for node-vector inputs.  In particular allows:
// 1. unique_ptr element type can be non-const.
// 2. unique_ptr element type can be any descendant of the required type.
// 3. input container can be any object with a `begin()` and `end()`.
//
// Note, initializer lists cannot be used to pass
//  option_list, column_definition_list, foreign_key_list, check_constraint_list, partition_by_list, cluster_by_list
// due to incompatibility with unique_ptr.  Use zetasql::MakeNodeVector
// instead.
template <
  typename option_list_t
      = std::vector<std::unique_ptr<const ResolvedOption>>,
  typename column_definition_list_t
      = std::vector<std::unique_ptr<const ResolvedColumnDefinition>>,
  typename foreign_key_list_t
      = std::vector<std::unique_ptr<const ResolvedForeignKey>>,
  typename check_constraint_list_t
      = std::vector<std::unique_ptr<const ResolvedCheckConstraint>>,
  typename partition_by_list_t
      = std::vector<std::unique_ptr<const ResolvedExpr>>,
  typename cluster_by_list_t
      = std::vector<std::unique_ptr<const ResolvedExpr>>>
std::unique_ptr<ResolvedCreateTableStmt> MakeResolvedCreateTableStmt(
    const std::vector<std::string>& name_path,
    ResolvedCreateStatement::CreateScope create_scope,
    ResolvedCreateStatement::CreateMode create_mode,
    option_list_t option_list,
    column_definition_list_t column_definition_list,
    const std::vector<ResolvedColumn>& pseudo_column_list,
    std::unique_ptr<const ResolvedPrimaryKey> primary_key,
    foreign_key_list_t foreign_key_list,
    check_constraint_list_t check_constraint_list,
    partition_by_list_t partition_by_list,
    cluster_by_list_t cluster_by_list,
    bool is_value_table) {
  static_assert(std::is_base_of<
      ResolvedOption,
      typename std::decay<decltype(**(option_list.begin()))>::type>::value,
      "option_list must be a container of unique_ptr with elements of type "
      "ResolvedOption (or its descendants).");
  static_assert(std::is_base_of<
      ResolvedColumnDefinition,
      typename std::decay<decltype(**(column_definition_list.begin()))>::type>::value,
      "column_definition_list must be a container of unique_ptr with elements of type "
      "ResolvedColumnDefinition (or its descendants).");
  static_assert(std::is_base_of<
      ResolvedForeignKey,
      typename std::decay<decltype(**(foreign_key_list.begin()))>::type>::value,
      "foreign_key_list must be a container of unique_ptr with elements of type "
      "ResolvedForeignKey (or its descendants).");
  static_assert(std::is_base_of<
      ResolvedCheckConstraint,
      typename std::decay<decltype(**(check_constraint_list.begin()))>::type>::value,
      "check_constraint_list must be a container of unique_ptr with elements of type "
      "ResolvedCheckConstraint (or its descendants).");
  static_assert(std::is_base_of<
      ResolvedExpr,
      typename std::decay<decltype(**(partition_by_list.begin()))>::type>::value,
      "partition_by_list must be a container of unique_ptr with elements of type "
      "ResolvedExpr (or its descendants).");
  static_assert(std::is_base_of<
      ResolvedExpr,
      typename std::decay<decltype(**(cluster_by_list.begin()))>::type>::value,
      "cluster_by_list must be a container of unique_ptr with elements of type "
      "ResolvedExpr (or its descendants).");
  return MakeResolvedCreateTableStmt(
      name_path,
      create_scope,
      create_mode,
      {std::make_move_iterator(option_list.begin()),
       std::make_move_iterator(option_list.end())},
      {std::make_move_iterator(column_definition_list.begin()),
       std::make_move_iterator(column_definition_list.end())},
      pseudo_column_list,
      std::move(primary_key),
      {std::make_move_iterator(foreign_key_list.begin()),
       std::make_move_iterator(foreign_key_list.end())},
      {std::make_move_iterator(check_constraint_list.begin()),
       std::make_move_iterator(check_constraint_list.end())},
      {std::make_move_iterator(partition_by_list.begin()),
       std::make_move_iterator(partition_by_list.end())},
      {std::make_move_iterator(cluster_by_list.begin()),
       std::make_move_iterator(cluster_by_list.end())},
      is_value_table);
}

inline std::unique_ptr<ResolvedCreateTableStmt> MakeResolvedCreateTableStmt() {
  return std::unique_ptr<ResolvedCreateTableStmt>(
      new ResolvedCreateTableStmt());
}

// This statement:
//   CREATE [TEMP] TABLE <name> [(column schema, ...)]
//   [PARTITION BY expr, ...] [CLUSTER BY expr, ...] [OPTIONS (...)]
//   AS SELECT ...
//
// The <output_column_list> matches 1:1 with the <column_definition_list> in
// ResolvedCreateTableStmtBase, and maps ResolvedColumns produced by <query>
// into specific columns of the created table.  The output column names and
// types must match the column definition names and types.  If the table is
// a value table, <output_column_list> must have exactly one column, with a
// generated name such as "$struct".
//
// <output_column_list> does not contain all table schema information that
// <column_definition_list> does. For example, NOT NULL annotations, column
// OPTIONS, and primary keys are only available in <column_definition_list>.
// Consumers are encouraged to read from <column_definition_list> rather
// than than <output_column_list> to determine the table schema, if possible.
//
// <query> is the query to run.
class ResolvedCreateTableAsSelectStmt final : public ResolvedCreateTableStmtBase {
 public:
  typedef ResolvedCreateTableStmtBase SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_CREATE_TABLE_AS_SELECT_STMT;

  friend std::unique_ptr<ResolvedCreateTableAsSelectStmt> MakeResolvedCreateTableAsSelectStmt();
 protected:
  ResolvedCreateTableAsSelectStmt()
      : ResolvedCreateTableStmtBase()
      , output_column_list_()
      , query_()
  {}
 public:

  ResolvedCreateTableAsSelectStmt(const ResolvedCreateTableAsSelectStmt&) = delete;
  ResolvedCreateTableAsSelectStmt& operator=(const ResolvedCreateTableAsSelectStmt&) = delete;

  friend std::unique_ptr<ResolvedCreateTableAsSelectStmt> MakeResolvedCreateTableAsSelectStmt(
      const std::vector<std::string>& name_path,
      CreateScope create_scope,
      CreateMode create_mode,
      std::vector<std::unique_ptr<const ResolvedOption>> option_list,
      std::vector<std::unique_ptr<const ResolvedColumnDefinition>> column_definition_list,
      const std::vector<ResolvedColumn>& pseudo_column_list,
      std::unique_ptr<const ResolvedPrimaryKey> primary_key,
      std::vector<std::unique_ptr<const ResolvedForeignKey>> foreign_key_list,
      std::vector<std::unique_ptr<const ResolvedCheckConstraint>> check_constraint_list,
      std::vector<std::unique_ptr<const ResolvedExpr>> partition_by_list,
      std::vector<std::unique_ptr<const ResolvedExpr>> cluster_by_list,
      bool is_value_table,
      std::vector<std::unique_ptr<const ResolvedOutputColumn>> output_column_list,
      std::unique_ptr<const ResolvedScan> query
  );
  ~ResolvedCreateTableAsSelectStmt() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_CREATE_TABLE_AS_SELECT_STMT; }
  std::string node_kind_string() const final { return "CreateTableAsSelectStmt"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedCreateTableAsSelectStmtProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedCreateTableStmtBaseProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedCreateTableAsSelectStmt>> RestoreFrom(
      const ResolvedCreateTableAsSelectStmtProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  const std::vector<std::unique_ptr<const ResolvedOutputColumn>>& output_column_list() const {
    accessed_ |= (1<<0);
    return output_column_list_;
  }
  int output_column_list_size() const {
    if (output_column_list_.empty()) accessed_ |= (1<<0);
    return static_cast<int>(output_column_list_.size());
  }
  const ResolvedOutputColumn* output_column_list(int i) const {
    accessed_ |= (1<<0);
    return output_column_list_.at(i).get();
  }
  void add_output_column_list(std::unique_ptr<const ResolvedOutputColumn> v) {
    output_column_list_.emplace_back(std::move(v));
  }
  void set_output_column_list(std::vector<std::unique_ptr<const ResolvedOutputColumn>> v) {
    output_column_list_ = std::move(v);
  }

  std::vector<std::unique_ptr<const ResolvedOutputColumn>> release_output_column_list() {
    std::vector<std::unique_ptr<const ResolvedOutputColumn>> tmp;
    output_column_list_.swap(tmp);
    return tmp;
  }

  const ResolvedScan* query() const {
    accessed_ |= (1<<1);
    return query_.get();
  }
  void set_query(std::unique_ptr<const ResolvedScan> v) {
    query_ = std::move(v);
  }

  std::unique_ptr<const ResolvedScan> release_query() {
    return std::move(query_);
  }

 protected:
  explicit ResolvedCreateTableAsSelectStmt(
      const std::vector<std::string>& name_path,
      CreateScope create_scope,
      CreateMode create_mode,
      std::vector<std::unique_ptr<const ResolvedOption>> option_list,
      std::vector<std::unique_ptr<const ResolvedColumnDefinition>> column_definition_list,
      const std::vector<ResolvedColumn>& pseudo_column_list,
      std::unique_ptr<const ResolvedPrimaryKey> primary_key,
      std::vector<std::unique_ptr<const ResolvedForeignKey>> foreign_key_list,
      std::vector<std::unique_ptr<const ResolvedCheckConstraint>> check_constraint_list,
      std::vector<std::unique_ptr<const ResolvedExpr>> partition_by_list,
      std::vector<std::unique_ptr<const ResolvedExpr>> cluster_by_list,
      bool is_value_table,
      std::vector<std::unique_ptr<const ResolvedOutputColumn>> output_column_list,
      std::unique_ptr<const ResolvedScan> query,
      ConstructorOverload)
      : ResolvedCreateTableStmtBase(
            name_path,
            create_scope,
            create_mode,
            std::move(option_list),
            std::move(column_definition_list),
            pseudo_column_list,
            std::move(primary_key),
            std::move(foreign_key_list),
            std::move(check_constraint_list),
            std::move(partition_by_list),
            std::move(cluster_by_list),
            is_value_table,
            ConstructorOverload::NEW_CONSTRUCTOR),
      output_column_list_(std::move(output_column_list)),
      query_(std::move(query)) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  std::vector<std::unique_ptr<const ResolvedOutputColumn>> output_column_list_;
  std::unique_ptr<const ResolvedScan> query_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedCreateTableAsSelectStmt> MakeResolvedCreateTableAsSelectStmt(
    const std::vector<std::string>& name_path,
    ResolvedCreateStatement::CreateScope create_scope,
    ResolvedCreateStatement::CreateMode create_mode,
    std::vector<std::unique_ptr<const ResolvedOption>> option_list,
    std::vector<std::unique_ptr<const ResolvedColumnDefinition>> column_definition_list,
    const std::vector<ResolvedColumn>& pseudo_column_list,
    std::unique_ptr<const ResolvedPrimaryKey> primary_key,
    std::vector<std::unique_ptr<const ResolvedForeignKey>> foreign_key_list,
    std::vector<std::unique_ptr<const ResolvedCheckConstraint>> check_constraint_list,
    std::vector<std::unique_ptr<const ResolvedExpr>> partition_by_list,
    std::vector<std::unique_ptr<const ResolvedExpr>> cluster_by_list,
    bool is_value_table,
    std::vector<std::unique_ptr<const ResolvedOutputColumn>> output_column_list,
    std::unique_ptr<const ResolvedScan> query) {
  return std::unique_ptr<ResolvedCreateTableAsSelectStmt>(new ResolvedCreateTableAsSelectStmt(
        name_path,
        create_scope,
        create_mode,
        std::move(option_list),
        std::move(column_definition_list),
        pseudo_column_list,
        std::move(primary_key),
        std::move(foreign_key_list),
        std::move(check_constraint_list),
        std::move(partition_by_list),
        std::move(cluster_by_list),
        is_value_table,
        std::move(output_column_list),
        std::move(query),
        ResolvedCreateTableAsSelectStmt::NEW_CONSTRUCTOR));
}

// Overloaded factory method for the construction of ResolvedCreateTableAsSelectStmt with
// a wider range of inputs for node-vector inputs.  In particular allows:
// 1. unique_ptr element type can be non-const.
// 2. unique_ptr element type can be any descendant of the required type.
// 3. input container can be any object with a `begin()` and `end()`.
//
// Note, initializer lists cannot be used to pass
//  option_list, column_definition_list, foreign_key_list, check_constraint_list, partition_by_list, cluster_by_list, output_column_list
// due to incompatibility with unique_ptr.  Use zetasql::MakeNodeVector
// instead.
template <
  typename option_list_t
      = std::vector<std::unique_ptr<const ResolvedOption>>,
  typename column_definition_list_t
      = std::vector<std::unique_ptr<const ResolvedColumnDefinition>>,
  typename foreign_key_list_t
      = std::vector<std::unique_ptr<const ResolvedForeignKey>>,
  typename check_constraint_list_t
      = std::vector<std::unique_ptr<const ResolvedCheckConstraint>>,
  typename partition_by_list_t
      = std::vector<std::unique_ptr<const ResolvedExpr>>,
  typename cluster_by_list_t
      = std::vector<std::unique_ptr<const ResolvedExpr>>,
  typename output_column_list_t
      = std::vector<std::unique_ptr<const ResolvedOutputColumn>>>
std::unique_ptr<ResolvedCreateTableAsSelectStmt> MakeResolvedCreateTableAsSelectStmt(
    const std::vector<std::string>& name_path,
    ResolvedCreateStatement::CreateScope create_scope,
    ResolvedCreateStatement::CreateMode create_mode,
    option_list_t option_list,
    column_definition_list_t column_definition_list,
    const std::vector<ResolvedColumn>& pseudo_column_list,
    std::unique_ptr<const ResolvedPrimaryKey> primary_key,
    foreign_key_list_t foreign_key_list,
    check_constraint_list_t check_constraint_list,
    partition_by_list_t partition_by_list,
    cluster_by_list_t cluster_by_list,
    bool is_value_table,
    output_column_list_t output_column_list,
    std::unique_ptr<const ResolvedScan> query) {
  static_assert(std::is_base_of<
      ResolvedOption,
      typename std::decay<decltype(**(option_list.begin()))>::type>::value,
      "option_list must be a container of unique_ptr with elements of type "
      "ResolvedOption (or its descendants).");
  static_assert(std::is_base_of<
      ResolvedColumnDefinition,
      typename std::decay<decltype(**(column_definition_list.begin()))>::type>::value,
      "column_definition_list must be a container of unique_ptr with elements of type "
      "ResolvedColumnDefinition (or its descendants).");
  static_assert(std::is_base_of<
      ResolvedForeignKey,
      typename std::decay<decltype(**(foreign_key_list.begin()))>::type>::value,
      "foreign_key_list must be a container of unique_ptr with elements of type "
      "ResolvedForeignKey (or its descendants).");
  static_assert(std::is_base_of<
      ResolvedCheckConstraint,
      typename std::decay<decltype(**(check_constraint_list.begin()))>::type>::value,
      "check_constraint_list must be a container of unique_ptr with elements of type "
      "ResolvedCheckConstraint (or its descendants).");
  static_assert(std::is_base_of<
      ResolvedExpr,
      typename std::decay<decltype(**(partition_by_list.begin()))>::type>::value,
      "partition_by_list must be a container of unique_ptr with elements of type "
      "ResolvedExpr (or its descendants).");
  static_assert(std::is_base_of<
      ResolvedExpr,
      typename std::decay<decltype(**(cluster_by_list.begin()))>::type>::value,
      "cluster_by_list must be a container of unique_ptr with elements of type "
      "ResolvedExpr (or its descendants).");
  static_assert(std::is_base_of<
      ResolvedOutputColumn,
      typename std::decay<decltype(**(output_column_list.begin()))>::type>::value,
      "output_column_list must be a container of unique_ptr with elements of type "
      "ResolvedOutputColumn (or its descendants).");
  return MakeResolvedCreateTableAsSelectStmt(
      name_path,
      create_scope,
      create_mode,
      {std::make_move_iterator(option_list.begin()),
       std::make_move_iterator(option_list.end())},
      {std::make_move_iterator(column_definition_list.begin()),
       std::make_move_iterator(column_definition_list.end())},
      pseudo_column_list,
      std::move(primary_key),
      {std::make_move_iterator(foreign_key_list.begin()),
       std::make_move_iterator(foreign_key_list.end())},
      {std::make_move_iterator(check_constraint_list.begin()),
       std::make_move_iterator(check_constraint_list.end())},
      {std::make_move_iterator(partition_by_list.begin()),
       std::make_move_iterator(partition_by_list.end())},
      {std::make_move_iterator(cluster_by_list.begin()),
       std::make_move_iterator(cluster_by_list.end())},
      is_value_table,
      {std::make_move_iterator(output_column_list.begin()),
       std::make_move_iterator(output_column_list.end())},
      std::move(query));
}

inline std::unique_ptr<ResolvedCreateTableAsSelectStmt> MakeResolvedCreateTableAsSelectStmt() {
  return std::unique_ptr<ResolvedCreateTableAsSelectStmt>(
      new ResolvedCreateTableAsSelectStmt());
}

// This statement:
//   CREATE [TEMP] MODEL <name> [TRANSFORM(...)] [OPTIONS (...)] AS SELECT ..
//
// <option_list> has engine-specific directives for how to train this model.
// <output_column_list> matches 1:1 with the <query>'s column_list, and
//                      identifies the names and types of the columns output
//                      from the select statement.
// <query> is the select statement.
// <transform_list> is the list of ResolvedComputedColumn in TRANSFORM
//   clause.
// <transform_output_column_list> matches 1:1 with <transform_list> output.
class ResolvedCreateModelStmt final : public ResolvedCreateStatement {
 public:
  typedef ResolvedCreateStatement SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_CREATE_MODEL_STMT;

  friend std::unique_ptr<ResolvedCreateModelStmt> MakeResolvedCreateModelStmt();
 protected:
  ResolvedCreateModelStmt()
      : ResolvedCreateStatement()
      , option_list_()
      , output_column_list_()
      , query_()
      , transform_list_()
      , transform_output_column_list_()
  {}
 public:

  ResolvedCreateModelStmt(const ResolvedCreateModelStmt&) = delete;
  ResolvedCreateModelStmt& operator=(const ResolvedCreateModelStmt&) = delete;

  friend std::unique_ptr<ResolvedCreateModelStmt> MakeResolvedCreateModelStmt(
      const std::vector<std::string>& name_path,
      CreateScope create_scope,
      CreateMode create_mode,
      std::vector<std::unique_ptr<const ResolvedOption>> option_list,
      std::vector<std::unique_ptr<const ResolvedOutputColumn>> output_column_list,
      std::unique_ptr<const ResolvedScan> query,
      std::vector<std::unique_ptr<const ResolvedComputedColumn>> transform_list,
      std::vector<std::unique_ptr<const ResolvedOutputColumn>> transform_output_column_list
  );
  ~ResolvedCreateModelStmt() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_CREATE_MODEL_STMT; }
  std::string node_kind_string() const final { return "CreateModelStmt"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedCreateModelStmtProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedCreateStatementProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedCreateModelStmt>> RestoreFrom(
      const ResolvedCreateModelStmtProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  const std::vector<std::unique_ptr<const ResolvedOption>>& option_list() const {
    accessed_ |= (1<<0);
    return option_list_;
  }
  int option_list_size() const {
    if (option_list_.empty()) accessed_ |= (1<<0);
    return static_cast<int>(option_list_.size());
  }
  const ResolvedOption* option_list(int i) const {
    accessed_ |= (1<<0);
    return option_list_.at(i).get();
  }
  void add_option_list(std::unique_ptr<const ResolvedOption> v) {
    option_list_.emplace_back(std::move(v));
  }
  void set_option_list(std::vector<std::unique_ptr<const ResolvedOption>> v) {
    option_list_ = std::move(v);
  }

  std::vector<std::unique_ptr<const ResolvedOption>> release_option_list() {
    std::vector<std::unique_ptr<const ResolvedOption>> tmp;
    option_list_.swap(tmp);
    return tmp;
  }

  const std::vector<std::unique_ptr<const ResolvedOutputColumn>>& output_column_list() const {
    accessed_ |= (1<<1);
    return output_column_list_;
  }
  int output_column_list_size() const {
    if (output_column_list_.empty()) accessed_ |= (1<<1);
    return static_cast<int>(output_column_list_.size());
  }
  const ResolvedOutputColumn* output_column_list(int i) const {
    accessed_ |= (1<<1);
    return output_column_list_.at(i).get();
  }
  void add_output_column_list(std::unique_ptr<const ResolvedOutputColumn> v) {
    output_column_list_.emplace_back(std::move(v));
  }
  void set_output_column_list(std::vector<std::unique_ptr<const ResolvedOutputColumn>> v) {
    output_column_list_ = std::move(v);
  }

  std::vector<std::unique_ptr<const ResolvedOutputColumn>> release_output_column_list() {
    std::vector<std::unique_ptr<const ResolvedOutputColumn>> tmp;
    output_column_list_.swap(tmp);
    return tmp;
  }

  const ResolvedScan* query() const {
    accessed_ |= (1<<2);
    return query_.get();
  }
  void set_query(std::unique_ptr<const ResolvedScan> v) {
    query_ = std::move(v);
  }

  std::unique_ptr<const ResolvedScan> release_query() {
    return std::move(query_);
  }

  const std::vector<std::unique_ptr<const ResolvedComputedColumn>>& transform_list() const {
    accessed_ |= (1<<3);
    return transform_list_;
  }
  int transform_list_size() const {
    if (transform_list_.empty()) accessed_ |= (1<<3);
    return static_cast<int>(transform_list_.size());
  }
  const ResolvedComputedColumn* transform_list(int i) const {
    accessed_ |= (1<<3);
    return transform_list_.at(i).get();
  }
  void add_transform_list(std::unique_ptr<const ResolvedComputedColumn> v) {
    transform_list_.emplace_back(std::move(v));
  }
  void set_transform_list(std::vector<std::unique_ptr<const ResolvedComputedColumn>> v) {
    transform_list_ = std::move(v);
  }

  std::vector<std::unique_ptr<const ResolvedComputedColumn>> release_transform_list() {
    std::vector<std::unique_ptr<const ResolvedComputedColumn>> tmp;
    transform_list_.swap(tmp);
    return tmp;
  }

  const std::vector<std::unique_ptr<const ResolvedOutputColumn>>& transform_output_column_list() const {
    accessed_ |= (1<<4);
    return transform_output_column_list_;
  }
  int transform_output_column_list_size() const {
    if (transform_output_column_list_.empty()) accessed_ |= (1<<4);
    return static_cast<int>(transform_output_column_list_.size());
  }
  const ResolvedOutputColumn* transform_output_column_list(int i) const {
    accessed_ |= (1<<4);
    return transform_output_column_list_.at(i).get();
  }
  void add_transform_output_column_list(std::unique_ptr<const ResolvedOutputColumn> v) {
    transform_output_column_list_.emplace_back(std::move(v));
  }
  void set_transform_output_column_list(std::vector<std::unique_ptr<const ResolvedOutputColumn>> v) {
    transform_output_column_list_ = std::move(v);
  }

  std::vector<std::unique_ptr<const ResolvedOutputColumn>> release_transform_output_column_list() {
    std::vector<std::unique_ptr<const ResolvedOutputColumn>> tmp;
    transform_output_column_list_.swap(tmp);
    return tmp;
  }

 protected:
  explicit ResolvedCreateModelStmt(
      const std::vector<std::string>& name_path,
      CreateScope create_scope,
      CreateMode create_mode,
      std::vector<std::unique_ptr<const ResolvedOption>> option_list,
      std::vector<std::unique_ptr<const ResolvedOutputColumn>> output_column_list,
      std::unique_ptr<const ResolvedScan> query,
      std::vector<std::unique_ptr<const ResolvedComputedColumn>> transform_list,
      std::vector<std::unique_ptr<const ResolvedOutputColumn>> transform_output_column_list,
      ConstructorOverload)
      : ResolvedCreateStatement(
            name_path,
            create_scope,
            create_mode,
            ConstructorOverload::NEW_CONSTRUCTOR),
      option_list_(std::move(option_list)),
      output_column_list_(std::move(output_column_list)),
      query_(std::move(query)),
      transform_list_(std::move(transform_list)),
      transform_output_column_list_(std::move(transform_output_column_list)) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  std::vector<std::unique_ptr<const ResolvedOption>> option_list_;
  std::vector<std::unique_ptr<const ResolvedOutputColumn>> output_column_list_;
  std::unique_ptr<const ResolvedScan> query_;
  std::vector<std::unique_ptr<const ResolvedComputedColumn>> transform_list_;
  std::vector<std::unique_ptr<const ResolvedOutputColumn>> transform_output_column_list_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedCreateModelStmt> MakeResolvedCreateModelStmt(
    const std::vector<std::string>& name_path,
    ResolvedCreateStatement::CreateScope create_scope,
    ResolvedCreateStatement::CreateMode create_mode,
    std::vector<std::unique_ptr<const ResolvedOption>> option_list,
    std::vector<std::unique_ptr<const ResolvedOutputColumn>> output_column_list,
    std::unique_ptr<const ResolvedScan> query,
    std::vector<std::unique_ptr<const ResolvedComputedColumn>> transform_list,
    std::vector<std::unique_ptr<const ResolvedOutputColumn>> transform_output_column_list) {
  return std::unique_ptr<ResolvedCreateModelStmt>(new ResolvedCreateModelStmt(
        name_path,
        create_scope,
        create_mode,
        std::move(option_list),
        std::move(output_column_list),
        std::move(query),
        std::move(transform_list),
        std::move(transform_output_column_list),
        ResolvedCreateModelStmt::NEW_CONSTRUCTOR));
}

// Overloaded factory method for the construction of ResolvedCreateModelStmt with
// a wider range of inputs for node-vector inputs.  In particular allows:
// 1. unique_ptr element type can be non-const.
// 2. unique_ptr element type can be any descendant of the required type.
// 3. input container can be any object with a `begin()` and `end()`.
//
// Note, initializer lists cannot be used to pass
//  option_list, output_column_list, transform_list, transform_output_column_list
// due to incompatibility with unique_ptr.  Use zetasql::MakeNodeVector
// instead.
template <
  typename option_list_t
      = std::vector<std::unique_ptr<const ResolvedOption>>,
  typename output_column_list_t
      = std::vector<std::unique_ptr<const ResolvedOutputColumn>>,
  typename transform_list_t
      = std::vector<std::unique_ptr<const ResolvedComputedColumn>>,
  typename transform_output_column_list_t
      = std::vector<std::unique_ptr<const ResolvedOutputColumn>>>
std::unique_ptr<ResolvedCreateModelStmt> MakeResolvedCreateModelStmt(
    const std::vector<std::string>& name_path,
    ResolvedCreateStatement::CreateScope create_scope,
    ResolvedCreateStatement::CreateMode create_mode,
    option_list_t option_list,
    output_column_list_t output_column_list,
    std::unique_ptr<const ResolvedScan> query,
    transform_list_t transform_list,
    transform_output_column_list_t transform_output_column_list) {
  static_assert(std::is_base_of<
      ResolvedOption,
      typename std::decay<decltype(**(option_list.begin()))>::type>::value,
      "option_list must be a container of unique_ptr with elements of type "
      "ResolvedOption (or its descendants).");
  static_assert(std::is_base_of<
      ResolvedOutputColumn,
      typename std::decay<decltype(**(output_column_list.begin()))>::type>::value,
      "output_column_list must be a container of unique_ptr with elements of type "
      "ResolvedOutputColumn (or its descendants).");
  static_assert(std::is_base_of<
      ResolvedComputedColumn,
      typename std::decay<decltype(**(transform_list.begin()))>::type>::value,
      "transform_list must be a container of unique_ptr with elements of type "
      "ResolvedComputedColumn (or its descendants).");
  static_assert(std::is_base_of<
      ResolvedOutputColumn,
      typename std::decay<decltype(**(transform_output_column_list.begin()))>::type>::value,
      "transform_output_column_list must be a container of unique_ptr with elements of type "
      "ResolvedOutputColumn (or its descendants).");
  return MakeResolvedCreateModelStmt(
      name_path,
      create_scope,
      create_mode,
      {std::make_move_iterator(option_list.begin()),
       std::make_move_iterator(option_list.end())},
      {std::make_move_iterator(output_column_list.begin()),
       std::make_move_iterator(output_column_list.end())},
      std::move(query),
      {std::make_move_iterator(transform_list.begin()),
       std::make_move_iterator(transform_list.end())},
      {std::make_move_iterator(transform_output_column_list.begin()),
       std::make_move_iterator(transform_output_column_list.end())});
}

inline std::unique_ptr<ResolvedCreateModelStmt> MakeResolvedCreateModelStmt() {
  return std::unique_ptr<ResolvedCreateModelStmt>(
      new ResolvedCreateModelStmt());
}

// Common superclass for CREATE view/materialized view:
//   CREATE [TEMP|MATERIALIZED] VIEW <name> [OPTIONS (...)] AS SELECT ...
//
// <option_list> has engine-specific directives for options attached to
//               this view.
// <output_column_list> has the names and types of the columns in the
//                      created view, and maps from <query>'s column_list
//                      to these output columns.
// <query> is the query to run.
// <sql> is the view query text.
// <sql_security> is the declared security mode for the function. Values
//        include 'INVOKER', 'DEFINER'.
//
// Note that <query> and <sql> are both marked as IGNORABLE because
// an engine could look at either one (but might not look at both).
// An engine must look at one (and cannot ignore both) to be
// semantically valid, but there is currently no way to enforce that.
//
// The view must produce named columns with unique names.
class ResolvedCreateViewBase  : public ResolvedCreateStatement {
 public:
  typedef ResolvedCreateStatement SUPER;

  // Number of leaf node types that exist as descendants of this abstract type.
  static const int NUM_DESCENDANT_LEAF_TYPES = 2;

  ResolvedCreateViewBase()
      : ResolvedCreateStatement()
      , option_list_()
      , output_column_list_()
      , query_()
      , sql_()
      , sql_security_()
      , is_value_table_()
  {}
 public:

  ResolvedCreateViewBase(const ResolvedCreateViewBase&) = delete;
  ResolvedCreateViewBase& operator=(const ResolvedCreateViewBase&) = delete;

  ~ResolvedCreateViewBase() override;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const override;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const override;

  zetasql_base::Status CheckFieldsAccessed() const override;
  void ClearFieldsAccessed() const override;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedCreateViewBaseProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedCreateStatementProto* proto) const final;

  virtual zetasql_base::Status SaveTo(
      Type::FileDescriptorSetMap* file_descriptor_set_map,
      AnyResolvedCreateViewBaseProto* proto) const = 0;
  static zetasql_base::StatusOr<std::unique_ptr<ResolvedCreateViewBase>> RestoreFrom(
      const AnyResolvedCreateViewBaseProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const override;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) override;

  // Member fields

  const std::vector<std::unique_ptr<const ResolvedOption>>& option_list() const {
    accessed_ |= (1<<0);
    return option_list_;
  }
  int option_list_size() const {
    if (option_list_.empty()) accessed_ |= (1<<0);
    return static_cast<int>(option_list_.size());
  }
  const ResolvedOption* option_list(int i) const {
    accessed_ |= (1<<0);
    return option_list_.at(i).get();
  }
  void add_option_list(std::unique_ptr<const ResolvedOption> v) {
    option_list_.emplace_back(std::move(v));
  }
  void set_option_list(std::vector<std::unique_ptr<const ResolvedOption>> v) {
    option_list_ = std::move(v);
  }

  std::vector<std::unique_ptr<const ResolvedOption>> release_option_list() {
    std::vector<std::unique_ptr<const ResolvedOption>> tmp;
    option_list_.swap(tmp);
    return tmp;
  }

  const std::vector<std::unique_ptr<const ResolvedOutputColumn>>& output_column_list() const {
    accessed_ |= (1<<1);
    return output_column_list_;
  }
  int output_column_list_size() const {
    if (output_column_list_.empty()) accessed_ |= (1<<1);
    return static_cast<int>(output_column_list_.size());
  }
  const ResolvedOutputColumn* output_column_list(int i) const {
    accessed_ |= (1<<1);
    return output_column_list_.at(i).get();
  }
  void add_output_column_list(std::unique_ptr<const ResolvedOutputColumn> v) {
    output_column_list_.emplace_back(std::move(v));
  }
  void set_output_column_list(std::vector<std::unique_ptr<const ResolvedOutputColumn>> v) {
    output_column_list_ = std::move(v);
  }

  std::vector<std::unique_ptr<const ResolvedOutputColumn>> release_output_column_list() {
    std::vector<std::unique_ptr<const ResolvedOutputColumn>> tmp;
    output_column_list_.swap(tmp);
    return tmp;
  }

  const ResolvedScan* query() const {
    accessed_ |= (1<<2);
    return query_.get();
  }
  void set_query(std::unique_ptr<const ResolvedScan> v) {
    query_ = std::move(v);
  }

  std::unique_ptr<const ResolvedScan> release_query() {
    return std::move(query_);
  }

  const std::string& sql() const {
    accessed_ |= (1<<3);
    return sql_;
  }
  void set_sql(const std::string& v) {
    sql_ = v;
  }

  SqlSecurity sql_security() const {
    accessed_ |= (1<<4);
    return sql_security_;
  }
  void set_sql_security(SqlSecurity v) {
    sql_security_ = v;
  }

  // If true, this view produces a value table. Rather than producing
  // rows with named columns, it produces rows with a single unnamed
  // value type.  output_column_list will have exactly one column, with
  // an empty name. See (broken link).
  bool is_value_table() const {
    accessed_ |= (1<<5);
    return is_value_table_;
  }
  void set_is_value_table(bool v) {
    is_value_table_ = v;
  }

 protected:
  explicit ResolvedCreateViewBase(
      const std::vector<std::string>& name_path,
      CreateScope create_scope,
      CreateMode create_mode,
      std::vector<std::unique_ptr<const ResolvedOption>> option_list,
      std::vector<std::unique_ptr<const ResolvedOutputColumn>> output_column_list,
      std::unique_ptr<const ResolvedScan> query,
      const std::string& sql,
      SqlSecurity sql_security,
      bool is_value_table,
      ConstructorOverload)
      : ResolvedCreateStatement(
            name_path,
            create_scope,
            create_mode,
            ConstructorOverload::NEW_CONSTRUCTOR),
      option_list_(std::move(option_list)),
      output_column_list_(std::move(output_column_list)),
      query_(std::move(query)),
      sql_(sql),
      sql_security_(sql_security),
      is_value_table_(is_value_table) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const override;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  std::vector<std::unique_ptr<const ResolvedOption>> option_list_;
  std::vector<std::unique_ptr<const ResolvedOutputColumn>> output_column_list_;
  std::unique_ptr<const ResolvedScan> query_;
  std::string sql_;
  SqlSecurity sql_security_;
  bool is_value_table_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

// This statement:
// CREATE [TEMP] VIEW <name> [OPTIONS (...)] AS SELECT ...
class ResolvedCreateViewStmt final : public ResolvedCreateViewBase {
 public:
  typedef ResolvedCreateViewBase SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_CREATE_VIEW_STMT;

  friend std::unique_ptr<ResolvedCreateViewStmt> MakeResolvedCreateViewStmt();
 protected:
  ResolvedCreateViewStmt()
      : ResolvedCreateViewBase()
  {}
 public:

  ResolvedCreateViewStmt(const ResolvedCreateViewStmt&) = delete;
  ResolvedCreateViewStmt& operator=(const ResolvedCreateViewStmt&) = delete;

  friend std::unique_ptr<ResolvedCreateViewStmt> MakeResolvedCreateViewStmt(
      const std::vector<std::string>& name_path,
      CreateScope create_scope,
      CreateMode create_mode,
      std::vector<std::unique_ptr<const ResolvedOption>> option_list,
      std::vector<std::unique_ptr<const ResolvedOutputColumn>> output_column_list,
      std::unique_ptr<const ResolvedScan> query,
      const std::string& sql,
      SqlSecurity sql_security,
      bool is_value_table
  );
  ~ResolvedCreateViewStmt() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_CREATE_VIEW_STMT; }
  std::string node_kind_string() const final { return "CreateViewStmt"; }

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedCreateViewStmtProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedCreateViewBaseProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedCreateViewStmt>> RestoreFrom(
      const ResolvedCreateViewStmtProto& proto,
      const ResolvedNode::RestoreParams& params);

  // Member fields

 protected:
  explicit ResolvedCreateViewStmt(
      const std::vector<std::string>& name_path,
      CreateScope create_scope,
      CreateMode create_mode,
      std::vector<std::unique_ptr<const ResolvedOption>> option_list,
      std::vector<std::unique_ptr<const ResolvedOutputColumn>> output_column_list,
      std::unique_ptr<const ResolvedScan> query,
      const std::string& sql,
      SqlSecurity sql_security,
      bool is_value_table,
      ConstructorOverload)
      : ResolvedCreateViewBase(
            name_path,
            create_scope,
            create_mode,
            std::move(option_list),
            std::move(output_column_list),
            std::move(query),
            sql,
            sql_security,
            is_value_table,
            ConstructorOverload::NEW_CONSTRUCTOR) {
  }

 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

};

inline std::unique_ptr<ResolvedCreateViewStmt> MakeResolvedCreateViewStmt(
    const std::vector<std::string>& name_path,
    ResolvedCreateStatement::CreateScope create_scope,
    ResolvedCreateStatement::CreateMode create_mode,
    std::vector<std::unique_ptr<const ResolvedOption>> option_list,
    std::vector<std::unique_ptr<const ResolvedOutputColumn>> output_column_list,
    std::unique_ptr<const ResolvedScan> query,
    const std::string& sql,
    ResolvedCreateStatement::SqlSecurity sql_security,
    bool is_value_table) {
  return std::unique_ptr<ResolvedCreateViewStmt>(new ResolvedCreateViewStmt(
        name_path,
        create_scope,
        create_mode,
        std::move(option_list),
        std::move(output_column_list),
        std::move(query),
        sql,
        sql_security,
        is_value_table,
        ResolvedCreateViewStmt::NEW_CONSTRUCTOR));
}

// Overloaded factory method for the construction of ResolvedCreateViewStmt with
// a wider range of inputs for node-vector inputs.  In particular allows:
// 1. unique_ptr element type can be non-const.
// 2. unique_ptr element type can be any descendant of the required type.
// 3. input container can be any object with a `begin()` and `end()`.
//
// Note, initializer lists cannot be used to pass
//  option_list, output_column_list
// due to incompatibility with unique_ptr.  Use zetasql::MakeNodeVector
// instead.
template <
  typename option_list_t
      = std::vector<std::unique_ptr<const ResolvedOption>>,
  typename output_column_list_t
      = std::vector<std::unique_ptr<const ResolvedOutputColumn>>>
std::unique_ptr<ResolvedCreateViewStmt> MakeResolvedCreateViewStmt(
    const std::vector<std::string>& name_path,
    ResolvedCreateStatement::CreateScope create_scope,
    ResolvedCreateStatement::CreateMode create_mode,
    option_list_t option_list,
    output_column_list_t output_column_list,
    std::unique_ptr<const ResolvedScan> query,
    const std::string& sql,
    ResolvedCreateStatement::SqlSecurity sql_security,
    bool is_value_table) {
  static_assert(std::is_base_of<
      ResolvedOption,
      typename std::decay<decltype(**(option_list.begin()))>::type>::value,
      "option_list must be a container of unique_ptr with elements of type "
      "ResolvedOption (or its descendants).");
  static_assert(std::is_base_of<
      ResolvedOutputColumn,
      typename std::decay<decltype(**(output_column_list.begin()))>::type>::value,
      "output_column_list must be a container of unique_ptr with elements of type "
      "ResolvedOutputColumn (or its descendants).");
  return MakeResolvedCreateViewStmt(
      name_path,
      create_scope,
      create_mode,
      {std::make_move_iterator(option_list.begin()),
       std::make_move_iterator(option_list.end())},
      {std::make_move_iterator(output_column_list.begin()),
       std::make_move_iterator(output_column_list.end())},
      std::move(query),
      sql,
      sql_security,
      is_value_table);
}

inline std::unique_ptr<ResolvedCreateViewStmt> MakeResolvedCreateViewStmt() {
  return std::unique_ptr<ResolvedCreateViewStmt>(
      new ResolvedCreateViewStmt());
}

// This statement:
//   CREATE [TEMP] EXTERNAL TABLE <name> OPTIONS (...)
//
// <option_list> has engine-specific directives that specify how to
//               produce data for this external table.
class ResolvedCreateExternalTableStmt final : public ResolvedCreateStatement {
 public:
  typedef ResolvedCreateStatement SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_CREATE_EXTERNAL_TABLE_STMT;

  friend std::unique_ptr<ResolvedCreateExternalTableStmt> MakeResolvedCreateExternalTableStmt();
 protected:
  ResolvedCreateExternalTableStmt()
      : ResolvedCreateStatement()
      , option_list_()
  {}
 public:

  ResolvedCreateExternalTableStmt(const ResolvedCreateExternalTableStmt&) = delete;
  ResolvedCreateExternalTableStmt& operator=(const ResolvedCreateExternalTableStmt&) = delete;

  friend std::unique_ptr<ResolvedCreateExternalTableStmt> MakeResolvedCreateExternalTableStmt(
      const std::vector<std::string>& name_path,
      CreateScope create_scope,
      CreateMode create_mode,
      std::vector<std::unique_ptr<const ResolvedOption>> option_list
  );
  ~ResolvedCreateExternalTableStmt() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_CREATE_EXTERNAL_TABLE_STMT; }
  std::string node_kind_string() const final { return "CreateExternalTableStmt"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedCreateExternalTableStmtProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedCreateStatementProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedCreateExternalTableStmt>> RestoreFrom(
      const ResolvedCreateExternalTableStmtProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  const std::vector<std::unique_ptr<const ResolvedOption>>& option_list() const {
    accessed_ |= (1<<0);
    return option_list_;
  }
  int option_list_size() const {
    if (option_list_.empty()) accessed_ |= (1<<0);
    return static_cast<int>(option_list_.size());
  }
  const ResolvedOption* option_list(int i) const {
    accessed_ |= (1<<0);
    return option_list_.at(i).get();
  }
  void add_option_list(std::unique_ptr<const ResolvedOption> v) {
    option_list_.emplace_back(std::move(v));
  }
  void set_option_list(std::vector<std::unique_ptr<const ResolvedOption>> v) {
    option_list_ = std::move(v);
  }

  std::vector<std::unique_ptr<const ResolvedOption>> release_option_list() {
    std::vector<std::unique_ptr<const ResolvedOption>> tmp;
    option_list_.swap(tmp);
    return tmp;
  }

 protected:
  explicit ResolvedCreateExternalTableStmt(
      const std::vector<std::string>& name_path,
      CreateScope create_scope,
      CreateMode create_mode,
      std::vector<std::unique_ptr<const ResolvedOption>> option_list,
      ConstructorOverload)
      : ResolvedCreateStatement(
            name_path,
            create_scope,
            create_mode,
            ConstructorOverload::NEW_CONSTRUCTOR),
      option_list_(std::move(option_list)) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  std::vector<std::unique_ptr<const ResolvedOption>> option_list_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedCreateExternalTableStmt> MakeResolvedCreateExternalTableStmt(
    const std::vector<std::string>& name_path,
    ResolvedCreateStatement::CreateScope create_scope,
    ResolvedCreateStatement::CreateMode create_mode,
    std::vector<std::unique_ptr<const ResolvedOption>> option_list) {
  return std::unique_ptr<ResolvedCreateExternalTableStmt>(new ResolvedCreateExternalTableStmt(
        name_path,
        create_scope,
        create_mode,
        std::move(option_list),
        ResolvedCreateExternalTableStmt::NEW_CONSTRUCTOR));
}

// Overloaded factory method for the construction of ResolvedCreateExternalTableStmt with
// a wider range of inputs for node-vector inputs.  In particular allows:
// 1. unique_ptr element type can be non-const.
// 2. unique_ptr element type can be any descendant of the required type.
// 3. input container can be any object with a `begin()` and `end()`.
//
// Note, initializer lists cannot be used to pass
//  option_list
// due to incompatibility with unique_ptr.  Use zetasql::MakeNodeVector
// instead.
template <
  typename option_list_t
      = std::vector<std::unique_ptr<const ResolvedOption>>>
std::unique_ptr<ResolvedCreateExternalTableStmt> MakeResolvedCreateExternalTableStmt(
    const std::vector<std::string>& name_path,
    ResolvedCreateStatement::CreateScope create_scope,
    ResolvedCreateStatement::CreateMode create_mode,
    option_list_t option_list) {
  static_assert(std::is_base_of<
      ResolvedOption,
      typename std::decay<decltype(**(option_list.begin()))>::type>::value,
      "option_list must be a container of unique_ptr with elements of type "
      "ResolvedOption (or its descendants).");
  return MakeResolvedCreateExternalTableStmt(
      name_path,
      create_scope,
      create_mode,
      {std::make_move_iterator(option_list.begin()),
       std::make_move_iterator(option_list.end())});
}

inline std::unique_ptr<ResolvedCreateExternalTableStmt> MakeResolvedCreateExternalTableStmt() {
  return std::unique_ptr<ResolvedCreateExternalTableStmt>(
      new ResolvedCreateExternalTableStmt());
}

// This statement:
//   EXPORT DATA (<option_list>) AS SELECT ...
// which is used to run a query and export its result somewhere
// without giving the result a table name.
//
// <option_list> has engine-specific directives for how and where to
//               materialize the query result.
// <output_column_list> has the names and types of the columns produced by
//                      the query, and maps from <query>'s column_list
//                      to these output columns.  The engine may ignore
//                      the column names depending on the output format.
// <query> is the query to run.
//
// The query must produce named columns with unique names.
class ResolvedExportDataStmt final : public ResolvedStatement {
 public:
  typedef ResolvedStatement SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_EXPORT_DATA_STMT;

  friend std::unique_ptr<ResolvedExportDataStmt> MakeResolvedExportDataStmt();
 protected:
  ResolvedExportDataStmt()
      : ResolvedStatement()
      , option_list_()
      , output_column_list_()
      , is_value_table_()
      , query_()
  {}
 public:

  ResolvedExportDataStmt(const ResolvedExportDataStmt&) = delete;
  ResolvedExportDataStmt& operator=(const ResolvedExportDataStmt&) = delete;

  friend std::unique_ptr<ResolvedExportDataStmt> MakeResolvedExportDataStmt(
      std::vector<std::unique_ptr<const ResolvedOption>> option_list,
      std::vector<std::unique_ptr<const ResolvedOutputColumn>> output_column_list,
      bool is_value_table,
      std::unique_ptr<const ResolvedScan> query
  );
  ~ResolvedExportDataStmt() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_EXPORT_DATA_STMT; }
  std::string node_kind_string() const final { return "ExportDataStmt"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedExportDataStmtProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedStatementProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedExportDataStmt>> RestoreFrom(
      const ResolvedExportDataStmtProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  const std::vector<std::unique_ptr<const ResolvedOption>>& option_list() const {
    accessed_ |= (1<<0);
    return option_list_;
  }
  int option_list_size() const {
    if (option_list_.empty()) accessed_ |= (1<<0);
    return static_cast<int>(option_list_.size());
  }
  const ResolvedOption* option_list(int i) const {
    accessed_ |= (1<<0);
    return option_list_.at(i).get();
  }
  void add_option_list(std::unique_ptr<const ResolvedOption> v) {
    option_list_.emplace_back(std::move(v));
  }
  void set_option_list(std::vector<std::unique_ptr<const ResolvedOption>> v) {
    option_list_ = std::move(v);
  }

  std::vector<std::unique_ptr<const ResolvedOption>> release_option_list() {
    std::vector<std::unique_ptr<const ResolvedOption>> tmp;
    option_list_.swap(tmp);
    return tmp;
  }

  const std::vector<std::unique_ptr<const ResolvedOutputColumn>>& output_column_list() const {
    accessed_ |= (1<<1);
    return output_column_list_;
  }
  int output_column_list_size() const {
    if (output_column_list_.empty()) accessed_ |= (1<<1);
    return static_cast<int>(output_column_list_.size());
  }
  const ResolvedOutputColumn* output_column_list(int i) const {
    accessed_ |= (1<<1);
    return output_column_list_.at(i).get();
  }
  void add_output_column_list(std::unique_ptr<const ResolvedOutputColumn> v) {
    output_column_list_.emplace_back(std::move(v));
  }
  void set_output_column_list(std::vector<std::unique_ptr<const ResolvedOutputColumn>> v) {
    output_column_list_ = std::move(v);
  }

  std::vector<std::unique_ptr<const ResolvedOutputColumn>> release_output_column_list() {
    std::vector<std::unique_ptr<const ResolvedOutputColumn>> tmp;
    output_column_list_.swap(tmp);
    return tmp;
  }

  // If true, the result of this query is a value table. Rather than
  // producing rows with named columns, it produces rows with a single
  // unnamed value type.  output_column_list will have exactly one
  // column, with an empty name. See (broken link).
  bool is_value_table() const {
    accessed_ |= (1<<2);
    return is_value_table_;
  }
  void set_is_value_table(bool v) {
    is_value_table_ = v;
  }

  const ResolvedScan* query() const {
    accessed_ |= (1<<3);
    return query_.get();
  }
  void set_query(std::unique_ptr<const ResolvedScan> v) {
    query_ = std::move(v);
  }

  std::unique_ptr<const ResolvedScan> release_query() {
    return std::move(query_);
  }

 protected:
  explicit ResolvedExportDataStmt(
      std::vector<std::unique_ptr<const ResolvedOption>> option_list,
      std::vector<std::unique_ptr<const ResolvedOutputColumn>> output_column_list,
      bool is_value_table,
      std::unique_ptr<const ResolvedScan> query,
      ConstructorOverload)
      : ResolvedStatement(
            ConstructorOverload::NEW_CONSTRUCTOR),
      option_list_(std::move(option_list)),
      output_column_list_(std::move(output_column_list)),
      is_value_table_(is_value_table),
      query_(std::move(query)) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  std::vector<std::unique_ptr<const ResolvedOption>> option_list_;
  std::vector<std::unique_ptr<const ResolvedOutputColumn>> output_column_list_;
  bool is_value_table_;
  std::unique_ptr<const ResolvedScan> query_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedExportDataStmt> MakeResolvedExportDataStmt(
    std::vector<std::unique_ptr<const ResolvedOption>> option_list,
    std::vector<std::unique_ptr<const ResolvedOutputColumn>> output_column_list,
    bool is_value_table,
    std::unique_ptr<const ResolvedScan> query) {
  return std::unique_ptr<ResolvedExportDataStmt>(new ResolvedExportDataStmt(
        std::move(option_list),
        std::move(output_column_list),
        is_value_table,
        std::move(query),
        ResolvedExportDataStmt::NEW_CONSTRUCTOR));
}

// Overloaded factory method for the construction of ResolvedExportDataStmt with
// a wider range of inputs for node-vector inputs.  In particular allows:
// 1. unique_ptr element type can be non-const.
// 2. unique_ptr element type can be any descendant of the required type.
// 3. input container can be any object with a `begin()` and `end()`.
//
// Note, initializer lists cannot be used to pass
//  option_list, output_column_list
// due to incompatibility with unique_ptr.  Use zetasql::MakeNodeVector
// instead.
template <
  typename option_list_t
      = std::vector<std::unique_ptr<const ResolvedOption>>,
  typename output_column_list_t
      = std::vector<std::unique_ptr<const ResolvedOutputColumn>>>
std::unique_ptr<ResolvedExportDataStmt> MakeResolvedExportDataStmt(
    option_list_t option_list,
    output_column_list_t output_column_list,
    bool is_value_table,
    std::unique_ptr<const ResolvedScan> query) {
  static_assert(std::is_base_of<
      ResolvedOption,
      typename std::decay<decltype(**(option_list.begin()))>::type>::value,
      "option_list must be a container of unique_ptr with elements of type "
      "ResolvedOption (or its descendants).");
  static_assert(std::is_base_of<
      ResolvedOutputColumn,
      typename std::decay<decltype(**(output_column_list.begin()))>::type>::value,
      "output_column_list must be a container of unique_ptr with elements of type "
      "ResolvedOutputColumn (or its descendants).");
  return MakeResolvedExportDataStmt(
      {std::make_move_iterator(option_list.begin()),
       std::make_move_iterator(option_list.end())},
      {std::make_move_iterator(output_column_list.begin()),
       std::make_move_iterator(output_column_list.end())},
      is_value_table,
      std::move(query));
}

inline std::unique_ptr<ResolvedExportDataStmt> MakeResolvedExportDataStmt() {
  return std::unique_ptr<ResolvedExportDataStmt>(
      new ResolvedExportDataStmt());
}

// This statement: DEFINE TABLE name (...);
//
// <name_path> is a vector giving the identifier path in the table name.
// <option_list> has engine-specific options of how the table is defined.
//
// DEFINE TABLE normally has the same effect as CREATE TEMP EXTERNAL TABLE.
class ResolvedDefineTableStmt final : public ResolvedStatement {
 public:
  typedef ResolvedStatement SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_DEFINE_TABLE_STMT;

  friend std::unique_ptr<ResolvedDefineTableStmt> MakeResolvedDefineTableStmt();
 protected:
  ResolvedDefineTableStmt()
      : ResolvedStatement()
      , name_path_()
      , option_list_()
  {}
 public:

  ResolvedDefineTableStmt(const ResolvedDefineTableStmt&) = delete;
  ResolvedDefineTableStmt& operator=(const ResolvedDefineTableStmt&) = delete;

  friend std::unique_ptr<ResolvedDefineTableStmt> MakeResolvedDefineTableStmt(
      const std::vector<std::string>& name_path,
      std::vector<std::unique_ptr<const ResolvedOption>> option_list
  );
  ~ResolvedDefineTableStmt() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_DEFINE_TABLE_STMT; }
  std::string node_kind_string() const final { return "DefineTableStmt"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedDefineTableStmtProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedStatementProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedDefineTableStmt>> RestoreFrom(
      const ResolvedDefineTableStmtProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  const std::vector<std::string>& name_path() const {
    accessed_ |= (1<<0);
    return name_path_;
  }
  int name_path_size() const {
    if (name_path_.empty()) accessed_ |= (1<<0);
    return static_cast<int>(name_path_.size());
  }
  std::string name_path(int i) const {
    accessed_ |= (1<<0);
    return name_path_.at(i);
  }
  void add_name_path(std::string v) {
    name_path_.push_back(std::string(v));
  }
  void set_name_path(const std::vector<std::string>& v) {
    name_path_ = v;
  }
  std::vector<std::string>* mutable_name_path() {
    accessed_ |= (1<<0);
    return &name_path_;
  }

  const std::vector<std::unique_ptr<const ResolvedOption>>& option_list() const {
    accessed_ |= (1<<1);
    return option_list_;
  }
  int option_list_size() const {
    if (option_list_.empty()) accessed_ |= (1<<1);
    return static_cast<int>(option_list_.size());
  }
  const ResolvedOption* option_list(int i) const {
    accessed_ |= (1<<1);
    return option_list_.at(i).get();
  }
  void add_option_list(std::unique_ptr<const ResolvedOption> v) {
    option_list_.emplace_back(std::move(v));
  }
  void set_option_list(std::vector<std::unique_ptr<const ResolvedOption>> v) {
    option_list_ = std::move(v);
  }

  std::vector<std::unique_ptr<const ResolvedOption>> release_option_list() {
    std::vector<std::unique_ptr<const ResolvedOption>> tmp;
    option_list_.swap(tmp);
    return tmp;
  }

 protected:
  explicit ResolvedDefineTableStmt(
      const std::vector<std::string>& name_path,
      std::vector<std::unique_ptr<const ResolvedOption>> option_list,
      ConstructorOverload)
      : ResolvedStatement(
            ConstructorOverload::NEW_CONSTRUCTOR),
      name_path_(name_path),
      option_list_(std::move(option_list)) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  std::vector<std::string> name_path_;
  std::vector<std::unique_ptr<const ResolvedOption>> option_list_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedDefineTableStmt> MakeResolvedDefineTableStmt(
    const std::vector<std::string>& name_path,
    std::vector<std::unique_ptr<const ResolvedOption>> option_list) {
  return std::unique_ptr<ResolvedDefineTableStmt>(new ResolvedDefineTableStmt(
        name_path,
        std::move(option_list),
        ResolvedDefineTableStmt::NEW_CONSTRUCTOR));
}

// Overloaded factory method for the construction of ResolvedDefineTableStmt with
// a wider range of inputs for node-vector inputs.  In particular allows:
// 1. unique_ptr element type can be non-const.
// 2. unique_ptr element type can be any descendant of the required type.
// 3. input container can be any object with a `begin()` and `end()`.
//
// Note, initializer lists cannot be used to pass
//  option_list
// due to incompatibility with unique_ptr.  Use zetasql::MakeNodeVector
// instead.
template <
  typename option_list_t
      = std::vector<std::unique_ptr<const ResolvedOption>>>
std::unique_ptr<ResolvedDefineTableStmt> MakeResolvedDefineTableStmt(
    const std::vector<std::string>& name_path,
    option_list_t option_list) {
  static_assert(std::is_base_of<
      ResolvedOption,
      typename std::decay<decltype(**(option_list.begin()))>::type>::value,
      "option_list must be a container of unique_ptr with elements of type "
      "ResolvedOption (or its descendants).");
  return MakeResolvedDefineTableStmt(
      name_path,
      {std::make_move_iterator(option_list.begin()),
       std::make_move_iterator(option_list.end())});
}

inline std::unique_ptr<ResolvedDefineTableStmt> MakeResolvedDefineTableStmt() {
  return std::unique_ptr<ResolvedDefineTableStmt>(
      new ResolvedDefineTableStmt());
}

// This statement: DESCRIBE [<object_type>] <name> [FROM <from_name_path>];
//
// <object_type> is an optional string identifier,
//               e.g., "INDEX", "FUNCTION", "TYPE", etc.
// <name_path> is a vector giving the identifier path for the object to be
//             described.
// <from_name_path> is an optional vector giving the identifier path of a
//                    containing object, e.g. a table.
class ResolvedDescribeStmt final : public ResolvedStatement {
 public:
  typedef ResolvedStatement SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_DESCRIBE_STMT;

  friend std::unique_ptr<ResolvedDescribeStmt> MakeResolvedDescribeStmt();
 protected:
  ResolvedDescribeStmt()
      : ResolvedStatement()
      , object_type_()
      , name_path_()
      , from_name_path_()
  {}
 public:

  ResolvedDescribeStmt(const ResolvedDescribeStmt&) = delete;
  ResolvedDescribeStmt& operator=(const ResolvedDescribeStmt&) = delete;

  friend std::unique_ptr<ResolvedDescribeStmt> MakeResolvedDescribeStmt(
      const std::string& object_type,
      const std::vector<std::string>& name_path,
      const std::vector<std::string>& from_name_path
  );
  ~ResolvedDescribeStmt() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_DESCRIBE_STMT; }
  std::string node_kind_string() const final { return "DescribeStmt"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedDescribeStmtProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedStatementProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedDescribeStmt>> RestoreFrom(
      const ResolvedDescribeStmtProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  const std::string& object_type() const {
    accessed_ |= (1<<0);
    return object_type_;
  }
  void set_object_type(const std::string& v) {
    object_type_ = v;
  }

  const std::vector<std::string>& name_path() const {
    accessed_ |= (1<<1);
    return name_path_;
  }
  int name_path_size() const {
    if (name_path_.empty()) accessed_ |= (1<<1);
    return static_cast<int>(name_path_.size());
  }
  std::string name_path(int i) const {
    accessed_ |= (1<<1);
    return name_path_.at(i);
  }
  void add_name_path(std::string v) {
    name_path_.push_back(std::string(v));
  }
  void set_name_path(const std::vector<std::string>& v) {
    name_path_ = v;
  }
  std::vector<std::string>* mutable_name_path() {
    accessed_ |= (1<<1);
    return &name_path_;
  }

  const std::vector<std::string>& from_name_path() const {
    accessed_ |= (1<<2);
    return from_name_path_;
  }
  int from_name_path_size() const {
    if (from_name_path_.empty()) accessed_ |= (1<<2);
    return static_cast<int>(from_name_path_.size());
  }
  std::string from_name_path(int i) const {
    accessed_ |= (1<<2);
    return from_name_path_.at(i);
  }
  void add_from_name_path(std::string v) {
    from_name_path_.push_back(std::string(v));
  }
  void set_from_name_path(const std::vector<std::string>& v) {
    from_name_path_ = v;
  }
  std::vector<std::string>* mutable_from_name_path() {
    accessed_ |= (1<<2);
    return &from_name_path_;
  }

 protected:
  explicit ResolvedDescribeStmt(
      const std::string& object_type,
      const std::vector<std::string>& name_path,
      const std::vector<std::string>& from_name_path,
      ConstructorOverload)
      : ResolvedStatement(
            ConstructorOverload::NEW_CONSTRUCTOR),
      object_type_(object_type),
      name_path_(name_path),
      from_name_path_(from_name_path) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  std::string object_type_;
  std::vector<std::string> name_path_;
  std::vector<std::string> from_name_path_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedDescribeStmt> MakeResolvedDescribeStmt(
    const std::string& object_type,
    const std::vector<std::string>& name_path,
    const std::vector<std::string>& from_name_path) {
  return std::unique_ptr<ResolvedDescribeStmt>(new ResolvedDescribeStmt(
        object_type,
        name_path,
        from_name_path,
        ResolvedDescribeStmt::NEW_CONSTRUCTOR));
}

inline std::unique_ptr<ResolvedDescribeStmt> MakeResolvedDescribeStmt() {
  return std::unique_ptr<ResolvedDescribeStmt>(
      new ResolvedDescribeStmt());
}

// This statement: SHOW <identifier> [FROM <name_path>] [LIKE <like_expr>];
//
// <identifier> is a string that determines the type of objects to be shown,
//              e.g., TABLES, COLUMNS, INDEXES, STATUS,
// <name_path> is an optional path to an object from which <identifier>
//             objects will be shown, e.g., if <identifier> = INDEXES and
//             <name> = table_name, the indexes of "table_name" will be
//             shown,
// <like_expr> is an optional ResolvedLiteral of type string that if present
//             restricts the objects shown to have a name like this string.
class ResolvedShowStmt final : public ResolvedStatement {
 public:
  typedef ResolvedStatement SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_SHOW_STMT;

  friend std::unique_ptr<ResolvedShowStmt> MakeResolvedShowStmt();
 protected:
  ResolvedShowStmt()
      : ResolvedStatement()
      , identifier_()
      , name_path_()
      , like_expr_()
  {}
 public:

  ResolvedShowStmt(const ResolvedShowStmt&) = delete;
  ResolvedShowStmt& operator=(const ResolvedShowStmt&) = delete;

  friend std::unique_ptr<ResolvedShowStmt> MakeResolvedShowStmt(
      const std::string& identifier,
      const std::vector<std::string>& name_path,
      std::unique_ptr<const ResolvedLiteral> like_expr
  );
  ~ResolvedShowStmt() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_SHOW_STMT; }
  std::string node_kind_string() const final { return "ShowStmt"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedShowStmtProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedStatementProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedShowStmt>> RestoreFrom(
      const ResolvedShowStmtProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  const std::string& identifier() const {
    accessed_ |= (1<<0);
    return identifier_;
  }
  void set_identifier(const std::string& v) {
    identifier_ = v;
  }

  const std::vector<std::string>& name_path() const {
    accessed_ |= (1<<1);
    return name_path_;
  }
  int name_path_size() const {
    if (name_path_.empty()) accessed_ |= (1<<1);
    return static_cast<int>(name_path_.size());
  }
  std::string name_path(int i) const {
    accessed_ |= (1<<1);
    return name_path_.at(i);
  }
  void add_name_path(std::string v) {
    name_path_.push_back(std::string(v));
  }
  void set_name_path(const std::vector<std::string>& v) {
    name_path_ = v;
  }
  std::vector<std::string>* mutable_name_path() {
    accessed_ |= (1<<1);
    return &name_path_;
  }

  const ResolvedLiteral* like_expr() const {
    accessed_ |= (1<<2);
    return like_expr_.get();
  }
  void set_like_expr(std::unique_ptr<const ResolvedLiteral> v) {
    like_expr_ = std::move(v);
  }

  std::unique_ptr<const ResolvedLiteral> release_like_expr() {
    return std::move(like_expr_);
  }

 protected:
  explicit ResolvedShowStmt(
      const std::string& identifier,
      const std::vector<std::string>& name_path,
      std::unique_ptr<const ResolvedLiteral> like_expr,
      ConstructorOverload)
      : ResolvedStatement(
            ConstructorOverload::NEW_CONSTRUCTOR),
      identifier_(identifier),
      name_path_(name_path),
      like_expr_(std::move(like_expr)) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  std::string identifier_;
  std::vector<std::string> name_path_;
  std::unique_ptr<const ResolvedLiteral> like_expr_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedShowStmt> MakeResolvedShowStmt(
    const std::string& identifier,
    const std::vector<std::string>& name_path,
    std::unique_ptr<const ResolvedLiteral> like_expr) {
  return std::unique_ptr<ResolvedShowStmt>(new ResolvedShowStmt(
        identifier,
        name_path,
        std::move(like_expr),
        ResolvedShowStmt::NEW_CONSTRUCTOR));
}

inline std::unique_ptr<ResolvedShowStmt> MakeResolvedShowStmt() {
  return std::unique_ptr<ResolvedShowStmt>(
      new ResolvedShowStmt());
}

// This statement: BEGIN [TRANSACTION] [ <transaction_mode> [, ...] ]
//
// Where transaction_mode is one of:
//      READ ONLY
//      READ WRITE
//      <isolation_level>
//
// <isolation_level> is a string vector storing the identifiers after
//       ISOLATION LEVEL. The strings inside vector could be one of the
//       SQL standard isolation levels:
//
//                   READ UNCOMMITTED
//                   READ COMMITTED
//                   READ REPEATABLE
//                   SERIALIZABLE
//
//       or could be arbitrary strings. ZetaSQL does not validate that
//       the string is valid.
class ResolvedBeginStmt final : public ResolvedStatement {
 public:
  typedef ResolvedStatement SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_BEGIN_STMT;

  typedef ResolvedBeginStmtEnums::ReadWriteMode ReadWriteMode;
  static const ReadWriteMode MODE_UNSPECIFIED = ResolvedBeginStmtEnums::MODE_UNSPECIFIED;
  static const ReadWriteMode MODE_READ_ONLY = ResolvedBeginStmtEnums::MODE_READ_ONLY;
  static const ReadWriteMode MODE_READ_WRITE = ResolvedBeginStmtEnums::MODE_READ_WRITE;

  friend std::unique_ptr<ResolvedBeginStmt> MakeResolvedBeginStmt();
 protected:
  ResolvedBeginStmt()
      : ResolvedStatement()
      , read_write_mode_()
      , isolation_level_list_()
  {}
 public:

  ResolvedBeginStmt(const ResolvedBeginStmt&) = delete;
  ResolvedBeginStmt& operator=(const ResolvedBeginStmt&) = delete;

  friend std::unique_ptr<ResolvedBeginStmt> MakeResolvedBeginStmt(
      ReadWriteMode read_write_mode,
      const std::vector<std::string>& isolation_level_list
  );
  ~ResolvedBeginStmt() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_BEGIN_STMT; }
  std::string node_kind_string() const final { return "BeginStmt"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedBeginStmtProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedStatementProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedBeginStmt>> RestoreFrom(
      const ResolvedBeginStmtProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  ReadWriteMode read_write_mode() const {
    accessed_ |= (1<<0);
    return read_write_mode_;
  }
  void set_read_write_mode(ReadWriteMode v) {
    read_write_mode_ = v;
  }

  const std::vector<std::string>& isolation_level_list() const {
    accessed_ |= (1<<1);
    return isolation_level_list_;
  }
  int isolation_level_list_size() const {
    if (isolation_level_list_.empty()) accessed_ |= (1<<1);
    return static_cast<int>(isolation_level_list_.size());
  }
  std::string isolation_level_list(int i) const {
    accessed_ |= (1<<1);
    return isolation_level_list_.at(i);
  }
  void add_isolation_level_list(std::string v) {
    isolation_level_list_.push_back(std::string(v));
  }
  void set_isolation_level_list(const std::vector<std::string>& v) {
    isolation_level_list_ = v;
  }
  std::vector<std::string>* mutable_isolation_level_list() {
    accessed_ |= (1<<1);
    return &isolation_level_list_;
  }

 protected:
  explicit ResolvedBeginStmt(
      ReadWriteMode read_write_mode,
      const std::vector<std::string>& isolation_level_list,
      ConstructorOverload)
      : ResolvedStatement(
            ConstructorOverload::NEW_CONSTRUCTOR),
      read_write_mode_(read_write_mode),
      isolation_level_list_(isolation_level_list) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  ReadWriteMode read_write_mode_;
  std::vector<std::string> isolation_level_list_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedBeginStmt> MakeResolvedBeginStmt(
    ResolvedBeginStmt::ReadWriteMode read_write_mode,
    const std::vector<std::string>& isolation_level_list) {
  return std::unique_ptr<ResolvedBeginStmt>(new ResolvedBeginStmt(
        read_write_mode,
        isolation_level_list,
        ResolvedBeginStmt::NEW_CONSTRUCTOR));
}

inline std::unique_ptr<ResolvedBeginStmt> MakeResolvedBeginStmt() {
  return std::unique_ptr<ResolvedBeginStmt>(
      new ResolvedBeginStmt());
}

// This statement: SET TRANSACTION <transaction_mode> [, ...]
//
// Where transaction_mode is one of:
//      READ ONLY
//      READ WRITE
//      <isolation_level>
//
// <isolation_level> is a string vector storing the identifiers after
//       ISOLATION LEVEL. The strings inside vector could be one of the
//       SQL standard isolation levels:
//
//                   READ UNCOMMITTED
//                   READ COMMITTED
//                   READ REPEATABLE
//                   SERIALIZABLE
//
//       or could be arbitrary strings. ZetaSQL does not validate that
//       the string is valid.
class ResolvedSetTransactionStmt final : public ResolvedStatement {
 public:
  typedef ResolvedStatement SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_SET_TRANSACTION_STMT;

  typedef ResolvedBeginStmt::ReadWriteMode ReadWriteMode;

  friend std::unique_ptr<ResolvedSetTransactionStmt> MakeResolvedSetTransactionStmt();
 protected:
  ResolvedSetTransactionStmt()
      : ResolvedStatement()
      , read_write_mode_()
      , isolation_level_list_()
  {}
 public:

  ResolvedSetTransactionStmt(const ResolvedSetTransactionStmt&) = delete;
  ResolvedSetTransactionStmt& operator=(const ResolvedSetTransactionStmt&) = delete;

  friend std::unique_ptr<ResolvedSetTransactionStmt> MakeResolvedSetTransactionStmt(
      ReadWriteMode read_write_mode,
      const std::vector<std::string>& isolation_level_list
  );
  ~ResolvedSetTransactionStmt() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_SET_TRANSACTION_STMT; }
  std::string node_kind_string() const final { return "SetTransactionStmt"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedSetTransactionStmtProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedStatementProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedSetTransactionStmt>> RestoreFrom(
      const ResolvedSetTransactionStmtProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  ReadWriteMode read_write_mode() const {
    accessed_ |= (1<<0);
    return read_write_mode_;
  }
  void set_read_write_mode(ReadWriteMode v) {
    read_write_mode_ = v;
  }

  const std::vector<std::string>& isolation_level_list() const {
    accessed_ |= (1<<1);
    return isolation_level_list_;
  }
  int isolation_level_list_size() const {
    if (isolation_level_list_.empty()) accessed_ |= (1<<1);
    return static_cast<int>(isolation_level_list_.size());
  }
  std::string isolation_level_list(int i) const {
    accessed_ |= (1<<1);
    return isolation_level_list_.at(i);
  }
  void add_isolation_level_list(std::string v) {
    isolation_level_list_.push_back(std::string(v));
  }
  void set_isolation_level_list(const std::vector<std::string>& v) {
    isolation_level_list_ = v;
  }
  std::vector<std::string>* mutable_isolation_level_list() {
    accessed_ |= (1<<1);
    return &isolation_level_list_;
  }

 protected:
  explicit ResolvedSetTransactionStmt(
      ReadWriteMode read_write_mode,
      const std::vector<std::string>& isolation_level_list,
      ConstructorOverload)
      : ResolvedStatement(
            ConstructorOverload::NEW_CONSTRUCTOR),
      read_write_mode_(read_write_mode),
      isolation_level_list_(isolation_level_list) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  ReadWriteMode read_write_mode_;
  std::vector<std::string> isolation_level_list_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedSetTransactionStmt> MakeResolvedSetTransactionStmt(
    ResolvedBeginStmt::ReadWriteMode read_write_mode,
    const std::vector<std::string>& isolation_level_list) {
  return std::unique_ptr<ResolvedSetTransactionStmt>(new ResolvedSetTransactionStmt(
        read_write_mode,
        isolation_level_list,
        ResolvedSetTransactionStmt::NEW_CONSTRUCTOR));
}

inline std::unique_ptr<ResolvedSetTransactionStmt> MakeResolvedSetTransactionStmt() {
  return std::unique_ptr<ResolvedSetTransactionStmt>(
      new ResolvedSetTransactionStmt());
}

// This statement: COMMIT [TRANSACTION];
class ResolvedCommitStmt final : public ResolvedStatement {
 public:
  typedef ResolvedStatement SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_COMMIT_STMT;

  friend std::unique_ptr<ResolvedCommitStmt> MakeResolvedCommitStmt();
 protected:
  ResolvedCommitStmt()
      : ResolvedStatement()
  {}
 public:

  ResolvedCommitStmt(const ResolvedCommitStmt&) = delete;
  ResolvedCommitStmt& operator=(const ResolvedCommitStmt&) = delete;

  ~ResolvedCommitStmt() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_COMMIT_STMT; }
  std::string node_kind_string() const final { return "CommitStmt"; }

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedCommitStmtProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedStatementProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedCommitStmt>> RestoreFrom(
      const ResolvedCommitStmtProto& proto,
      const ResolvedNode::RestoreParams& params);

  // Member fields

 protected:
  explicit ResolvedCommitStmt(
      ConstructorOverload)
      : ResolvedStatement(
            ConstructorOverload::NEW_CONSTRUCTOR) {
  }

 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

};

inline std::unique_ptr<ResolvedCommitStmt> MakeResolvedCommitStmt() {
  return std::unique_ptr<ResolvedCommitStmt>(
      new ResolvedCommitStmt());
}

// This statement: ROLLBACK [TRANSACTION];
class ResolvedRollbackStmt final : public ResolvedStatement {
 public:
  typedef ResolvedStatement SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_ROLLBACK_STMT;

  friend std::unique_ptr<ResolvedRollbackStmt> MakeResolvedRollbackStmt();
 protected:
  ResolvedRollbackStmt()
      : ResolvedStatement()
  {}
 public:

  ResolvedRollbackStmt(const ResolvedRollbackStmt&) = delete;
  ResolvedRollbackStmt& operator=(const ResolvedRollbackStmt&) = delete;

  ~ResolvedRollbackStmt() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_ROLLBACK_STMT; }
  std::string node_kind_string() const final { return "RollbackStmt"; }

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedRollbackStmtProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedStatementProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedRollbackStmt>> RestoreFrom(
      const ResolvedRollbackStmtProto& proto,
      const ResolvedNode::RestoreParams& params);

  // Member fields

 protected:
  explicit ResolvedRollbackStmt(
      ConstructorOverload)
      : ResolvedStatement(
            ConstructorOverload::NEW_CONSTRUCTOR) {
  }

 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

};

inline std::unique_ptr<ResolvedRollbackStmt> MakeResolvedRollbackStmt() {
  return std::unique_ptr<ResolvedRollbackStmt>(
      new ResolvedRollbackStmt());
}

// This statement: START BATCH [<batch_type>];
//
// <batch_type> is an optional string identifier that identifies the type of
//              the batch. (e.g. "DML" or "DDL)
class ResolvedStartBatchStmt final : public ResolvedStatement {
 public:
  typedef ResolvedStatement SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_START_BATCH_STMT;

  friend std::unique_ptr<ResolvedStartBatchStmt> MakeResolvedStartBatchStmt();
 protected:
  ResolvedStartBatchStmt()
      : ResolvedStatement()
      , batch_type_()
  {}
 public:

  ResolvedStartBatchStmt(const ResolvedStartBatchStmt&) = delete;
  ResolvedStartBatchStmt& operator=(const ResolvedStartBatchStmt&) = delete;

  friend std::unique_ptr<ResolvedStartBatchStmt> MakeResolvedStartBatchStmt(
      const std::string& batch_type
  );
  ~ResolvedStartBatchStmt() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_START_BATCH_STMT; }
  std::string node_kind_string() const final { return "StartBatchStmt"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedStartBatchStmtProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedStatementProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedStartBatchStmt>> RestoreFrom(
      const ResolvedStartBatchStmtProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  const std::string& batch_type() const {
    accessed_ |= (1<<0);
    return batch_type_;
  }
  void set_batch_type(const std::string& v) {
    batch_type_ = v;
  }

 protected:
  explicit ResolvedStartBatchStmt(
      const std::string& batch_type,
      ConstructorOverload)
      : ResolvedStatement(
            ConstructorOverload::NEW_CONSTRUCTOR),
      batch_type_(batch_type) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  std::string batch_type_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedStartBatchStmt> MakeResolvedStartBatchStmt(
    const std::string& batch_type) {
  return std::unique_ptr<ResolvedStartBatchStmt>(new ResolvedStartBatchStmt(
        batch_type,
        ResolvedStartBatchStmt::NEW_CONSTRUCTOR));
}

inline std::unique_ptr<ResolvedStartBatchStmt> MakeResolvedStartBatchStmt() {
  return std::unique_ptr<ResolvedStartBatchStmt>(
      new ResolvedStartBatchStmt());
}

// This statement: RUN BATCH;
class ResolvedRunBatchStmt final : public ResolvedStatement {
 public:
  typedef ResolvedStatement SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_RUN_BATCH_STMT;

  friend std::unique_ptr<ResolvedRunBatchStmt> MakeResolvedRunBatchStmt();
 protected:
  ResolvedRunBatchStmt()
      : ResolvedStatement()
  {}
 public:

  ResolvedRunBatchStmt(const ResolvedRunBatchStmt&) = delete;
  ResolvedRunBatchStmt& operator=(const ResolvedRunBatchStmt&) = delete;

  ~ResolvedRunBatchStmt() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_RUN_BATCH_STMT; }
  std::string node_kind_string() const final { return "RunBatchStmt"; }

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedRunBatchStmtProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedStatementProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedRunBatchStmt>> RestoreFrom(
      const ResolvedRunBatchStmtProto& proto,
      const ResolvedNode::RestoreParams& params);

  // Member fields

 protected:
  explicit ResolvedRunBatchStmt(
      ConstructorOverload)
      : ResolvedStatement(
            ConstructorOverload::NEW_CONSTRUCTOR) {
  }

 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

};

inline std::unique_ptr<ResolvedRunBatchStmt> MakeResolvedRunBatchStmt() {
  return std::unique_ptr<ResolvedRunBatchStmt>(
      new ResolvedRunBatchStmt());
}

// This statement: ABORT BATCH;
class ResolvedAbortBatchStmt final : public ResolvedStatement {
 public:
  typedef ResolvedStatement SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_ABORT_BATCH_STMT;

  friend std::unique_ptr<ResolvedAbortBatchStmt> MakeResolvedAbortBatchStmt();
 protected:
  ResolvedAbortBatchStmt()
      : ResolvedStatement()
  {}
 public:

  ResolvedAbortBatchStmt(const ResolvedAbortBatchStmt&) = delete;
  ResolvedAbortBatchStmt& operator=(const ResolvedAbortBatchStmt&) = delete;

  ~ResolvedAbortBatchStmt() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_ABORT_BATCH_STMT; }
  std::string node_kind_string() const final { return "AbortBatchStmt"; }

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedAbortBatchStmtProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedStatementProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedAbortBatchStmt>> RestoreFrom(
      const ResolvedAbortBatchStmtProto& proto,
      const ResolvedNode::RestoreParams& params);

  // Member fields

 protected:
  explicit ResolvedAbortBatchStmt(
      ConstructorOverload)
      : ResolvedStatement(
            ConstructorOverload::NEW_CONSTRUCTOR) {
  }

 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

};

inline std::unique_ptr<ResolvedAbortBatchStmt> MakeResolvedAbortBatchStmt() {
  return std::unique_ptr<ResolvedAbortBatchStmt>(
      new ResolvedAbortBatchStmt());
}

// This statement: DROP <object_type> [IF EXISTS] <name_path>;
//
// <object_type> is an string identifier,
//               e.g., "TABLE", "VIEW", "INDEX", "FUNCTION", "TYPE", etc.
// <name_path> is a vector giving the identifier path for the object to be
//             dropped.
// <is_if_exists> silently ignore the "name_path does not exist" error.
class ResolvedDropStmt final : public ResolvedStatement {
 public:
  typedef ResolvedStatement SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_DROP_STMT;

  friend std::unique_ptr<ResolvedDropStmt> MakeResolvedDropStmt();
 protected:
  ResolvedDropStmt()
      : ResolvedStatement()
      , object_type_()
      , is_if_exists_()
      , name_path_()
  {}
 public:

  ResolvedDropStmt(const ResolvedDropStmt&) = delete;
  ResolvedDropStmt& operator=(const ResolvedDropStmt&) = delete;

  friend std::unique_ptr<ResolvedDropStmt> MakeResolvedDropStmt(
      const std::string& object_type,
      bool is_if_exists,
      const std::vector<std::string>& name_path
  );
  ~ResolvedDropStmt() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_DROP_STMT; }
  std::string node_kind_string() const final { return "DropStmt"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedDropStmtProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedStatementProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedDropStmt>> RestoreFrom(
      const ResolvedDropStmtProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  const std::string& object_type() const {
    accessed_ |= (1<<0);
    return object_type_;
  }
  void set_object_type(const std::string& v) {
    object_type_ = v;
  }

  bool is_if_exists() const {
    accessed_ |= (1<<1);
    return is_if_exists_;
  }
  void set_is_if_exists(bool v) {
    is_if_exists_ = v;
  }

  const std::vector<std::string>& name_path() const {
    accessed_ |= (1<<2);
    return name_path_;
  }
  int name_path_size() const {
    if (name_path_.empty()) accessed_ |= (1<<2);
    return static_cast<int>(name_path_.size());
  }
  std::string name_path(int i) const {
    accessed_ |= (1<<2);
    return name_path_.at(i);
  }
  void add_name_path(std::string v) {
    name_path_.push_back(std::string(v));
  }
  void set_name_path(const std::vector<std::string>& v) {
    name_path_ = v;
  }
  std::vector<std::string>* mutable_name_path() {
    accessed_ |= (1<<2);
    return &name_path_;
  }

 protected:
  explicit ResolvedDropStmt(
      const std::string& object_type,
      bool is_if_exists,
      const std::vector<std::string>& name_path,
      ConstructorOverload)
      : ResolvedStatement(
            ConstructorOverload::NEW_CONSTRUCTOR),
      object_type_(object_type),
      is_if_exists_(is_if_exists),
      name_path_(name_path) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  std::string object_type_;
  bool is_if_exists_;
  std::vector<std::string> name_path_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedDropStmt> MakeResolvedDropStmt(
    const std::string& object_type,
    bool is_if_exists,
    const std::vector<std::string>& name_path) {
  return std::unique_ptr<ResolvedDropStmt>(new ResolvedDropStmt(
        object_type,
        is_if_exists,
        name_path,
        ResolvedDropStmt::NEW_CONSTRUCTOR));
}

inline std::unique_ptr<ResolvedDropStmt> MakeResolvedDropStmt() {
  return std::unique_ptr<ResolvedDropStmt>(
      new ResolvedDropStmt());
}

// This statement: DROP MATERIALIZED VIEW [IF EXISTS] <name_path>;
//
// <name_path> is a vector giving the identifier path for the object to be
//             dropped.
// <is_if_exists> silently ignore the "name_path does not exist" error.
class ResolvedDropMaterializedViewStmt final : public ResolvedStatement {
 public:
  typedef ResolvedStatement SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_DROP_MATERIALIZED_VIEW_STMT;

  friend std::unique_ptr<ResolvedDropMaterializedViewStmt> MakeResolvedDropMaterializedViewStmt();
 protected:
  ResolvedDropMaterializedViewStmt()
      : ResolvedStatement()
      , is_if_exists_()
      , name_path_()
  {}
 public:

  ResolvedDropMaterializedViewStmt(const ResolvedDropMaterializedViewStmt&) = delete;
  ResolvedDropMaterializedViewStmt& operator=(const ResolvedDropMaterializedViewStmt&) = delete;

  friend std::unique_ptr<ResolvedDropMaterializedViewStmt> MakeResolvedDropMaterializedViewStmt(
      bool is_if_exists,
      const std::vector<std::string>& name_path
  );
  ~ResolvedDropMaterializedViewStmt() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_DROP_MATERIALIZED_VIEW_STMT; }
  std::string node_kind_string() const final { return "DropMaterializedViewStmt"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedDropMaterializedViewStmtProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedStatementProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedDropMaterializedViewStmt>> RestoreFrom(
      const ResolvedDropMaterializedViewStmtProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  bool is_if_exists() const {
    accessed_ |= (1<<0);
    return is_if_exists_;
  }
  void set_is_if_exists(bool v) {
    is_if_exists_ = v;
  }

  const std::vector<std::string>& name_path() const {
    accessed_ |= (1<<1);
    return name_path_;
  }
  int name_path_size() const {
    if (name_path_.empty()) accessed_ |= (1<<1);
    return static_cast<int>(name_path_.size());
  }
  std::string name_path(int i) const {
    accessed_ |= (1<<1);
    return name_path_.at(i);
  }
  void add_name_path(std::string v) {
    name_path_.push_back(std::string(v));
  }
  void set_name_path(const std::vector<std::string>& v) {
    name_path_ = v;
  }
  std::vector<std::string>* mutable_name_path() {
    accessed_ |= (1<<1);
    return &name_path_;
  }

 protected:
  explicit ResolvedDropMaterializedViewStmt(
      bool is_if_exists,
      const std::vector<std::string>& name_path,
      ConstructorOverload)
      : ResolvedStatement(
            ConstructorOverload::NEW_CONSTRUCTOR),
      is_if_exists_(is_if_exists),
      name_path_(name_path) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  bool is_if_exists_;
  std::vector<std::string> name_path_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedDropMaterializedViewStmt> MakeResolvedDropMaterializedViewStmt(
    bool is_if_exists,
    const std::vector<std::string>& name_path) {
  return std::unique_ptr<ResolvedDropMaterializedViewStmt>(new ResolvedDropMaterializedViewStmt(
        is_if_exists,
        name_path,
        ResolvedDropMaterializedViewStmt::NEW_CONSTRUCTOR));
}

inline std::unique_ptr<ResolvedDropMaterializedViewStmt> MakeResolvedDropMaterializedViewStmt() {
  return std::unique_ptr<ResolvedDropMaterializedViewStmt>(
      new ResolvedDropMaterializedViewStmt());
}

// This represents a SQL WITH query (or subquery) like
//   WITH <with_query_name1> AS (<with_subquery1>),
//        <with_query_name2> AS (<with_subquery2>)
//   <query>;
//
// A <with_query_name> may be referenced (multiple times) inside a later
// with_subquery, or in the final <query>.
//
// If a WITH subquery is referenced multiple times, the full query should
// behave as if the subquery runs only once and its result is reused.
//
// There will be one ResolvedWithEntry here for each subquery in the SQL
// WITH statement, in the same order as in the query.
//
// Inside the resolved <query>, or any <with_entry_list> occurring after
// its definition, a <with_query_name> used as a table scan will be
// represented using a ResolvedWithRefScan.
//
// The <with_query_name> aliases are always unique within a query, and should
// be used to connect the ResolvedWithRefScan to the original query
// definition.  The subqueries are not inlined and duplicated into the tree.
//
// In ZetaSQL 1.0, WITH is allowed only on the outermost query and not in
// subqueries, so the ResolvedWithScan node can only occur as the outermost
// scan in a statement (e.g. a QueryStmt or CreateTableAsSelectStmt).
//
// In ZetaSQL 1.1 (language option FEATURE_V_1_1_WITH_ON_SUBQUERY), WITH
// is allowed on subqueries.  Then, ResolvedWithScan can occur anywhere in
// the tree.  The alias introduced by a ResolvedWithEntry is visible only
// in subsequent ResolvedWithEntry queries and in <query>.  The aliases used
// must be globally unique in the resolved AST however, so consumers do not
// need to implement any scoping for these names.  Because the aliases are
// unique, it is legal to collect all ResolvedWithEntries in the tree and
// treat them as if they were a single WITH clause at the outermost level.
//
// The subqueries inside ResolvedWithEntries cannot be correlated.
//
// If a WITH subquery is defined but never referenced, it will still be
// resolved and still show up here.  Query engines may choose not to run it.
//
// SQL-style WITH RECURSIVE is not currently supported.
class ResolvedWithScan final : public ResolvedScan {
 public:
  typedef ResolvedScan SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_WITH_SCAN;

  friend std::unique_ptr<ResolvedWithScan> MakeResolvedWithScan();
 protected:
  ResolvedWithScan()
      : ResolvedScan()
      , with_entry_list_()
      , query_()
  {}
 public:

  ResolvedWithScan(const ResolvedWithScan&) = delete;
  ResolvedWithScan& operator=(const ResolvedWithScan&) = delete;

  friend std::unique_ptr<ResolvedWithScan> MakeResolvedWithScan(
      const std::vector<ResolvedColumn>& column_list,
      std::vector<std::unique_ptr<const ResolvedWithEntry>> with_entry_list,
      std::unique_ptr<const ResolvedScan> query
  );
  ~ResolvedWithScan() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_WITH_SCAN; }
  std::string node_kind_string() const final { return "WithScan"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedWithScanProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedScanProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedWithScan>> RestoreFrom(
      const ResolvedWithScanProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  const std::vector<std::unique_ptr<const ResolvedWithEntry>>& with_entry_list() const {
    accessed_ |= (1<<0);
    return with_entry_list_;
  }
  int with_entry_list_size() const {
    if (with_entry_list_.empty()) accessed_ |= (1<<0);
    return static_cast<int>(with_entry_list_.size());
  }
  const ResolvedWithEntry* with_entry_list(int i) const {
    accessed_ |= (1<<0);
    return with_entry_list_.at(i).get();
  }
  void add_with_entry_list(std::unique_ptr<const ResolvedWithEntry> v) {
    with_entry_list_.emplace_back(std::move(v));
  }
  void set_with_entry_list(std::vector<std::unique_ptr<const ResolvedWithEntry>> v) {
    with_entry_list_ = std::move(v);
  }

  std::vector<std::unique_ptr<const ResolvedWithEntry>> release_with_entry_list() {
    std::vector<std::unique_ptr<const ResolvedWithEntry>> tmp;
    with_entry_list_.swap(tmp);
    return tmp;
  }

  const ResolvedScan* query() const {
    accessed_ |= (1<<1);
    return query_.get();
  }
  void set_query(std::unique_ptr<const ResolvedScan> v) {
    query_ = std::move(v);
    set_is_ordered(query_->is_ordered());
  }

  std::unique_ptr<const ResolvedScan> release_query() {
    return std::move(query_);
  }

 protected:
  explicit ResolvedWithScan(
      const std::vector<ResolvedColumn>& column_list,
      std::vector<std::unique_ptr<const ResolvedWithEntry>> with_entry_list,
      std::unique_ptr<const ResolvedScan> query,
      ConstructorOverload)
      : ResolvedScan(
            column_list,
            ConstructorOverload::NEW_CONSTRUCTOR),
      with_entry_list_(std::move(with_entry_list)),
      query_(std::move(query)) {
    set_is_ordered(query_->is_ordered());
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  std::vector<std::unique_ptr<const ResolvedWithEntry>> with_entry_list_;
  std::unique_ptr<const ResolvedScan> query_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedWithScan> MakeResolvedWithScan(
    const std::vector<ResolvedColumn>& column_list,
    std::vector<std::unique_ptr<const ResolvedWithEntry>> with_entry_list,
    std::unique_ptr<const ResolvedScan> query) {
  return std::unique_ptr<ResolvedWithScan>(new ResolvedWithScan(
        column_list,
        std::move(with_entry_list),
        std::move(query),
        ResolvedWithScan::NEW_CONSTRUCTOR));
}

// Overloaded factory method for the construction of ResolvedWithScan with
// a wider range of inputs for node-vector inputs.  In particular allows:
// 1. unique_ptr element type can be non-const.
// 2. unique_ptr element type can be any descendant of the required type.
// 3. input container can be any object with a `begin()` and `end()`.
//
// Note, initializer lists cannot be used to pass
//  with_entry_list
// due to incompatibility with unique_ptr.  Use zetasql::MakeNodeVector
// instead.
template <
  typename with_entry_list_t
      = std::vector<std::unique_ptr<const ResolvedWithEntry>>>
std::unique_ptr<ResolvedWithScan> MakeResolvedWithScan(
    const std::vector<ResolvedColumn>& column_list,
    with_entry_list_t with_entry_list,
    std::unique_ptr<const ResolvedScan> query) {
  static_assert(std::is_base_of<
      ResolvedWithEntry,
      typename std::decay<decltype(**(with_entry_list.begin()))>::type>::value,
      "with_entry_list must be a container of unique_ptr with elements of type "
      "ResolvedWithEntry (or its descendants).");
  return MakeResolvedWithScan(
      column_list,
      {std::make_move_iterator(with_entry_list.begin()),
       std::make_move_iterator(with_entry_list.end())},
      std::move(query));
}

inline std::unique_ptr<ResolvedWithScan> MakeResolvedWithScan() {
  return std::unique_ptr<ResolvedWithScan>(
      new ResolvedWithScan());
}

// This represents one aliased subquery introduced in a WITH clause.
//
// The <with_query_name>s must be globally unique in the full resolved AST.
// The <with_subquery> cannot be correlated and cannot reference any
// columns from outside.  It may reference other WITH subqueries.
//
// See ResolvedWithScan for full details.
class ResolvedWithEntry final : public ResolvedArgument {
 public:
  typedef ResolvedArgument SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_WITH_ENTRY;

  friend std::unique_ptr<ResolvedWithEntry> MakeResolvedWithEntry();
 protected:
  ResolvedWithEntry()
      : ResolvedArgument()
      , with_query_name_()
      , with_subquery_()
  {}
 public:

  ResolvedWithEntry(const ResolvedWithEntry&) = delete;
  ResolvedWithEntry& operator=(const ResolvedWithEntry&) = delete;

  friend std::unique_ptr<ResolvedWithEntry> MakeResolvedWithEntry(
      const std::string& with_query_name,
      std::unique_ptr<const ResolvedScan> with_subquery
  );
  ~ResolvedWithEntry() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_WITH_ENTRY; }
  std::string node_kind_string() const final { return "WithEntry"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedWithEntryProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedArgumentProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedWithEntry>> RestoreFrom(
      const ResolvedWithEntryProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  const std::string& with_query_name() const {
    accessed_ |= (1<<0);
    return with_query_name_;
  }
  void set_with_query_name(const std::string& v) {
    with_query_name_ = v;
  }

  const ResolvedScan* with_subquery() const {
    accessed_ |= (1<<1);
    return with_subquery_.get();
  }
  void set_with_subquery(std::unique_ptr<const ResolvedScan> v) {
    with_subquery_ = std::move(v);
  }

  std::unique_ptr<const ResolvedScan> release_with_subquery() {
    return std::move(with_subquery_);
  }

 protected:
  explicit ResolvedWithEntry(
      const std::string& with_query_name,
      std::unique_ptr<const ResolvedScan> with_subquery,
      ConstructorOverload)
      : ResolvedArgument(
            ConstructorOverload::NEW_CONSTRUCTOR),
      with_query_name_(with_query_name),
      with_subquery_(std::move(with_subquery)) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  std::string with_query_name_;
  std::unique_ptr<const ResolvedScan> with_subquery_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedWithEntry> MakeResolvedWithEntry(
    const std::string& with_query_name,
    std::unique_ptr<const ResolvedScan> with_subquery) {
  return std::unique_ptr<ResolvedWithEntry>(new ResolvedWithEntry(
        with_query_name,
        std::move(with_subquery),
        ResolvedWithEntry::NEW_CONSTRUCTOR));
}

inline std::unique_ptr<ResolvedWithEntry> MakeResolvedWithEntry() {
  return std::unique_ptr<ResolvedWithEntry>(
      new ResolvedWithEntry());
}

// This represents one SQL hint key/value pair.
// The SQL syntax @{ key1=value1, key2=value2, some_db.key3=value3 }
// will expand to three ResolvedOptions.  Keyword hints (e.g. LOOKUP JOIN)
// are interpreted as shorthand, and will be expanded to a ResolvedOption
// attached to the appropriate node before any explicit long-form hints.
//
// ResolvedOptions are attached to the ResolvedScan corresponding to the
// operator that the SQL hint was associated with.
// See (broken link) for more detail.
// Hint semantics are implementation defined.
//
// Each hint is resolved as a [<qualifier>.]<name>:=<value> pair.
//   <qualifier> will be empty if no qualifier was present.
//   <name> is always non-empty.
//   <value> can be a ResolvedLiteral or a ResolvedParameter,
//           a cast of a ResolvedParameter (for typed hints only),
//           or a general expression (on constant inputs).
//
// If AllowedHintsAndOptions was set in AnalyzerOptions, and this hint or
// option was included there and had an expected type, the type of <value>
// will match that expected type.  Unknown hints (not listed in
// AllowedHintsAndOptions) are not stripped and will still show up here.
//
// If non-empty, <qualifier> should be interpreted as a target system name,
// and a database system should ignore any hints targeted to different
// systems.
//
// The SQL syntax allows using an identifier as a hint value.
// Such values are stored here as ResolvedLiterals with string type.
class ResolvedOption final : public ResolvedArgument {
 public:
  typedef ResolvedArgument SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_OPTION;

  friend std::unique_ptr<ResolvedOption> MakeResolvedOption();
 protected:
  ResolvedOption()
      : ResolvedArgument()
      , qualifier_()
      , name_()
      , value_()
  {}
 public:

  ResolvedOption(const ResolvedOption&) = delete;
  ResolvedOption& operator=(const ResolvedOption&) = delete;

  friend std::unique_ptr<ResolvedOption> MakeResolvedOption(
      const std::string& qualifier,
      const std::string& name,
      std::unique_ptr<const ResolvedExpr> value
  );
  ~ResolvedOption() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_OPTION; }
  std::string node_kind_string() const final { return "Option"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedOptionProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedArgumentProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedOption>> RestoreFrom(
      const ResolvedOptionProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  const std::string& qualifier() const {
    accessed_ |= (1<<0);
    return qualifier_;
  }
  void set_qualifier(const std::string& v) {
    qualifier_ = v;
  }

  const std::string& name() const {
    accessed_ |= (1<<1);
    return name_;
  }
  void set_name(const std::string& v) {
    name_ = v;
  }

  const ResolvedExpr* value() const {
    accessed_ |= (1<<2);
    return value_.get();
  }
  void set_value(std::unique_ptr<const ResolvedExpr> v) {
    value_ = std::move(v);
  }

  std::unique_ptr<const ResolvedExpr> release_value() {
    return std::move(value_);
  }

 protected:
  explicit ResolvedOption(
      const std::string& qualifier,
      const std::string& name,
      std::unique_ptr<const ResolvedExpr> value,
      ConstructorOverload)
      : ResolvedArgument(
            ConstructorOverload::NEW_CONSTRUCTOR),
      qualifier_(qualifier),
      name_(name),
      value_(std::move(value)) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
  std::string GetNameForDebugString() const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  std::string qualifier_;
  std::string name_;
  std::unique_ptr<const ResolvedExpr> value_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedOption> MakeResolvedOption(
    const std::string& qualifier,
    const std::string& name,
    std::unique_ptr<const ResolvedExpr> value) {
  return std::unique_ptr<ResolvedOption>(new ResolvedOption(
        qualifier,
        name,
        std::move(value),
        ResolvedOption::NEW_CONSTRUCTOR));
}

inline std::unique_ptr<ResolvedOption> MakeResolvedOption() {
  return std::unique_ptr<ResolvedOption>(
      new ResolvedOption());
}

// Window partitioning specification for an analytic function call.
//
// PARTITION BY keys in <partition_by_list>.
class ResolvedWindowPartitioning final : public ResolvedArgument {
 public:
  typedef ResolvedArgument SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_WINDOW_PARTITIONING;

  friend std::unique_ptr<ResolvedWindowPartitioning> MakeResolvedWindowPartitioning();
 protected:
  ResolvedWindowPartitioning()
      : ResolvedArgument()
      , partition_by_list_()
      , hint_list_()
  {}
 public:

  ResolvedWindowPartitioning(const ResolvedWindowPartitioning&) = delete;
  ResolvedWindowPartitioning& operator=(const ResolvedWindowPartitioning&) = delete;

  friend std::unique_ptr<ResolvedWindowPartitioning> MakeResolvedWindowPartitioning(
      std::vector<std::unique_ptr<const ResolvedColumnRef>> partition_by_list
  );
  ~ResolvedWindowPartitioning() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_WINDOW_PARTITIONING; }
  std::string node_kind_string() const final { return "WindowPartitioning"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedWindowPartitioningProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedArgumentProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedWindowPartitioning>> RestoreFrom(
      const ResolvedWindowPartitioningProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  const std::vector<std::unique_ptr<const ResolvedColumnRef>>& partition_by_list() const {
    accessed_ |= (1<<0);
    return partition_by_list_;
  }
  int partition_by_list_size() const {
    if (partition_by_list_.empty()) accessed_ |= (1<<0);
    return static_cast<int>(partition_by_list_.size());
  }
  const ResolvedColumnRef* partition_by_list(int i) const {
    accessed_ |= (1<<0);
    return partition_by_list_.at(i).get();
  }
  void add_partition_by_list(std::unique_ptr<const ResolvedColumnRef> v) {
    partition_by_list_.emplace_back(std::move(v));
  }
  void set_partition_by_list(std::vector<std::unique_ptr<const ResolvedColumnRef>> v) {
    partition_by_list_ = std::move(v);
  }

  std::vector<std::unique_ptr<const ResolvedColumnRef>> release_partition_by_list() {
    std::vector<std::unique_ptr<const ResolvedColumnRef>> tmp;
    partition_by_list_.swap(tmp);
    return tmp;
  }

  const std::vector<std::unique_ptr<const ResolvedOption>>& hint_list() const {
    accessed_ |= (1<<1);
    return hint_list_;
  }
  int hint_list_size() const {
    if (hint_list_.empty()) accessed_ |= (1<<1);
    return static_cast<int>(hint_list_.size());
  }
  const ResolvedOption* hint_list(int i) const {
    accessed_ |= (1<<1);
    return hint_list_.at(i).get();
  }
  void add_hint_list(std::unique_ptr<const ResolvedOption> v) {
    hint_list_.emplace_back(std::move(v));
  }
  void set_hint_list(std::vector<std::unique_ptr<const ResolvedOption>> v) {
    hint_list_ = std::move(v);
  }

  std::vector<std::unique_ptr<const ResolvedOption>> release_hint_list() {
    std::vector<std::unique_ptr<const ResolvedOption>> tmp;
    hint_list_.swap(tmp);
    return tmp;
  }

 protected:
  explicit ResolvedWindowPartitioning(
      std::vector<std::unique_ptr<const ResolvedColumnRef>> partition_by_list,
      ConstructorOverload)
      : ResolvedArgument(
            ConstructorOverload::NEW_CONSTRUCTOR),
      partition_by_list_(std::move(partition_by_list)),
      hint_list_() {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  std::vector<std::unique_ptr<const ResolvedColumnRef>> partition_by_list_;
  std::vector<std::unique_ptr<const ResolvedOption>> hint_list_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedWindowPartitioning> MakeResolvedWindowPartitioning(
    std::vector<std::unique_ptr<const ResolvedColumnRef>> partition_by_list) {
  return std::unique_ptr<ResolvedWindowPartitioning>(new ResolvedWindowPartitioning(
        std::move(partition_by_list),
        ResolvedWindowPartitioning::NEW_CONSTRUCTOR));
}

// Overloaded factory method for the construction of ResolvedWindowPartitioning with
// a wider range of inputs for node-vector inputs.  In particular allows:
// 1. unique_ptr element type can be non-const.
// 2. unique_ptr element type can be any descendant of the required type.
// 3. input container can be any object with a `begin()` and `end()`.
//
// Note, initializer lists cannot be used to pass
//  partition_by_list
// due to incompatibility with unique_ptr.  Use zetasql::MakeNodeVector
// instead.
template <
  typename partition_by_list_t
      = std::vector<std::unique_ptr<const ResolvedColumnRef>>>
std::unique_ptr<ResolvedWindowPartitioning> MakeResolvedWindowPartitioning(
    partition_by_list_t partition_by_list) {
  static_assert(std::is_base_of<
      ResolvedColumnRef,
      typename std::decay<decltype(**(partition_by_list.begin()))>::type>::value,
      "partition_by_list must be a container of unique_ptr with elements of type "
      "ResolvedColumnRef (or its descendants).");
  return MakeResolvedWindowPartitioning(
      {std::make_move_iterator(partition_by_list.begin()),
       std::make_move_iterator(partition_by_list.end())});
}

inline std::unique_ptr<ResolvedWindowPartitioning> MakeResolvedWindowPartitioning() {
  return std::unique_ptr<ResolvedWindowPartitioning>(
      new ResolvedWindowPartitioning());
}

// Window ordering specification for an analytic function call.
//
// ORDER BY items in <order_by_list>. There should be exactly one ORDER
// BY item if this is a window ORDER BY for a RANGE-based window.
class ResolvedWindowOrdering final : public ResolvedArgument {
 public:
  typedef ResolvedArgument SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_WINDOW_ORDERING;

  friend std::unique_ptr<ResolvedWindowOrdering> MakeResolvedWindowOrdering();
 protected:
  ResolvedWindowOrdering()
      : ResolvedArgument()
      , order_by_item_list_()
      , hint_list_()
  {}
 public:

  ResolvedWindowOrdering(const ResolvedWindowOrdering&) = delete;
  ResolvedWindowOrdering& operator=(const ResolvedWindowOrdering&) = delete;

  friend std::unique_ptr<ResolvedWindowOrdering> MakeResolvedWindowOrdering(
      std::vector<std::unique_ptr<const ResolvedOrderByItem>> order_by_item_list
  );
  ~ResolvedWindowOrdering() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_WINDOW_ORDERING; }
  std::string node_kind_string() const final { return "WindowOrdering"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedWindowOrderingProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedArgumentProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedWindowOrdering>> RestoreFrom(
      const ResolvedWindowOrderingProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  const std::vector<std::unique_ptr<const ResolvedOrderByItem>>& order_by_item_list() const {
    accessed_ |= (1<<0);
    return order_by_item_list_;
  }
  int order_by_item_list_size() const {
    if (order_by_item_list_.empty()) accessed_ |= (1<<0);
    return static_cast<int>(order_by_item_list_.size());
  }
  const ResolvedOrderByItem* order_by_item_list(int i) const {
    accessed_ |= (1<<0);
    return order_by_item_list_.at(i).get();
  }
  void add_order_by_item_list(std::unique_ptr<const ResolvedOrderByItem> v) {
    order_by_item_list_.emplace_back(std::move(v));
  }
  void set_order_by_item_list(std::vector<std::unique_ptr<const ResolvedOrderByItem>> v) {
    order_by_item_list_ = std::move(v);
  }

  std::vector<std::unique_ptr<const ResolvedOrderByItem>> release_order_by_item_list() {
    std::vector<std::unique_ptr<const ResolvedOrderByItem>> tmp;
    order_by_item_list_.swap(tmp);
    return tmp;
  }

  const std::vector<std::unique_ptr<const ResolvedOption>>& hint_list() const {
    accessed_ |= (1<<1);
    return hint_list_;
  }
  int hint_list_size() const {
    if (hint_list_.empty()) accessed_ |= (1<<1);
    return static_cast<int>(hint_list_.size());
  }
  const ResolvedOption* hint_list(int i) const {
    accessed_ |= (1<<1);
    return hint_list_.at(i).get();
  }
  void add_hint_list(std::unique_ptr<const ResolvedOption> v) {
    hint_list_.emplace_back(std::move(v));
  }
  void set_hint_list(std::vector<std::unique_ptr<const ResolvedOption>> v) {
    hint_list_ = std::move(v);
  }

  std::vector<std::unique_ptr<const ResolvedOption>> release_hint_list() {
    std::vector<std::unique_ptr<const ResolvedOption>> tmp;
    hint_list_.swap(tmp);
    return tmp;
  }

 protected:
  explicit ResolvedWindowOrdering(
      std::vector<std::unique_ptr<const ResolvedOrderByItem>> order_by_item_list,
      ConstructorOverload)
      : ResolvedArgument(
            ConstructorOverload::NEW_CONSTRUCTOR),
      order_by_item_list_(std::move(order_by_item_list)),
      hint_list_() {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  std::vector<std::unique_ptr<const ResolvedOrderByItem>> order_by_item_list_;
  std::vector<std::unique_ptr<const ResolvedOption>> hint_list_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedWindowOrdering> MakeResolvedWindowOrdering(
    std::vector<std::unique_ptr<const ResolvedOrderByItem>> order_by_item_list) {
  return std::unique_ptr<ResolvedWindowOrdering>(new ResolvedWindowOrdering(
        std::move(order_by_item_list),
        ResolvedWindowOrdering::NEW_CONSTRUCTOR));
}

// Overloaded factory method for the construction of ResolvedWindowOrdering with
// a wider range of inputs for node-vector inputs.  In particular allows:
// 1. unique_ptr element type can be non-const.
// 2. unique_ptr element type can be any descendant of the required type.
// 3. input container can be any object with a `begin()` and `end()`.
//
// Note, initializer lists cannot be used to pass
//  order_by_item_list
// due to incompatibility with unique_ptr.  Use zetasql::MakeNodeVector
// instead.
template <
  typename order_by_item_list_t
      = std::vector<std::unique_ptr<const ResolvedOrderByItem>>>
std::unique_ptr<ResolvedWindowOrdering> MakeResolvedWindowOrdering(
    order_by_item_list_t order_by_item_list) {
  static_assert(std::is_base_of<
      ResolvedOrderByItem,
      typename std::decay<decltype(**(order_by_item_list.begin()))>::type>::value,
      "order_by_item_list must be a container of unique_ptr with elements of type "
      "ResolvedOrderByItem (or its descendants).");
  return MakeResolvedWindowOrdering(
      {std::make_move_iterator(order_by_item_list.begin()),
       std::make_move_iterator(order_by_item_list.end())});
}

inline std::unique_ptr<ResolvedWindowOrdering> MakeResolvedWindowOrdering() {
  return std::unique_ptr<ResolvedWindowOrdering>(
      new ResolvedWindowOrdering());
}

// Window framing specification for an analytic function call.
//
// ROW-based window frames compute the frame based on physical offsets
// from the current row.
// RANGE-based window frames compute the frame based on a logical
// range of rows around the current row based on the current row's
// ORDER BY key value.
//
// <start_expr> and <end_expr> cannot be NULL. If the window frame
// is one-sided in the input query, the resolver will generate an
// implicit ending boundary.
class ResolvedWindowFrame final : public ResolvedArgument {
 public:
  typedef ResolvedArgument SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_WINDOW_FRAME;

  typedef ResolvedWindowFrameEnums::FrameUnit FrameUnit;
  static const FrameUnit ROWS = ResolvedWindowFrameEnums::ROWS;
  static const FrameUnit RANGE = ResolvedWindowFrameEnums::RANGE;

  std::string GetFrameUnitString() const;
  static std::string FrameUnitToString(FrameUnit frame_unit);

  friend std::unique_ptr<ResolvedWindowFrame> MakeResolvedWindowFrame();
 protected:
  ResolvedWindowFrame()
      : ResolvedArgument()
      , frame_unit_()
      , start_expr_()
      , end_expr_()
  {}
 public:

  ResolvedWindowFrame(const ResolvedWindowFrame&) = delete;
  ResolvedWindowFrame& operator=(const ResolvedWindowFrame&) = delete;

  friend std::unique_ptr<ResolvedWindowFrame> MakeResolvedWindowFrame(
      FrameUnit frame_unit,
      std::unique_ptr<const ResolvedWindowFrameExpr> start_expr,
      std::unique_ptr<const ResolvedWindowFrameExpr> end_expr
  );
  ~ResolvedWindowFrame() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_WINDOW_FRAME; }
  std::string node_kind_string() const final { return "WindowFrame"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedWindowFrameProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedArgumentProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedWindowFrame>> RestoreFrom(
      const ResolvedWindowFrameProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  FrameUnit frame_unit() const {
    accessed_ |= (1<<0);
    return frame_unit_;
  }
  void set_frame_unit(FrameUnit v) {
    frame_unit_ = v;
  }

  const ResolvedWindowFrameExpr* start_expr() const {
    accessed_ |= (1<<1);
    return start_expr_.get();
  }
  void set_start_expr(std::unique_ptr<const ResolvedWindowFrameExpr> v) {
    start_expr_ = std::move(v);
  }

  std::unique_ptr<const ResolvedWindowFrameExpr> release_start_expr() {
    return std::move(start_expr_);
  }

  const ResolvedWindowFrameExpr* end_expr() const {
    accessed_ |= (1<<2);
    return end_expr_.get();
  }
  void set_end_expr(std::unique_ptr<const ResolvedWindowFrameExpr> v) {
    end_expr_ = std::move(v);
  }

  std::unique_ptr<const ResolvedWindowFrameExpr> release_end_expr() {
    return std::move(end_expr_);
  }

 protected:
  explicit ResolvedWindowFrame(
      FrameUnit frame_unit,
      std::unique_ptr<const ResolvedWindowFrameExpr> start_expr,
      std::unique_ptr<const ResolvedWindowFrameExpr> end_expr,
      ConstructorOverload)
      : ResolvedArgument(
            ConstructorOverload::NEW_CONSTRUCTOR),
      frame_unit_(frame_unit),
      start_expr_(std::move(start_expr)),
      end_expr_(std::move(end_expr)) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
  std::string GetNameForDebugString() const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  FrameUnit frame_unit_;
  std::unique_ptr<const ResolvedWindowFrameExpr> start_expr_;
  std::unique_ptr<const ResolvedWindowFrameExpr> end_expr_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedWindowFrame> MakeResolvedWindowFrame(
    ResolvedWindowFrame::FrameUnit frame_unit,
    std::unique_ptr<const ResolvedWindowFrameExpr> start_expr,
    std::unique_ptr<const ResolvedWindowFrameExpr> end_expr) {
  return std::unique_ptr<ResolvedWindowFrame>(new ResolvedWindowFrame(
        frame_unit,
        std::move(start_expr),
        std::move(end_expr),
        ResolvedWindowFrame::NEW_CONSTRUCTOR));
}

inline std::unique_ptr<ResolvedWindowFrame> MakeResolvedWindowFrame() {
  return std::unique_ptr<ResolvedWindowFrame>(
      new ResolvedWindowFrame());
}

// This represents a group of analytic function calls that shares PARTITION
// BY and ORDER BY.
//
// <partition_by> can be NULL. <order_by> may be NULL depending on the
// functions in <analytic_function_list> and the window frame unit. See
// (broken link) for more details.
//
// All expressions in <analytic_function_list> have a
// ResolvedAggregateFunctionCall with a function in mode
// Function::AGGREGATE or Function::ANALYTIC.
class ResolvedAnalyticFunctionGroup final : public ResolvedArgument {
 public:
  typedef ResolvedArgument SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_ANALYTIC_FUNCTION_GROUP;

  friend std::unique_ptr<ResolvedAnalyticFunctionGroup> MakeResolvedAnalyticFunctionGroup();
 protected:
  ResolvedAnalyticFunctionGroup()
      : ResolvedArgument()
      , partition_by_()
      , order_by_()
      , analytic_function_list_()
  {}
 public:

  ResolvedAnalyticFunctionGroup(const ResolvedAnalyticFunctionGroup&) = delete;
  ResolvedAnalyticFunctionGroup& operator=(const ResolvedAnalyticFunctionGroup&) = delete;

  friend std::unique_ptr<ResolvedAnalyticFunctionGroup> MakeResolvedAnalyticFunctionGroup(
      std::unique_ptr<const ResolvedWindowPartitioning> partition_by,
      std::unique_ptr<const ResolvedWindowOrdering> order_by,
      std::vector<std::unique_ptr<const ResolvedComputedColumn>> analytic_function_list
  );
  ~ResolvedAnalyticFunctionGroup() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_ANALYTIC_FUNCTION_GROUP; }
  std::string node_kind_string() const final { return "AnalyticFunctionGroup"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedAnalyticFunctionGroupProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedArgumentProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedAnalyticFunctionGroup>> RestoreFrom(
      const ResolvedAnalyticFunctionGroupProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  const ResolvedWindowPartitioning* partition_by() const {
    accessed_ |= (1<<0);
    return partition_by_.get();
  }
  void set_partition_by(std::unique_ptr<const ResolvedWindowPartitioning> v) {
    partition_by_ = std::move(v);
  }

  std::unique_ptr<const ResolvedWindowPartitioning> release_partition_by() {
    return std::move(partition_by_);
  }

  const ResolvedWindowOrdering* order_by() const {
    accessed_ |= (1<<1);
    return order_by_.get();
  }
  void set_order_by(std::unique_ptr<const ResolvedWindowOrdering> v) {
    order_by_ = std::move(v);
  }

  std::unique_ptr<const ResolvedWindowOrdering> release_order_by() {
    return std::move(order_by_);
  }

  const std::vector<std::unique_ptr<const ResolvedComputedColumn>>& analytic_function_list() const {
    accessed_ |= (1<<2);
    return analytic_function_list_;
  }
  int analytic_function_list_size() const {
    if (analytic_function_list_.empty()) accessed_ |= (1<<2);
    return static_cast<int>(analytic_function_list_.size());
  }
  const ResolvedComputedColumn* analytic_function_list(int i) const {
    accessed_ |= (1<<2);
    return analytic_function_list_.at(i).get();
  }
  void add_analytic_function_list(std::unique_ptr<const ResolvedComputedColumn> v) {
    analytic_function_list_.emplace_back(std::move(v));
  }
  void set_analytic_function_list(std::vector<std::unique_ptr<const ResolvedComputedColumn>> v) {
    analytic_function_list_ = std::move(v);
  }

  std::vector<std::unique_ptr<const ResolvedComputedColumn>> release_analytic_function_list() {
    std::vector<std::unique_ptr<const ResolvedComputedColumn>> tmp;
    analytic_function_list_.swap(tmp);
    return tmp;
  }

 protected:
  explicit ResolvedAnalyticFunctionGroup(
      std::unique_ptr<const ResolvedWindowPartitioning> partition_by,
      std::unique_ptr<const ResolvedWindowOrdering> order_by,
      std::vector<std::unique_ptr<const ResolvedComputedColumn>> analytic_function_list,
      ConstructorOverload)
      : ResolvedArgument(
            ConstructorOverload::NEW_CONSTRUCTOR),
      partition_by_(std::move(partition_by)),
      order_by_(std::move(order_by)),
      analytic_function_list_(std::move(analytic_function_list)) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  std::unique_ptr<const ResolvedWindowPartitioning> partition_by_;
  std::unique_ptr<const ResolvedWindowOrdering> order_by_;
  std::vector<std::unique_ptr<const ResolvedComputedColumn>> analytic_function_list_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedAnalyticFunctionGroup> MakeResolvedAnalyticFunctionGroup(
    std::unique_ptr<const ResolvedWindowPartitioning> partition_by,
    std::unique_ptr<const ResolvedWindowOrdering> order_by,
    std::vector<std::unique_ptr<const ResolvedComputedColumn>> analytic_function_list) {
  return std::unique_ptr<ResolvedAnalyticFunctionGroup>(new ResolvedAnalyticFunctionGroup(
        std::move(partition_by),
        std::move(order_by),
        std::move(analytic_function_list),
        ResolvedAnalyticFunctionGroup::NEW_CONSTRUCTOR));
}

// Overloaded factory method for the construction of ResolvedAnalyticFunctionGroup with
// a wider range of inputs for node-vector inputs.  In particular allows:
// 1. unique_ptr element type can be non-const.
// 2. unique_ptr element type can be any descendant of the required type.
// 3. input container can be any object with a `begin()` and `end()`.
//
// Note, initializer lists cannot be used to pass
//  analytic_function_list
// due to incompatibility with unique_ptr.  Use zetasql::MakeNodeVector
// instead.
template <
  typename analytic_function_list_t
      = std::vector<std::unique_ptr<const ResolvedComputedColumn>>>
std::unique_ptr<ResolvedAnalyticFunctionGroup> MakeResolvedAnalyticFunctionGroup(
    std::unique_ptr<const ResolvedWindowPartitioning> partition_by,
    std::unique_ptr<const ResolvedWindowOrdering> order_by,
    analytic_function_list_t analytic_function_list) {
  static_assert(std::is_base_of<
      ResolvedComputedColumn,
      typename std::decay<decltype(**(analytic_function_list.begin()))>::type>::value,
      "analytic_function_list must be a container of unique_ptr with elements of type "
      "ResolvedComputedColumn (or its descendants).");
  return MakeResolvedAnalyticFunctionGroup(
      std::move(partition_by),
      std::move(order_by),
      {std::make_move_iterator(analytic_function_list.begin()),
       std::make_move_iterator(analytic_function_list.end())});
}

inline std::unique_ptr<ResolvedAnalyticFunctionGroup> MakeResolvedAnalyticFunctionGroup() {
  return std::unique_ptr<ResolvedAnalyticFunctionGroup>(
      new ResolvedAnalyticFunctionGroup());
}

// Window frame boundary expression that determines the first/last row of
// the moving window for each tuple.
//
// <expression> cannot be NULL if the type is OFFSET_PRECEDING
// or OFFSET_FOLLOWING. It must be a constant expression. If this is a
// boundary for a ROW-based window, it must be integer type. Otherwise,
// it must be numeric type and must match exactly the type of the window
// ordering expression.  See (broken link) for more
// details.
class ResolvedWindowFrameExpr final : public ResolvedArgument {
 public:
  typedef ResolvedArgument SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_WINDOW_FRAME_EXPR;

  typedef ResolvedWindowFrameExprEnums::BoundaryType BoundaryType;
  static const BoundaryType UNBOUNDED_PRECEDING = ResolvedWindowFrameExprEnums::UNBOUNDED_PRECEDING;
  static const BoundaryType OFFSET_PRECEDING = ResolvedWindowFrameExprEnums::OFFSET_PRECEDING;
  static const BoundaryType CURRENT_ROW = ResolvedWindowFrameExprEnums::CURRENT_ROW;
  static const BoundaryType OFFSET_FOLLOWING = ResolvedWindowFrameExprEnums::OFFSET_FOLLOWING;
  static const BoundaryType UNBOUNDED_FOLLOWING = ResolvedWindowFrameExprEnums::UNBOUNDED_FOLLOWING;

  std::string GetBoundaryTypeString() const;
  static std::string BoundaryTypeToString(BoundaryType boundary_type);

  friend std::unique_ptr<ResolvedWindowFrameExpr> MakeResolvedWindowFrameExpr();
 protected:
  ResolvedWindowFrameExpr()
      : ResolvedArgument()
      , boundary_type_()
      , expression_()
  {}
 public:

  ResolvedWindowFrameExpr(const ResolvedWindowFrameExpr&) = delete;
  ResolvedWindowFrameExpr& operator=(const ResolvedWindowFrameExpr&) = delete;

  friend std::unique_ptr<ResolvedWindowFrameExpr> MakeResolvedWindowFrameExpr(
      BoundaryType boundary_type,
      std::unique_ptr<const ResolvedExpr> expression
  );
  ~ResolvedWindowFrameExpr() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_WINDOW_FRAME_EXPR; }
  std::string node_kind_string() const final { return "WindowFrameExpr"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedWindowFrameExprProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedArgumentProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedWindowFrameExpr>> RestoreFrom(
      const ResolvedWindowFrameExprProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  BoundaryType boundary_type() const {
    accessed_ |= (1<<0);
    return boundary_type_;
  }
  void set_boundary_type(BoundaryType v) {
    boundary_type_ = v;
  }

  const ResolvedExpr* expression() const {
    accessed_ |= (1<<1);
    return expression_.get();
  }
  void set_expression(std::unique_ptr<const ResolvedExpr> v) {
    expression_ = std::move(v);
  }

  std::unique_ptr<const ResolvedExpr> release_expression() {
    return std::move(expression_);
  }

 protected:
  explicit ResolvedWindowFrameExpr(
      BoundaryType boundary_type,
      std::unique_ptr<const ResolvedExpr> expression,
      ConstructorOverload)
      : ResolvedArgument(
            ConstructorOverload::NEW_CONSTRUCTOR),
      boundary_type_(boundary_type),
      expression_(std::move(expression)) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
  std::string GetNameForDebugString() const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  BoundaryType boundary_type_;
  std::unique_ptr<const ResolvedExpr> expression_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedWindowFrameExpr> MakeResolvedWindowFrameExpr(
    ResolvedWindowFrameExpr::BoundaryType boundary_type,
    std::unique_ptr<const ResolvedExpr> expression) {
  return std::unique_ptr<ResolvedWindowFrameExpr>(new ResolvedWindowFrameExpr(
        boundary_type,
        std::move(expression),
        ResolvedWindowFrameExpr::NEW_CONSTRUCTOR));
}

inline std::unique_ptr<ResolvedWindowFrameExpr> MakeResolvedWindowFrameExpr() {
  return std::unique_ptr<ResolvedWindowFrameExpr>(
      new ResolvedWindowFrameExpr());
}

// This represents a value inside an INSERT or UPDATE statement.
//
// The <value> is either an expression or a DMLDefault.
//
// For proto fields, NULL values mean the field should be cleared.
class ResolvedDMLValue final : public ResolvedArgument {
 public:
  typedef ResolvedArgument SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_DMLVALUE;

  friend std::unique_ptr<ResolvedDMLValue> MakeResolvedDMLValue();
 protected:
  ResolvedDMLValue()
      : ResolvedArgument()
      , value_()
  {}
 public:

  ResolvedDMLValue(const ResolvedDMLValue&) = delete;
  ResolvedDMLValue& operator=(const ResolvedDMLValue&) = delete;

  friend std::unique_ptr<ResolvedDMLValue> MakeResolvedDMLValue(
      std::unique_ptr<const ResolvedExpr> value
  );
  ~ResolvedDMLValue() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_DMLVALUE; }
  std::string node_kind_string() const final { return "DMLValue"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedDMLValueProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedArgumentProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedDMLValue>> RestoreFrom(
      const ResolvedDMLValueProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  const ResolvedExpr* value() const {
    accessed_ |= (1<<0);
    return value_.get();
  }
  void set_value(std::unique_ptr<const ResolvedExpr> v) {
    value_ = std::move(v);
  }

  std::unique_ptr<const ResolvedExpr> release_value() {
    return std::move(value_);
  }

 protected:
  explicit ResolvedDMLValue(
      std::unique_ptr<const ResolvedExpr> value,
      ConstructorOverload)
      : ResolvedArgument(
            ConstructorOverload::NEW_CONSTRUCTOR),
      value_(std::move(value)) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  std::unique_ptr<const ResolvedExpr> value_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedDMLValue> MakeResolvedDMLValue(
    std::unique_ptr<const ResolvedExpr> value) {
  return std::unique_ptr<ResolvedDMLValue>(new ResolvedDMLValue(
        std::move(value),
        ResolvedDMLValue::NEW_CONSTRUCTOR));
}

inline std::unique_ptr<ResolvedDMLValue> MakeResolvedDMLValue() {
  return std::unique_ptr<ResolvedDMLValue>(
      new ResolvedDMLValue());
}

// This is used to represent the value DEFAULT that shows up (in place of a
// value expression) in INSERT and UPDATE statements.
// For columns, engines should substitute the engine-defined default value
// for that column, or give an error.
// For proto fields, this always means to clear the field.
// This will never show up inside expressions other than ResolvedDMLValue.
class ResolvedDMLDefault final : public ResolvedExpr {
 public:
  typedef ResolvedExpr SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_DMLDEFAULT;

  friend std::unique_ptr<ResolvedDMLDefault> MakeResolvedDMLDefault();
 protected:
  ResolvedDMLDefault()
      : ResolvedExpr()
  {}
 public:

  ResolvedDMLDefault(const ResolvedDMLDefault&) = delete;
  ResolvedDMLDefault& operator=(const ResolvedDMLDefault&) = delete;

  friend std::unique_ptr<ResolvedDMLDefault> MakeResolvedDMLDefault(
      const Type* type
  );
  ~ResolvedDMLDefault() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_DMLDEFAULT; }
  std::string node_kind_string() const final { return "DMLDefault"; }

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedDMLDefaultProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedExprProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedDMLDefault>> RestoreFrom(
      const ResolvedDMLDefaultProto& proto,
      const ResolvedNode::RestoreParams& params);

  // Member fields

 protected:
  explicit ResolvedDMLDefault(
      const Type* type,
      ConstructorOverload)
      : ResolvedExpr(
            type,
            ConstructorOverload::NEW_CONSTRUCTOR) {
  }

 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

};

inline std::unique_ptr<ResolvedDMLDefault> MakeResolvedDMLDefault(
    const Type* type) {
  return std::unique_ptr<ResolvedDMLDefault>(new ResolvedDMLDefault(
        type,
        ResolvedDMLDefault::NEW_CONSTRUCTOR));
}

inline std::unique_ptr<ResolvedDMLDefault> MakeResolvedDMLDefault() {
  return std::unique_ptr<ResolvedDMLDefault>(
      new ResolvedDMLDefault());
}

// This represents the ASSERT statement:
//   ASSERT <expression> [AS <description>];
//
// <expression> is any expression that returns a bool.
// <description> is an optional string literal used to give a more
// descriptive error message in case the ASSERT fails.
class ResolvedAssertStmt final : public ResolvedStatement {
 public:
  typedef ResolvedStatement SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_ASSERT_STMT;

  friend std::unique_ptr<ResolvedAssertStmt> MakeResolvedAssertStmt();
 protected:
  ResolvedAssertStmt()
      : ResolvedStatement()
      , expression_()
      , description_()
  {}
 public:

  ResolvedAssertStmt(const ResolvedAssertStmt&) = delete;
  ResolvedAssertStmt& operator=(const ResolvedAssertStmt&) = delete;

  friend std::unique_ptr<ResolvedAssertStmt> MakeResolvedAssertStmt(
      std::unique_ptr<const ResolvedExpr> expression,
      const std::string& description
  );
  ~ResolvedAssertStmt() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_ASSERT_STMT; }
  std::string node_kind_string() const final { return "AssertStmt"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedAssertStmtProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedStatementProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedAssertStmt>> RestoreFrom(
      const ResolvedAssertStmtProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  const ResolvedExpr* expression() const {
    accessed_ |= (1<<0);
    return expression_.get();
  }
  void set_expression(std::unique_ptr<const ResolvedExpr> v) {
    expression_ = std::move(v);
  }

  std::unique_ptr<const ResolvedExpr> release_expression() {
    return std::move(expression_);
  }

  const std::string& description() const {
    accessed_ |= (1<<1);
    return description_;
  }
  void set_description(const std::string& v) {
    description_ = v;
  }

 protected:
  explicit ResolvedAssertStmt(
      std::unique_ptr<const ResolvedExpr> expression,
      const std::string& description,
      ConstructorOverload)
      : ResolvedStatement(
            ConstructorOverload::NEW_CONSTRUCTOR),
      expression_(std::move(expression)),
      description_(description) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  std::unique_ptr<const ResolvedExpr> expression_;
  std::string description_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedAssertStmt> MakeResolvedAssertStmt(
    std::unique_ptr<const ResolvedExpr> expression,
    const std::string& description) {
  return std::unique_ptr<ResolvedAssertStmt>(new ResolvedAssertStmt(
        std::move(expression),
        description,
        ResolvedAssertStmt::NEW_CONSTRUCTOR));
}

inline std::unique_ptr<ResolvedAssertStmt> MakeResolvedAssertStmt() {
  return std::unique_ptr<ResolvedAssertStmt>(
      new ResolvedAssertStmt());
}

// This represents the ASSERT ROWS MODIFIED clause on a DML statement.
// The value must be a literal or (possibly casted) parameter int64.
//
// The statement should fail if the number of rows updated does not
// exactly match this number.
class ResolvedAssertRowsModified final : public ResolvedArgument {
 public:
  typedef ResolvedArgument SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_ASSERT_ROWS_MODIFIED;

  friend std::unique_ptr<ResolvedAssertRowsModified> MakeResolvedAssertRowsModified();
 protected:
  ResolvedAssertRowsModified()
      : ResolvedArgument()
      , rows_()
  {}
 public:

  ResolvedAssertRowsModified(const ResolvedAssertRowsModified&) = delete;
  ResolvedAssertRowsModified& operator=(const ResolvedAssertRowsModified&) = delete;

  friend std::unique_ptr<ResolvedAssertRowsModified> MakeResolvedAssertRowsModified(
      std::unique_ptr<const ResolvedExpr> rows
  );
  ~ResolvedAssertRowsModified() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_ASSERT_ROWS_MODIFIED; }
  std::string node_kind_string() const final { return "AssertRowsModified"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedAssertRowsModifiedProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedArgumentProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedAssertRowsModified>> RestoreFrom(
      const ResolvedAssertRowsModifiedProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  const ResolvedExpr* rows() const {
    accessed_ |= (1<<0);
    return rows_.get();
  }
  void set_rows(std::unique_ptr<const ResolvedExpr> v) {
    rows_ = std::move(v);
  }

  std::unique_ptr<const ResolvedExpr> release_rows() {
    return std::move(rows_);
  }

 protected:
  explicit ResolvedAssertRowsModified(
      std::unique_ptr<const ResolvedExpr> rows,
      ConstructorOverload)
      : ResolvedArgument(
            ConstructorOverload::NEW_CONSTRUCTOR),
      rows_(std::move(rows)) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  std::unique_ptr<const ResolvedExpr> rows_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedAssertRowsModified> MakeResolvedAssertRowsModified(
    std::unique_ptr<const ResolvedExpr> rows) {
  return std::unique_ptr<ResolvedAssertRowsModified>(new ResolvedAssertRowsModified(
        std::move(rows),
        ResolvedAssertRowsModified::NEW_CONSTRUCTOR));
}

inline std::unique_ptr<ResolvedAssertRowsModified> MakeResolvedAssertRowsModified() {
  return std::unique_ptr<ResolvedAssertRowsModified>(
      new ResolvedAssertRowsModified());
}

// This represents one row in the VALUES clause of an INSERT.
class ResolvedInsertRow final : public ResolvedArgument {
 public:
  typedef ResolvedArgument SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_INSERT_ROW;

  friend std::unique_ptr<ResolvedInsertRow> MakeResolvedInsertRow();
 protected:
  ResolvedInsertRow()
      : ResolvedArgument()
      , value_list_()
  {}
 public:

  ResolvedInsertRow(const ResolvedInsertRow&) = delete;
  ResolvedInsertRow& operator=(const ResolvedInsertRow&) = delete;

  friend std::unique_ptr<ResolvedInsertRow> MakeResolvedInsertRow(
      std::vector<std::unique_ptr<const ResolvedDMLValue>> value_list
  );
  ~ResolvedInsertRow() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_INSERT_ROW; }
  std::string node_kind_string() const final { return "InsertRow"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedInsertRowProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedArgumentProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedInsertRow>> RestoreFrom(
      const ResolvedInsertRowProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  const std::vector<std::unique_ptr<const ResolvedDMLValue>>& value_list() const {
    accessed_ |= (1<<0);
    return value_list_;
  }
  int value_list_size() const {
    if (value_list_.empty()) accessed_ |= (1<<0);
    return static_cast<int>(value_list_.size());
  }
  const ResolvedDMLValue* value_list(int i) const {
    accessed_ |= (1<<0);
    return value_list_.at(i).get();
  }
  void add_value_list(std::unique_ptr<const ResolvedDMLValue> v) {
    value_list_.emplace_back(std::move(v));
  }
  void set_value_list(std::vector<std::unique_ptr<const ResolvedDMLValue>> v) {
    value_list_ = std::move(v);
  }

  std::vector<std::unique_ptr<const ResolvedDMLValue>> release_value_list() {
    std::vector<std::unique_ptr<const ResolvedDMLValue>> tmp;
    value_list_.swap(tmp);
    return tmp;
  }

 protected:
  explicit ResolvedInsertRow(
      std::vector<std::unique_ptr<const ResolvedDMLValue>> value_list,
      ConstructorOverload)
      : ResolvedArgument(
            ConstructorOverload::NEW_CONSTRUCTOR),
      value_list_(std::move(value_list)) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  std::vector<std::unique_ptr<const ResolvedDMLValue>> value_list_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedInsertRow> MakeResolvedInsertRow(
    std::vector<std::unique_ptr<const ResolvedDMLValue>> value_list) {
  return std::unique_ptr<ResolvedInsertRow>(new ResolvedInsertRow(
        std::move(value_list),
        ResolvedInsertRow::NEW_CONSTRUCTOR));
}

// Overloaded factory method for the construction of ResolvedInsertRow with
// a wider range of inputs for node-vector inputs.  In particular allows:
// 1. unique_ptr element type can be non-const.
// 2. unique_ptr element type can be any descendant of the required type.
// 3. input container can be any object with a `begin()` and `end()`.
//
// Note, initializer lists cannot be used to pass
//  value_list
// due to incompatibility with unique_ptr.  Use zetasql::MakeNodeVector
// instead.
template <
  typename value_list_t
      = std::vector<std::unique_ptr<const ResolvedDMLValue>>>
std::unique_ptr<ResolvedInsertRow> MakeResolvedInsertRow(
    value_list_t value_list) {
  static_assert(std::is_base_of<
      ResolvedDMLValue,
      typename std::decay<decltype(**(value_list.begin()))>::type>::value,
      "value_list must be a container of unique_ptr with elements of type "
      "ResolvedDMLValue (or its descendants).");
  return MakeResolvedInsertRow(
      {std::make_move_iterator(value_list.begin()),
       std::make_move_iterator(value_list.end())});
}

inline std::unique_ptr<ResolvedInsertRow> MakeResolvedInsertRow() {
  return std::unique_ptr<ResolvedInsertRow>(
      new ResolvedInsertRow());
}

// This represents an INSERT statement, or a nested INSERT inside an
// UPDATE statement.
//
// For top-level INSERT statements, <table_scan> gives the table to
// scan and creates ResolvedColumns for its columns.  Those columns can be
// referenced in <insert_column_list>.
//
// For nested INSERTS, there is no <table_scan> or <insert_column_list>.
// There is implicitly a single column to insert, and its type is the
// element type of the array being updated in the ResolvedUpdateItem
// containing this statement.
//
// For nested INSERTs, alternate modes are not supported and <insert_mode>
// will always be set to OR_ERROR.
//
// The rows to insert come from <row_list> or the result of <query>.
// Exactly one of these must be present.
//
// If <row_list> is present, the columns in the row_list match
// positionally with <insert_column_list>.
//
// If <query> is present, <query_output_column_list> must also be present.
// <query_output_column_list> is the list of output columns produced by
// <query> that correspond positionally with the target <insert_column_list>
// on the output table.  For nested INSERTs with no <insert_column_list>,
// <query_output_column_list> must have exactly one column.
//
// <query_parameter_list> is set for nested INSERTs where <query> is set and
// references non-target values (columns or field values) from the table. It
// is only set when FEATURE_V_1_2_CORRELATED_REFS_IN_NESTED_DML is enabled.
class ResolvedInsertStmt final : public ResolvedStatement {
 public:
  typedef ResolvedStatement SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_INSERT_STMT;

  typedef ResolvedInsertStmtEnums::InsertMode InsertMode;
  static const InsertMode OR_ERROR = ResolvedInsertStmtEnums::OR_ERROR;
  static const InsertMode OR_IGNORE = ResolvedInsertStmtEnums::OR_IGNORE;
  static const InsertMode OR_REPLACE = ResolvedInsertStmtEnums::OR_REPLACE;
  static const InsertMode OR_UPDATE = ResolvedInsertStmtEnums::OR_UPDATE;

  std::string GetInsertModeString() const;
  static std::string InsertModeToString(InsertMode boundary_type);

  friend std::unique_ptr<ResolvedInsertStmt> MakeResolvedInsertStmt();
 protected:
  ResolvedInsertStmt()
      : ResolvedStatement()
      , table_scan_()
      , insert_mode_()
      , assert_rows_modified_()
      , insert_column_list_()
      , query_parameter_list_()
      , query_()
      , query_output_column_list_()
      , row_list_()
  {}
 public:

  ResolvedInsertStmt(const ResolvedInsertStmt&) = delete;
  ResolvedInsertStmt& operator=(const ResolvedInsertStmt&) = delete;

  friend std::unique_ptr<ResolvedInsertStmt> MakeResolvedInsertStmt(
      std::unique_ptr<const ResolvedTableScan> table_scan,
      InsertMode insert_mode,
      std::unique_ptr<const ResolvedAssertRowsModified> assert_rows_modified,
      const std::vector<ResolvedColumn>& insert_column_list,
      std::vector<std::unique_ptr<const ResolvedColumnRef>> query_parameter_list,
      std::unique_ptr<const ResolvedScan> query,
      const std::vector<ResolvedColumn>& query_output_column_list,
      std::vector<std::unique_ptr<const ResolvedInsertRow>> row_list
  );
  ~ResolvedInsertStmt() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_INSERT_STMT; }
  std::string node_kind_string() const final { return "InsertStmt"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedInsertStmtProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedStatementProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedInsertStmt>> RestoreFrom(
      const ResolvedInsertStmtProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  const ResolvedTableScan* table_scan() const {
    accessed_ |= (1<<0);
    return table_scan_.get();
  }
  void set_table_scan(std::unique_ptr<const ResolvedTableScan> v) {
    table_scan_ = std::move(v);
  }

  std::unique_ptr<const ResolvedTableScan> release_table_scan() {
    return std::move(table_scan_);
  }

  // Behavior on duplicate rows (normally defined to mean duplicate
  // primary keys).
  InsertMode insert_mode() const {
    accessed_ |= (1<<1);
    return insert_mode_;
  }
  void set_insert_mode(InsertMode v) {
    insert_mode_ = v;
  }

  const ResolvedAssertRowsModified* assert_rows_modified() const {
    accessed_ |= (1<<2);
    return assert_rows_modified_.get();
  }
  void set_assert_rows_modified(std::unique_ptr<const ResolvedAssertRowsModified> v) {
    assert_rows_modified_ = std::move(v);
  }

  std::unique_ptr<const ResolvedAssertRowsModified> release_assert_rows_modified() {
    return std::move(assert_rows_modified_);
  }

  const std::vector<ResolvedColumn>& insert_column_list() const {
    accessed_ |= (1<<3);
    return insert_column_list_;
  }
  int insert_column_list_size() const {
    if (insert_column_list_.empty()) accessed_ |= (1<<3);
    return static_cast<int>(insert_column_list_.size());
  }
  ResolvedColumn insert_column_list(int i) const {
    accessed_ |= (1<<3);
    return insert_column_list_.at(i);
  }
  void add_insert_column_list(ResolvedColumn v) {
    insert_column_list_.push_back(ResolvedColumn(v));
  }
  void set_insert_column_list(const std::vector<ResolvedColumn>& v) {
    insert_column_list_ = v;
  }
  std::vector<ResolvedColumn>* mutable_insert_column_list() {
    accessed_ |= (1<<3);
    return &insert_column_list_;
  }

  const std::vector<std::unique_ptr<const ResolvedColumnRef>>& query_parameter_list() const {
    accessed_ |= (1<<4);
    return query_parameter_list_;
  }
  int query_parameter_list_size() const {
    if (query_parameter_list_.empty()) accessed_ |= (1<<4);
    return static_cast<int>(query_parameter_list_.size());
  }
  const ResolvedColumnRef* query_parameter_list(int i) const {
    accessed_ |= (1<<4);
    return query_parameter_list_.at(i).get();
  }
  void add_query_parameter_list(std::unique_ptr<const ResolvedColumnRef> v) {
    query_parameter_list_.emplace_back(std::move(v));
  }
  void set_query_parameter_list(std::vector<std::unique_ptr<const ResolvedColumnRef>> v) {
    query_parameter_list_ = std::move(v);
  }

  std::vector<std::unique_ptr<const ResolvedColumnRef>> release_query_parameter_list() {
    std::vector<std::unique_ptr<const ResolvedColumnRef>> tmp;
    query_parameter_list_.swap(tmp);
    return tmp;
  }

  const ResolvedScan* query() const {
    accessed_ |= (1<<5);
    return query_.get();
  }
  void set_query(std::unique_ptr<const ResolvedScan> v) {
    query_ = std::move(v);
  }

  std::unique_ptr<const ResolvedScan> release_query() {
    return std::move(query_);
  }

  const std::vector<ResolvedColumn>& query_output_column_list() const {
    accessed_ |= (1<<6);
    return query_output_column_list_;
  }
  int query_output_column_list_size() const {
    if (query_output_column_list_.empty()) accessed_ |= (1<<6);
    return static_cast<int>(query_output_column_list_.size());
  }
  ResolvedColumn query_output_column_list(int i) const {
    accessed_ |= (1<<6);
    return query_output_column_list_.at(i);
  }
  void add_query_output_column_list(ResolvedColumn v) {
    query_output_column_list_.push_back(ResolvedColumn(v));
  }
  void set_query_output_column_list(const std::vector<ResolvedColumn>& v) {
    query_output_column_list_ = v;
  }
  std::vector<ResolvedColumn>* mutable_query_output_column_list() {
    accessed_ |= (1<<6);
    return &query_output_column_list_;
  }

  const std::vector<std::unique_ptr<const ResolvedInsertRow>>& row_list() const {
    accessed_ |= (1<<7);
    return row_list_;
  }
  int row_list_size() const {
    if (row_list_.empty()) accessed_ |= (1<<7);
    return static_cast<int>(row_list_.size());
  }
  const ResolvedInsertRow* row_list(int i) const {
    accessed_ |= (1<<7);
    return row_list_.at(i).get();
  }
  void add_row_list(std::unique_ptr<const ResolvedInsertRow> v) {
    row_list_.emplace_back(std::move(v));
  }
  void set_row_list(std::vector<std::unique_ptr<const ResolvedInsertRow>> v) {
    row_list_ = std::move(v);
  }

  std::vector<std::unique_ptr<const ResolvedInsertRow>> release_row_list() {
    std::vector<std::unique_ptr<const ResolvedInsertRow>> tmp;
    row_list_.swap(tmp);
    return tmp;
  }

 protected:
  explicit ResolvedInsertStmt(
      std::unique_ptr<const ResolvedTableScan> table_scan,
      InsertMode insert_mode,
      std::unique_ptr<const ResolvedAssertRowsModified> assert_rows_modified,
      const std::vector<ResolvedColumn>& insert_column_list,
      std::vector<std::unique_ptr<const ResolvedColumnRef>> query_parameter_list,
      std::unique_ptr<const ResolvedScan> query,
      const std::vector<ResolvedColumn>& query_output_column_list,
      std::vector<std::unique_ptr<const ResolvedInsertRow>> row_list,
      ConstructorOverload)
      : ResolvedStatement(
            ConstructorOverload::NEW_CONSTRUCTOR),
      table_scan_(std::move(table_scan)),
      insert_mode_(insert_mode),
      assert_rows_modified_(std::move(assert_rows_modified)),
      insert_column_list_(insert_column_list),
      query_parameter_list_(std::move(query_parameter_list)),
      query_(std::move(query)),
      query_output_column_list_(query_output_column_list),
      row_list_(std::move(row_list)) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  std::unique_ptr<const ResolvedTableScan> table_scan_;
  InsertMode insert_mode_;
  std::unique_ptr<const ResolvedAssertRowsModified> assert_rows_modified_;
  std::vector<ResolvedColumn> insert_column_list_;
  std::vector<std::unique_ptr<const ResolvedColumnRef>> query_parameter_list_;
  std::unique_ptr<const ResolvedScan> query_;
  std::vector<ResolvedColumn> query_output_column_list_;
  std::vector<std::unique_ptr<const ResolvedInsertRow>> row_list_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedInsertStmt> MakeResolvedInsertStmt(
    std::unique_ptr<const ResolvedTableScan> table_scan,
    ResolvedInsertStmt::InsertMode insert_mode,
    std::unique_ptr<const ResolvedAssertRowsModified> assert_rows_modified,
    const std::vector<ResolvedColumn>& insert_column_list,
    std::vector<std::unique_ptr<const ResolvedColumnRef>> query_parameter_list,
    std::unique_ptr<const ResolvedScan> query,
    const std::vector<ResolvedColumn>& query_output_column_list,
    std::vector<std::unique_ptr<const ResolvedInsertRow>> row_list) {
  return std::unique_ptr<ResolvedInsertStmt>(new ResolvedInsertStmt(
        std::move(table_scan),
        insert_mode,
        std::move(assert_rows_modified),
        insert_column_list,
        std::move(query_parameter_list),
        std::move(query),
        query_output_column_list,
        std::move(row_list),
        ResolvedInsertStmt::NEW_CONSTRUCTOR));
}

// Overloaded factory method for the construction of ResolvedInsertStmt with
// a wider range of inputs for node-vector inputs.  In particular allows:
// 1. unique_ptr element type can be non-const.
// 2. unique_ptr element type can be any descendant of the required type.
// 3. input container can be any object with a `begin()` and `end()`.
//
// Note, initializer lists cannot be used to pass
//  query_parameter_list, row_list
// due to incompatibility with unique_ptr.  Use zetasql::MakeNodeVector
// instead.
template <
  typename query_parameter_list_t
      = std::vector<std::unique_ptr<const ResolvedColumnRef>>,
  typename row_list_t
      = std::vector<std::unique_ptr<const ResolvedInsertRow>>>
std::unique_ptr<ResolvedInsertStmt> MakeResolvedInsertStmt(
    std::unique_ptr<const ResolvedTableScan> table_scan,
    ResolvedInsertStmt::InsertMode insert_mode,
    std::unique_ptr<const ResolvedAssertRowsModified> assert_rows_modified,
    const std::vector<ResolvedColumn>& insert_column_list,
    query_parameter_list_t query_parameter_list,
    std::unique_ptr<const ResolvedScan> query,
    const std::vector<ResolvedColumn>& query_output_column_list,
    row_list_t row_list) {
  static_assert(std::is_base_of<
      ResolvedColumnRef,
      typename std::decay<decltype(**(query_parameter_list.begin()))>::type>::value,
      "query_parameter_list must be a container of unique_ptr with elements of type "
      "ResolvedColumnRef (or its descendants).");
  static_assert(std::is_base_of<
      ResolvedInsertRow,
      typename std::decay<decltype(**(row_list.begin()))>::type>::value,
      "row_list must be a container of unique_ptr with elements of type "
      "ResolvedInsertRow (or its descendants).");
  return MakeResolvedInsertStmt(
      std::move(table_scan),
      insert_mode,
      std::move(assert_rows_modified),
      insert_column_list,
      {std::make_move_iterator(query_parameter_list.begin()),
       std::make_move_iterator(query_parameter_list.end())},
      std::move(query),
      query_output_column_list,
      {std::make_move_iterator(row_list.begin()),
       std::make_move_iterator(row_list.end())});
}

inline std::unique_ptr<ResolvedInsertStmt> MakeResolvedInsertStmt() {
  return std::unique_ptr<ResolvedInsertStmt>(
      new ResolvedInsertStmt());
}

// This represents a DELETE statement or a nested DELETE inside an
// UPDATE statement.
//
// For top-level DELETE statements, <table_scan> gives the table to
// scan and creates ResolvedColumns for its columns.  Those columns can
// be referenced inside the <where_expr>.
//
// For nested DELETEs, there is no <table_scan>.  The <where_expr> can
// only reference:
//   (1) the element_column from the ResolvedUpdateItem containing this
//       statement,
//   (2) columns from the outer statements, and
//   (3) (optionally) <array_offset_column>, which represents the 0-based
//       offset of the array element being modified.
//
// <where_expr> is required.
class ResolvedDeleteStmt final : public ResolvedStatement {
 public:
  typedef ResolvedStatement SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_DELETE_STMT;

  friend std::unique_ptr<ResolvedDeleteStmt> MakeResolvedDeleteStmt();
 protected:
  ResolvedDeleteStmt()
      : ResolvedStatement()
      , table_scan_()
      , assert_rows_modified_()
      , array_offset_column_()
      , where_expr_()
  {}
 public:

  ResolvedDeleteStmt(const ResolvedDeleteStmt&) = delete;
  ResolvedDeleteStmt& operator=(const ResolvedDeleteStmt&) = delete;

  friend std::unique_ptr<ResolvedDeleteStmt> MakeResolvedDeleteStmt(
      std::unique_ptr<const ResolvedTableScan> table_scan,
      std::unique_ptr<const ResolvedAssertRowsModified> assert_rows_modified,
      std::unique_ptr<const ResolvedColumnHolder> array_offset_column,
      std::unique_ptr<const ResolvedExpr> where_expr
  );
  ~ResolvedDeleteStmt() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_DELETE_STMT; }
  std::string node_kind_string() const final { return "DeleteStmt"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedDeleteStmtProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedStatementProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedDeleteStmt>> RestoreFrom(
      const ResolvedDeleteStmtProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  const ResolvedTableScan* table_scan() const {
    accessed_ |= (1<<0);
    return table_scan_.get();
  }
  void set_table_scan(std::unique_ptr<const ResolvedTableScan> v) {
    table_scan_ = std::move(v);
  }

  std::unique_ptr<const ResolvedTableScan> release_table_scan() {
    return std::move(table_scan_);
  }

  const ResolvedAssertRowsModified* assert_rows_modified() const {
    accessed_ |= (1<<1);
    return assert_rows_modified_.get();
  }
  void set_assert_rows_modified(std::unique_ptr<const ResolvedAssertRowsModified> v) {
    assert_rows_modified_ = std::move(v);
  }

  std::unique_ptr<const ResolvedAssertRowsModified> release_assert_rows_modified() {
    return std::move(assert_rows_modified_);
  }

  const ResolvedColumnHolder* array_offset_column() const {
    accessed_ |= (1<<2);
    return array_offset_column_.get();
  }
  void set_array_offset_column(std::unique_ptr<const ResolvedColumnHolder> v) {
    array_offset_column_ = std::move(v);
  }

  std::unique_ptr<const ResolvedColumnHolder> release_array_offset_column() {
    return std::move(array_offset_column_);
  }

  const ResolvedExpr* where_expr() const {
    accessed_ |= (1<<3);
    return where_expr_.get();
  }
  void set_where_expr(std::unique_ptr<const ResolvedExpr> v) {
    where_expr_ = std::move(v);
  }

  std::unique_ptr<const ResolvedExpr> release_where_expr() {
    return std::move(where_expr_);
  }

 protected:
  explicit ResolvedDeleteStmt(
      std::unique_ptr<const ResolvedTableScan> table_scan,
      std::unique_ptr<const ResolvedAssertRowsModified> assert_rows_modified,
      std::unique_ptr<const ResolvedColumnHolder> array_offset_column,
      std::unique_ptr<const ResolvedExpr> where_expr,
      ConstructorOverload)
      : ResolvedStatement(
            ConstructorOverload::NEW_CONSTRUCTOR),
      table_scan_(std::move(table_scan)),
      assert_rows_modified_(std::move(assert_rows_modified)),
      array_offset_column_(std::move(array_offset_column)),
      where_expr_(std::move(where_expr)) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  std::unique_ptr<const ResolvedTableScan> table_scan_;
  std::unique_ptr<const ResolvedAssertRowsModified> assert_rows_modified_;
  std::unique_ptr<const ResolvedColumnHolder> array_offset_column_;
  std::unique_ptr<const ResolvedExpr> where_expr_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedDeleteStmt> MakeResolvedDeleteStmt(
    std::unique_ptr<const ResolvedTableScan> table_scan,
    std::unique_ptr<const ResolvedAssertRowsModified> assert_rows_modified,
    std::unique_ptr<const ResolvedColumnHolder> array_offset_column,
    std::unique_ptr<const ResolvedExpr> where_expr) {
  return std::unique_ptr<ResolvedDeleteStmt>(new ResolvedDeleteStmt(
        std::move(table_scan),
        std::move(assert_rows_modified),
        std::move(array_offset_column),
        std::move(where_expr),
        ResolvedDeleteStmt::NEW_CONSTRUCTOR));
}

inline std::unique_ptr<ResolvedDeleteStmt> MakeResolvedDeleteStmt() {
  return std::unique_ptr<ResolvedDeleteStmt>(
      new ResolvedDeleteStmt());
}

// This represents one item inside the SET clause of an UPDATE.
//
// The entity being updated is specified by <target>.
//
// For a regular
//   SET {target} = {expression} | DEFAULT
// clause (not including an array element update like SET a[OFFSET(0)] = 5),
// <target> and <set_value> will be present, and all other fields will be
// unset.
//
// For an array element update (e.g. SET a.b[<expr>].c = <value>),
//   - <target> is set to the array,
//   - <element_column> is a new ResolvedColumn that can be used inside the
//     update items to refer to the array element.
//   - <array_update_list> will have a node corresponding to the offset into
//     that array and the modification to that array element.
// For example, for SET a.b[<expr>].c = <value>, we have
//    ResolvedUpdateItem
//    +-<target> = a.b
//    +-<element_column> = <x>
//    +-<array_update_list>
//      +-ResolvedUpdateArrayItem
//        +-<offset> = <expr>
//        +-<update_item> = ResolvedUpdateItem
//          +-<target> = <x>.c
//          +-<set_value> = <value>
//
// The engine is required to fail the update if there are two elements of
// <array_update_list> corresponding to offset expressions that evaluate to
// the same value. These are considered to be conflicting updates.
//
// Multiple updates to the same array are always represented as multiple
// elements of <array_update_list> under a single ResolvedUpdateItem
// corresponding to that array. <array_update_list> will only have one
// element for modifications to an array-valued subfield of an array element.
// E.g., for SET a[<expr1>].b[<expr2>] = 5, a[<expr3>].b[<expr4>] = 6, we
// will have:
//     ResolvedUpdateItem
//     +-<target> = a
//     +-<element_column> = x
//     +-<array_update_list>
//       +-ResolvedUpdateArrayItem
//         +-<offset> = <expr1>
//         +-ResolvedUpdateItem for <x>.b[<expr2>] = 5
//       +-ResolvedUpdateArrayItem
//         +-<offset> = <expr3>
//         +-ResolvedUpdateItem for <x>.b[<expr4>] = 6
// The engine must give a runtime error if <expr1> and <expr3> evaluate to
// the same thing. Notably, it does not have to understand that the
// two ResolvedUpdateItems corresponding to "b" refer to the same array iff
// <expr1> and <expr3> evaluate to the same thing.
//
// TODO: Consider allowing the engine to execute an update like
// SET a[<expr1>].b = 1, a[<expr2>].c = 2 even if <expr1> == <expr2> since
// "b" and "c" do not overlap. Also consider allowing a more complex example
// like SET a[<expr1>].b[<expr2>] = ...,
// a[<expr3>].b[<expr4>].c[<expr5>] = ... even if <expr1> == <expr3>, as long
// as <expr2> != <expr4> in that case.
//
// For nested DML, <target> and <element_column> will both be set, and one or
// more of the nested statement lists will be non-empty. <target> must have
// ARRAY type, and <element_column> introduces a ResolvedColumn representing
// elements of that array. The nested statement lists will always be empty in
// a ResolvedUpdateItem child of a ResolvedUpdateArrayItem node.
//
// See (broken link) for more detail.
class ResolvedUpdateItem final : public ResolvedArgument {
 public:
  typedef ResolvedArgument SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_UPDATE_ITEM;

  friend std::unique_ptr<ResolvedUpdateItem> MakeResolvedUpdateItem();
 protected:
  ResolvedUpdateItem()
      : ResolvedArgument()
      , target_()
      , set_value_()
      , element_column_()
      , array_update_list_()
      , delete_list_()
      , update_list_()
      , insert_list_()
  {}
 public:

  ResolvedUpdateItem(const ResolvedUpdateItem&) = delete;
  ResolvedUpdateItem& operator=(const ResolvedUpdateItem&) = delete;

  friend std::unique_ptr<ResolvedUpdateItem> MakeResolvedUpdateItem(
      std::unique_ptr<const ResolvedExpr> target,
      std::unique_ptr<const ResolvedDMLValue> set_value,
      std::unique_ptr<const ResolvedColumnHolder> element_column,
      std::vector<std::unique_ptr<const ResolvedUpdateArrayItem>> array_update_list,
      std::vector<std::unique_ptr<const ResolvedDeleteStmt>> delete_list,
      std::vector<std::unique_ptr<const ResolvedUpdateStmt>> update_list,
      std::vector<std::unique_ptr<const ResolvedInsertStmt>> insert_list
  );
  ~ResolvedUpdateItem() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_UPDATE_ITEM; }
  std::string node_kind_string() const final { return "UpdateItem"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedUpdateItemProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedArgumentProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedUpdateItem>> RestoreFrom(
      const ResolvedUpdateItemProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  // The target entity to be updated.
  //
  // This is an expression evaluated using the ResolvedColumns visible
  // inside this statement.  This expression can contain only
  // ResolvedColumnRefs, ResolvedGetProtoField and
  // ResolvedGetStructField nodes.
  //
  // In a top-level UPDATE, the expression always starts with a
  // ResolvedColumnRef referencing a column from the statement's
  // TableScan.
  //
  // In a nested UPDATE, the expression always starts with a
  // ResolvedColumnRef referencing the element_column from the
  // ResolvedUpdateItem containing this scan.
  //
  // This node is also used to represent a modification of a single
  // array element (when it occurs as a child of a
  // ResolvedUpdateArrayItem node).  In that case, the expression
  // starts with a ResolvedColumnRef referencing the <element_column>
  // from its grandparent ResolvedUpdateItem. (E.g., for "SET a[<expr>]
  // = 5", the grandparent ResolvedUpdateItem has <target> "a", the
  // parent ResolvedUpdateArrayItem has offset <expr>, and this node
  // has <set_value> 5 and target corresponding to the grandparent's
  // <element_column> field.)
  //
  // For either a nested UPDATE or an array modification, there may be
  // a path of field accesses after the initial ResolvedColumnRef,
  // represented by a chain of GetField nodes.
  //
  // NOTE: We use the same GetField nodes as we do for queries, but
  // they are not treated the same.  Here, they express a path inside
  // an object that is being mutated, so they have reference semantics.
  const ResolvedExpr* target() const {
    accessed_ |= (1<<0);
    return target_.get();
  }
  void set_target(std::unique_ptr<const ResolvedExpr> v) {
    target_ = std::move(v);
  }

  std::unique_ptr<const ResolvedExpr> release_target() {
    return std::move(target_);
  }

  // Set the target entity to this value.  The types must match.
  // This can contain the same columns that can appear in the
  // <where_expr> of the enclosing ResolvedUpdateStmt.
  //
  // This is mutually exclusive with all fields below, which are used
  // for nested updates only.
  const ResolvedDMLValue* set_value() const {
    accessed_ |= (1<<1);
    return set_value_.get();
  }
  void set_set_value(std::unique_ptr<const ResolvedDMLValue> v) {
    set_value_ = std::move(v);
  }

  std::unique_ptr<const ResolvedDMLValue> release_set_value() {
    return std::move(set_value_);
  }

  // The ResolvedColumn introduced to represent the elements of the
  // array being updated.  This works similarly to
  // ArrayScan::element_column.
  //
  // <target> must have array type, and this column has the array's
  // element type.
  //
  // This column can be referenced inside the nested statements below.
  const ResolvedColumnHolder* element_column() const {
    accessed_ |= (1<<2);
    return element_column_.get();
  }
  void set_element_column(std::unique_ptr<const ResolvedColumnHolder> v) {
    element_column_ = std::move(v);
  }

  std::unique_ptr<const ResolvedColumnHolder> release_element_column() {
    return std::move(element_column_);
  }

  // Array element modifications to apply. Each item runs on the value
  // of <element_column> specified by ResolvedUpdateArrayItem.offset.
  // This field is always empty if the analyzer option
  // FEATURE_V_1_2_ARRAY_ELEMENTS_WITH_SET is disabled.
  //
  // The engine must fail if two elements in this list have offset
  // expressions that evaluate to the same value.
  // TODO: Consider generalizing this to allow
  // SET a[<expr1>].b = ..., a[<expr2>].c = ...
  const std::vector<std::unique_ptr<const ResolvedUpdateArrayItem>>& array_update_list() const {
    accessed_ |= (1<<3);
    return array_update_list_;
  }
  int array_update_list_size() const {
    if (array_update_list_.empty()) accessed_ |= (1<<3);
    return static_cast<int>(array_update_list_.size());
  }
  const ResolvedUpdateArrayItem* array_update_list(int i) const {
    accessed_ |= (1<<3);
    return array_update_list_.at(i).get();
  }
  void add_array_update_list(std::unique_ptr<const ResolvedUpdateArrayItem> v) {
    array_update_list_.emplace_back(std::move(v));
  }
  void set_array_update_list(std::vector<std::unique_ptr<const ResolvedUpdateArrayItem>> v) {
    array_update_list_ = std::move(v);
  }

  std::vector<std::unique_ptr<const ResolvedUpdateArrayItem>> release_array_update_list() {
    std::vector<std::unique_ptr<const ResolvedUpdateArrayItem>> tmp;
    array_update_list_.swap(tmp);
    return tmp;
  }

  // Nested DELETE statements to apply.  Each delete runs on one value
  // of <element_column> and may choose to delete that array element.
  //
  // DELETEs are applied before INSERTs or UPDATEs.
  //
  // It is legal for the same input element to match multiple DELETEs.
  const std::vector<std::unique_ptr<const ResolvedDeleteStmt>>& delete_list() const {
    accessed_ |= (1<<4);
    return delete_list_;
  }
  int delete_list_size() const {
    if (delete_list_.empty()) accessed_ |= (1<<4);
    return static_cast<int>(delete_list_.size());
  }
  const ResolvedDeleteStmt* delete_list(int i) const {
    accessed_ |= (1<<4);
    return delete_list_.at(i).get();
  }
  void add_delete_list(std::unique_ptr<const ResolvedDeleteStmt> v) {
    delete_list_.emplace_back(std::move(v));
  }
  void set_delete_list(std::vector<std::unique_ptr<const ResolvedDeleteStmt>> v) {
    delete_list_ = std::move(v);
  }

  std::vector<std::unique_ptr<const ResolvedDeleteStmt>> release_delete_list() {
    std::vector<std::unique_ptr<const ResolvedDeleteStmt>> tmp;
    delete_list_.swap(tmp);
    return tmp;
  }

  // Nested UPDATE statements to apply.  Each update runs on one value
  // of <element_column> and may choose to update that array element.
  //
  // UPDATEs are applied after DELETEs and before INSERTs.
  //
  // It is an error if any element is matched by multiple UPDATEs.
  const std::vector<std::unique_ptr<const ResolvedUpdateStmt>>& update_list() const {
    accessed_ |= (1<<5);
    return update_list_;
  }
  int update_list_size() const {
    if (update_list_.empty()) accessed_ |= (1<<5);
    return static_cast<int>(update_list_.size());
  }
  const ResolvedUpdateStmt* update_list(int i) const {
    accessed_ |= (1<<5);
    return update_list_.at(i).get();
  }
  void add_update_list(std::unique_ptr<const ResolvedUpdateStmt> v) {
    update_list_.emplace_back(std::move(v));
  }
  void set_update_list(std::vector<std::unique_ptr<const ResolvedUpdateStmt>> v) {
    update_list_ = std::move(v);
  }

  std::vector<std::unique_ptr<const ResolvedUpdateStmt>> release_update_list() {
    std::vector<std::unique_ptr<const ResolvedUpdateStmt>> tmp;
    update_list_.swap(tmp);
    return tmp;
  }

  // Nested INSERT statements to apply.  Each insert will produce zero
  // or more values for <element_column>.
  //
  // INSERTs are applied after DELETEs and UPDATEs.
  //
  // For nested UPDATEs, insert_mode will always be the default, and
  // has no effect.
  const std::vector<std::unique_ptr<const ResolvedInsertStmt>>& insert_list() const {
    accessed_ |= (1<<6);
    return insert_list_;
  }
  int insert_list_size() const {
    if (insert_list_.empty()) accessed_ |= (1<<6);
    return static_cast<int>(insert_list_.size());
  }
  const ResolvedInsertStmt* insert_list(int i) const {
    accessed_ |= (1<<6);
    return insert_list_.at(i).get();
  }
  void add_insert_list(std::unique_ptr<const ResolvedInsertStmt> v) {
    insert_list_.emplace_back(std::move(v));
  }
  void set_insert_list(std::vector<std::unique_ptr<const ResolvedInsertStmt>> v) {
    insert_list_ = std::move(v);
  }

  std::vector<std::unique_ptr<const ResolvedInsertStmt>> release_insert_list() {
    std::vector<std::unique_ptr<const ResolvedInsertStmt>> tmp;
    insert_list_.swap(tmp);
    return tmp;
  }

 protected:
  explicit ResolvedUpdateItem(
      std::unique_ptr<const ResolvedExpr> target,
      std::unique_ptr<const ResolvedDMLValue> set_value,
      std::unique_ptr<const ResolvedColumnHolder> element_column,
      std::vector<std::unique_ptr<const ResolvedUpdateArrayItem>> array_update_list,
      std::vector<std::unique_ptr<const ResolvedDeleteStmt>> delete_list,
      std::vector<std::unique_ptr<const ResolvedUpdateStmt>> update_list,
      std::vector<std::unique_ptr<const ResolvedInsertStmt>> insert_list,
      ConstructorOverload)
      : ResolvedArgument(
            ConstructorOverload::NEW_CONSTRUCTOR),
      target_(std::move(target)),
      set_value_(std::move(set_value)),
      element_column_(std::move(element_column)),
      array_update_list_(std::move(array_update_list)),
      delete_list_(std::move(delete_list)),
      update_list_(std::move(update_list)),
      insert_list_(std::move(insert_list)) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  std::unique_ptr<const ResolvedExpr> target_;
  std::unique_ptr<const ResolvedDMLValue> set_value_;
  std::unique_ptr<const ResolvedColumnHolder> element_column_;
  std::vector<std::unique_ptr<const ResolvedUpdateArrayItem>> array_update_list_;
  std::vector<std::unique_ptr<const ResolvedDeleteStmt>> delete_list_;
  std::vector<std::unique_ptr<const ResolvedUpdateStmt>> update_list_;
  std::vector<std::unique_ptr<const ResolvedInsertStmt>> insert_list_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedUpdateItem> MakeResolvedUpdateItem(
    std::unique_ptr<const ResolvedExpr> target,
    std::unique_ptr<const ResolvedDMLValue> set_value,
    std::unique_ptr<const ResolvedColumnHolder> element_column,
    std::vector<std::unique_ptr<const ResolvedUpdateArrayItem>> array_update_list,
    std::vector<std::unique_ptr<const ResolvedDeleteStmt>> delete_list,
    std::vector<std::unique_ptr<const ResolvedUpdateStmt>> update_list,
    std::vector<std::unique_ptr<const ResolvedInsertStmt>> insert_list) {
  return std::unique_ptr<ResolvedUpdateItem>(new ResolvedUpdateItem(
        std::move(target),
        std::move(set_value),
        std::move(element_column),
        std::move(array_update_list),
        std::move(delete_list),
        std::move(update_list),
        std::move(insert_list),
        ResolvedUpdateItem::NEW_CONSTRUCTOR));
}

// Overloaded factory method for the construction of ResolvedUpdateItem with
// a wider range of inputs for node-vector inputs.  In particular allows:
// 1. unique_ptr element type can be non-const.
// 2. unique_ptr element type can be any descendant of the required type.
// 3. input container can be any object with a `begin()` and `end()`.
//
// Note, initializer lists cannot be used to pass
//  array_update_list, delete_list, update_list, insert_list
// due to incompatibility with unique_ptr.  Use zetasql::MakeNodeVector
// instead.
template <
  typename array_update_list_t
      = std::vector<std::unique_ptr<const ResolvedUpdateArrayItem>>,
  typename delete_list_t
      = std::vector<std::unique_ptr<const ResolvedDeleteStmt>>,
  typename update_list_t
      = std::vector<std::unique_ptr<const ResolvedUpdateStmt>>,
  typename insert_list_t
      = std::vector<std::unique_ptr<const ResolvedInsertStmt>>>
std::unique_ptr<ResolvedUpdateItem> MakeResolvedUpdateItem(
    std::unique_ptr<const ResolvedExpr> target,
    std::unique_ptr<const ResolvedDMLValue> set_value,
    std::unique_ptr<const ResolvedColumnHolder> element_column,
    array_update_list_t array_update_list,
    delete_list_t delete_list,
    update_list_t update_list,
    insert_list_t insert_list) {
  static_assert(std::is_base_of<
      ResolvedUpdateArrayItem,
      typename std::decay<decltype(**(array_update_list.begin()))>::type>::value,
      "array_update_list must be a container of unique_ptr with elements of type "
      "ResolvedUpdateArrayItem (or its descendants).");
  static_assert(std::is_base_of<
      ResolvedDeleteStmt,
      typename std::decay<decltype(**(delete_list.begin()))>::type>::value,
      "delete_list must be a container of unique_ptr with elements of type "
      "ResolvedDeleteStmt (or its descendants).");
  static_assert(std::is_base_of<
      ResolvedUpdateStmt,
      typename std::decay<decltype(**(update_list.begin()))>::type>::value,
      "update_list must be a container of unique_ptr with elements of type "
      "ResolvedUpdateStmt (or its descendants).");
  static_assert(std::is_base_of<
      ResolvedInsertStmt,
      typename std::decay<decltype(**(insert_list.begin()))>::type>::value,
      "insert_list must be a container of unique_ptr with elements of type "
      "ResolvedInsertStmt (or its descendants).");
  return MakeResolvedUpdateItem(
      std::move(target),
      std::move(set_value),
      std::move(element_column),
      {std::make_move_iterator(array_update_list.begin()),
       std::make_move_iterator(array_update_list.end())},
      {std::make_move_iterator(delete_list.begin()),
       std::make_move_iterator(delete_list.end())},
      {std::make_move_iterator(update_list.begin()),
       std::make_move_iterator(update_list.end())},
      {std::make_move_iterator(insert_list.begin()),
       std::make_move_iterator(insert_list.end())});
}

inline std::unique_ptr<ResolvedUpdateItem> MakeResolvedUpdateItem() {
  return std::unique_ptr<ResolvedUpdateItem>(
      new ResolvedUpdateItem());
}

// For an array element modification, this node represents the offset
// expression and the modification, but not the array. E.g., for
// SET a[<expr>] = 5, this node represents a modification of "= 5" to offset
// <expr> of the array defined by the parent node.
class ResolvedUpdateArrayItem final : public ResolvedArgument {
 public:
  typedef ResolvedArgument SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_UPDATE_ARRAY_ITEM;

  friend std::unique_ptr<ResolvedUpdateArrayItem> MakeResolvedUpdateArrayItem();
 protected:
  ResolvedUpdateArrayItem()
      : ResolvedArgument()
      , offset_()
      , update_item_()
  {}
 public:

  ResolvedUpdateArrayItem(const ResolvedUpdateArrayItem&) = delete;
  ResolvedUpdateArrayItem& operator=(const ResolvedUpdateArrayItem&) = delete;

  friend std::unique_ptr<ResolvedUpdateArrayItem> MakeResolvedUpdateArrayItem(
      std::unique_ptr<const ResolvedExpr> offset,
      std::unique_ptr<const ResolvedUpdateItem> update_item
  );
  ~ResolvedUpdateArrayItem() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_UPDATE_ARRAY_ITEM; }
  std::string node_kind_string() const final { return "UpdateArrayItem"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedUpdateArrayItemProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedArgumentProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedUpdateArrayItem>> RestoreFrom(
      const ResolvedUpdateArrayItemProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  // The array offset to be modified.
  const ResolvedExpr* offset() const {
    accessed_ |= (1<<0);
    return offset_.get();
  }
  void set_offset(std::unique_ptr<const ResolvedExpr> v) {
    offset_ = std::move(v);
  }

  std::unique_ptr<const ResolvedExpr> release_offset() {
    return std::move(offset_);
  }

  // The modification to perform to the array element.
  const ResolvedUpdateItem* update_item() const {
    accessed_ |= (1<<1);
    return update_item_.get();
  }
  void set_update_item(std::unique_ptr<const ResolvedUpdateItem> v) {
    update_item_ = std::move(v);
  }

  std::unique_ptr<const ResolvedUpdateItem> release_update_item() {
    return std::move(update_item_);
  }

 protected:
  explicit ResolvedUpdateArrayItem(
      std::unique_ptr<const ResolvedExpr> offset,
      std::unique_ptr<const ResolvedUpdateItem> update_item,
      ConstructorOverload)
      : ResolvedArgument(
            ConstructorOverload::NEW_CONSTRUCTOR),
      offset_(std::move(offset)),
      update_item_(std::move(update_item)) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  std::unique_ptr<const ResolvedExpr> offset_;
  std::unique_ptr<const ResolvedUpdateItem> update_item_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedUpdateArrayItem> MakeResolvedUpdateArrayItem(
    std::unique_ptr<const ResolvedExpr> offset,
    std::unique_ptr<const ResolvedUpdateItem> update_item) {
  return std::unique_ptr<ResolvedUpdateArrayItem>(new ResolvedUpdateArrayItem(
        std::move(offset),
        std::move(update_item),
        ResolvedUpdateArrayItem::NEW_CONSTRUCTOR));
}

inline std::unique_ptr<ResolvedUpdateArrayItem> MakeResolvedUpdateArrayItem() {
  return std::unique_ptr<ResolvedUpdateArrayItem>(
      new ResolvedUpdateArrayItem());
}

// This represents an UPDATE statement, or a nested UPDATE inside an
// UPDATE statement.
//
// For top-level UPDATE statements, <table_scan> gives the table to
// scan and creates ResolvedColumns for its columns.  Those columns can be
// referenced in the <update_item_list>. The top-level UPDATE statement may
// also have <from_scan>, the output of which is joined with
// the <table_scan> using expressions in the <where_expr>. The columns
// exposed in the <from_scan> are visible in the right side of the
// expressions in the <update_item_list> and in the <where_expr>.
// <array_offset_column> is never set for top-level UPDATE statements.
//
// Top-level UPDATE statements will also have <column_access_list> populated.
// For each column, this vector indicates if the column was read and/or
// written. The columns in this vector match those of
// <table_scan.column_list>. If a column was not encountered when producing
// the resolved AST, then the value at that index will be
// ResolvedStatement::NONE.
//
// For nested UPDATEs, there is no <table_scan>.  The <where_expr> can
// only reference:
//   (1) the element_column from the ResolvedUpdateItem containing this
//       statement,
//   (2) columns from the outer statements, and
//   (3) (optionally) <array_offset_column>, which represents the 0-based
//       offset of the array element being modified.
// The left hand sides of the expressions in <update_item_list> can only
// reference (1). The right hand sides of those expressions can reference
// (1), (2), and (3).
//
// The updates in <update_item_list> will be non-overlapping.
// If there are multiple nested statements updating the same entity,
// they will be combined into one ResolvedUpdateItem.
//
// See (broken link) for more detail on nested DML.
class ResolvedUpdateStmt final : public ResolvedStatement {
 public:
  typedef ResolvedStatement SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_UPDATE_STMT;

  friend std::unique_ptr<ResolvedUpdateStmt> MakeResolvedUpdateStmt();
 protected:
  ResolvedUpdateStmt()
      : ResolvedStatement()
      , table_scan_()
      , column_access_list_()
      , assert_rows_modified_()
      , array_offset_column_()
      , where_expr_()
      , update_item_list_()
      , from_scan_()
  {}
 public:

  ResolvedUpdateStmt(const ResolvedUpdateStmt&) = delete;
  ResolvedUpdateStmt& operator=(const ResolvedUpdateStmt&) = delete;

  friend std::unique_ptr<ResolvedUpdateStmt> MakeResolvedUpdateStmt(
      std::unique_ptr<const ResolvedTableScan> table_scan,
      std::unique_ptr<const ResolvedAssertRowsModified> assert_rows_modified,
      std::unique_ptr<const ResolvedColumnHolder> array_offset_column,
      std::unique_ptr<const ResolvedExpr> where_expr,
      std::vector<std::unique_ptr<const ResolvedUpdateItem>> update_item_list,
      std::unique_ptr<const ResolvedScan> from_scan
  );
  ~ResolvedUpdateStmt() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_UPDATE_STMT; }
  std::string node_kind_string() const final { return "UpdateStmt"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedUpdateStmtProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedStatementProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedUpdateStmt>> RestoreFrom(
      const ResolvedUpdateStmtProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  const ResolvedTableScan* table_scan() const {
    accessed_ |= (1<<0);
    return table_scan_.get();
  }
  void set_table_scan(std::unique_ptr<const ResolvedTableScan> v) {
    table_scan_ = std::move(v);
  }

  std::unique_ptr<const ResolvedTableScan> release_table_scan() {
    return std::move(table_scan_);
  }

  const std::vector<ObjectAccess>& column_access_list() const {
    accessed_ |= (1<<1);
    return column_access_list_;
  }
  int column_access_list_size() const {
    if (column_access_list_.empty()) accessed_ |= (1<<1);
    return static_cast<int>(column_access_list_.size());
  }
  ObjectAccess column_access_list(int i) const {
    accessed_ |= (1<<1);
    return column_access_list_.at(i);
  }
  void add_column_access_list(ObjectAccess v) {
    column_access_list_.push_back(ObjectAccess(v));
  }
  void set_column_access_list(const std::vector<ObjectAccess>& v) {
    column_access_list_ = v;
  }
  std::vector<ObjectAccess>* mutable_column_access_list() {
    accessed_ |= (1<<1);
    return &column_access_list_;
  }

  const ResolvedAssertRowsModified* assert_rows_modified() const {
    accessed_ |= (1<<2);
    return assert_rows_modified_.get();
  }
  void set_assert_rows_modified(std::unique_ptr<const ResolvedAssertRowsModified> v) {
    assert_rows_modified_ = std::move(v);
  }

  std::unique_ptr<const ResolvedAssertRowsModified> release_assert_rows_modified() {
    return std::move(assert_rows_modified_);
  }

  const ResolvedColumnHolder* array_offset_column() const {
    accessed_ |= (1<<3);
    return array_offset_column_.get();
  }
  void set_array_offset_column(std::unique_ptr<const ResolvedColumnHolder> v) {
    array_offset_column_ = std::move(v);
  }

  std::unique_ptr<const ResolvedColumnHolder> release_array_offset_column() {
    return std::move(array_offset_column_);
  }

  const ResolvedExpr* where_expr() const {
    accessed_ |= (1<<4);
    return where_expr_.get();
  }
  void set_where_expr(std::unique_ptr<const ResolvedExpr> v) {
    where_expr_ = std::move(v);
  }

  std::unique_ptr<const ResolvedExpr> release_where_expr() {
    return std::move(where_expr_);
  }

  const std::vector<std::unique_ptr<const ResolvedUpdateItem>>& update_item_list() const {
    accessed_ |= (1<<5);
    return update_item_list_;
  }
  int update_item_list_size() const {
    if (update_item_list_.empty()) accessed_ |= (1<<5);
    return static_cast<int>(update_item_list_.size());
  }
  const ResolvedUpdateItem* update_item_list(int i) const {
    accessed_ |= (1<<5);
    return update_item_list_.at(i).get();
  }
  void add_update_item_list(std::unique_ptr<const ResolvedUpdateItem> v) {
    update_item_list_.emplace_back(std::move(v));
  }
  void set_update_item_list(std::vector<std::unique_ptr<const ResolvedUpdateItem>> v) {
    update_item_list_ = std::move(v);
  }

  std::vector<std::unique_ptr<const ResolvedUpdateItem>> release_update_item_list() {
    std::vector<std::unique_ptr<const ResolvedUpdateItem>> tmp;
    update_item_list_.swap(tmp);
    return tmp;
  }

  const ResolvedScan* from_scan() const {
    accessed_ |= (1<<6);
    return from_scan_.get();
  }
  void set_from_scan(std::unique_ptr<const ResolvedScan> v) {
    from_scan_ = std::move(v);
  }

  std::unique_ptr<const ResolvedScan> release_from_scan() {
    return std::move(from_scan_);
  }

 protected:
  explicit ResolvedUpdateStmt(
      std::unique_ptr<const ResolvedTableScan> table_scan,
      std::unique_ptr<const ResolvedAssertRowsModified> assert_rows_modified,
      std::unique_ptr<const ResolvedColumnHolder> array_offset_column,
      std::unique_ptr<const ResolvedExpr> where_expr,
      std::vector<std::unique_ptr<const ResolvedUpdateItem>> update_item_list,
      std::unique_ptr<const ResolvedScan> from_scan,
      ConstructorOverload)
      : ResolvedStatement(
            ConstructorOverload::NEW_CONSTRUCTOR),
      table_scan_(std::move(table_scan)),
      column_access_list_(),
      assert_rows_modified_(std::move(assert_rows_modified)),
      array_offset_column_(std::move(array_offset_column)),
      where_expr_(std::move(where_expr)),
      update_item_list_(std::move(update_item_list)),
      from_scan_(std::move(from_scan)) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  std::unique_ptr<const ResolvedTableScan> table_scan_;
  std::vector<ObjectAccess> column_access_list_;
  std::unique_ptr<const ResolvedAssertRowsModified> assert_rows_modified_;
  std::unique_ptr<const ResolvedColumnHolder> array_offset_column_;
  std::unique_ptr<const ResolvedExpr> where_expr_;
  std::vector<std::unique_ptr<const ResolvedUpdateItem>> update_item_list_;
  std::unique_ptr<const ResolvedScan> from_scan_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedUpdateStmt> MakeResolvedUpdateStmt(
    std::unique_ptr<const ResolvedTableScan> table_scan,
    std::unique_ptr<const ResolvedAssertRowsModified> assert_rows_modified,
    std::unique_ptr<const ResolvedColumnHolder> array_offset_column,
    std::unique_ptr<const ResolvedExpr> where_expr,
    std::vector<std::unique_ptr<const ResolvedUpdateItem>> update_item_list,
    std::unique_ptr<const ResolvedScan> from_scan) {
  return std::unique_ptr<ResolvedUpdateStmt>(new ResolvedUpdateStmt(
        std::move(table_scan),
        std::move(assert_rows_modified),
        std::move(array_offset_column),
        std::move(where_expr),
        std::move(update_item_list),
        std::move(from_scan),
        ResolvedUpdateStmt::NEW_CONSTRUCTOR));
}

// Overloaded factory method for the construction of ResolvedUpdateStmt with
// a wider range of inputs for node-vector inputs.  In particular allows:
// 1. unique_ptr element type can be non-const.
// 2. unique_ptr element type can be any descendant of the required type.
// 3. input container can be any object with a `begin()` and `end()`.
//
// Note, initializer lists cannot be used to pass
//  update_item_list
// due to incompatibility with unique_ptr.  Use zetasql::MakeNodeVector
// instead.
template <
  typename update_item_list_t
      = std::vector<std::unique_ptr<const ResolvedUpdateItem>>>
std::unique_ptr<ResolvedUpdateStmt> MakeResolvedUpdateStmt(
    std::unique_ptr<const ResolvedTableScan> table_scan,
    std::unique_ptr<const ResolvedAssertRowsModified> assert_rows_modified,
    std::unique_ptr<const ResolvedColumnHolder> array_offset_column,
    std::unique_ptr<const ResolvedExpr> where_expr,
    update_item_list_t update_item_list,
    std::unique_ptr<const ResolvedScan> from_scan) {
  static_assert(std::is_base_of<
      ResolvedUpdateItem,
      typename std::decay<decltype(**(update_item_list.begin()))>::type>::value,
      "update_item_list must be a container of unique_ptr with elements of type "
      "ResolvedUpdateItem (or its descendants).");
  return MakeResolvedUpdateStmt(
      std::move(table_scan),
      std::move(assert_rows_modified),
      std::move(array_offset_column),
      std::move(where_expr),
      {std::make_move_iterator(update_item_list.begin()),
       std::make_move_iterator(update_item_list.end())},
      std::move(from_scan));
}

inline std::unique_ptr<ResolvedUpdateStmt> MakeResolvedUpdateStmt() {
  return std::unique_ptr<ResolvedUpdateStmt>(
      new ResolvedUpdateStmt());
}

// This is used by ResolvedMergeStmt to represent one WHEN ... THEN clause
// within MERGE statement.
//
// There are three types of clauses, which are MATCHED, NOT_MATCHED_BY_SOURCE
// and NOT_MATCHED_BY_TARGET. The <match_type> must have one of these values.
//
// The <match_expr> defines an optional expression to apply to the join
// result of <table_scan> and <from_scan> of the parent ResolvedMergeStmt.
//
// Each ResolvedMergeWhen must define exactly one of three operations,
//   -- INSERT: <action_type> is ResolvedMergeWhen::INSERT.
//              Both <insert_column_list> and <insert_row> are non-empty.
//              The size of <insert_column_list> must be the same with the
//              value_list size of <insert_row>, and, the column data type
//              must match.
//   -- UPDATE: <action_type> is ResolvedMergeWhen::UPDATE.
//              <update_item_list> is non-empty.
//   -- DELETE: <action_type> is ResolvedMergeWhen::DELETE.
// The INSERT, UPDATE and DELETE operations are mutually exclusive.
//
// When <match_type> is MATCHED, <action_type> must be UPDATE or DELETE.
// When <match_type> is NOT_MATCHED_BY_TARGET, <action_type> must be INSERT.
// When <match_type> is NOT_MATCHED_BY_SOURCE, <action_type> must be UPDATE
// or DELETE.
//
// The column visibility within a ResolvedMergeWhen clause is defined as
// following,
//   -- When <match_type> is MATCHED,
//      -- All columns from <table_scan> and <from_scan> are allowed in
//         <match_expr>.
//      -- If <action_type> is UPDATE, only columns from <table_scan> are
//         allowed on left side of expressions in <update_item_list>.
//         All columns from <table_scan> and <from_scan> are allowed on right
//         side of expressions in <update_item_list>.
//   -- When <match_type> is NOT_MATCHED_BY_TARGET,
//      -- Only columns from <from_scan> are allowed in <match_expr>.
//      -- Only columns from <table_scan> are allowed in
//         <insert_column_list>.
//      -- Only columns from <from_scan> are allowed in <insert_row>.
//   -- When <match_type> is NOT_MATCHED_BY_SOURCE,
//      -- Only columns from <table_scan> are allowed in <match_expr>.
//      -- If <action_type> is UPDATE, only columns from <table_scan> are
//         allowed in <update_item_list>.
class ResolvedMergeWhen final : public ResolvedArgument {
 public:
  typedef ResolvedArgument SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_MERGE_WHEN;

  typedef ResolvedMergeWhenEnums::MatchType MatchType;
  typedef ResolvedMergeWhenEnums::ActionType ActionType;
  static const MatchType MATCHED = ResolvedMergeWhenEnums::MATCHED;
  static const MatchType NOT_MATCHED_BY_SOURCE = ResolvedMergeWhenEnums::NOT_MATCHED_BY_SOURCE;
  static const MatchType NOT_MATCHED_BY_TARGET = ResolvedMergeWhenEnums::NOT_MATCHED_BY_TARGET;
  static const ActionType INSERT = ResolvedMergeWhenEnums::INSERT;
  static const ActionType UPDATE = ResolvedMergeWhenEnums::UPDATE;
  static const ActionType DELETE = ResolvedMergeWhenEnums::DELETE;

  friend std::unique_ptr<ResolvedMergeWhen> MakeResolvedMergeWhen();
 protected:
  ResolvedMergeWhen()
      : ResolvedArgument()
      , match_type_()
      , match_expr_()
      , action_type_()
      , insert_column_list_()
      , insert_row_()
      , update_item_list_()
  {}
 public:

  ResolvedMergeWhen(const ResolvedMergeWhen&) = delete;
  ResolvedMergeWhen& operator=(const ResolvedMergeWhen&) = delete;

  friend std::unique_ptr<ResolvedMergeWhen> MakeResolvedMergeWhen(
      MatchType match_type,
      std::unique_ptr<const ResolvedExpr> match_expr,
      ActionType action_type,
      const std::vector<ResolvedColumn>& insert_column_list,
      std::unique_ptr<const ResolvedInsertRow> insert_row,
      std::vector<std::unique_ptr<const ResolvedUpdateItem>> update_item_list
  );
  ~ResolvedMergeWhen() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_MERGE_WHEN; }
  std::string node_kind_string() const final { return "MergeWhen"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedMergeWhenProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedArgumentProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedMergeWhen>> RestoreFrom(
      const ResolvedMergeWhenProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  MatchType match_type() const {
    accessed_ |= (1<<0);
    return match_type_;
  }
  void set_match_type(MatchType v) {
    match_type_ = v;
  }

  const ResolvedExpr* match_expr() const {
    accessed_ |= (1<<1);
    return match_expr_.get();
  }
  void set_match_expr(std::unique_ptr<const ResolvedExpr> v) {
    match_expr_ = std::move(v);
  }

  std::unique_ptr<const ResolvedExpr> release_match_expr() {
    return std::move(match_expr_);
  }

  ActionType action_type() const {
    accessed_ |= (1<<2);
    return action_type_;
  }
  void set_action_type(ActionType v) {
    action_type_ = v;
  }

  const std::vector<ResolvedColumn>& insert_column_list() const {
    accessed_ |= (1<<3);
    return insert_column_list_;
  }
  int insert_column_list_size() const {
    if (insert_column_list_.empty()) accessed_ |= (1<<3);
    return static_cast<int>(insert_column_list_.size());
  }
  ResolvedColumn insert_column_list(int i) const {
    accessed_ |= (1<<3);
    return insert_column_list_.at(i);
  }
  void add_insert_column_list(ResolvedColumn v) {
    insert_column_list_.push_back(ResolvedColumn(v));
  }
  void set_insert_column_list(const std::vector<ResolvedColumn>& v) {
    insert_column_list_ = v;
  }
  std::vector<ResolvedColumn>* mutable_insert_column_list() {
    accessed_ |= (1<<3);
    return &insert_column_list_;
  }

  const ResolvedInsertRow* insert_row() const {
    accessed_ |= (1<<4);
    return insert_row_.get();
  }
  void set_insert_row(std::unique_ptr<const ResolvedInsertRow> v) {
    insert_row_ = std::move(v);
  }

  std::unique_ptr<const ResolvedInsertRow> release_insert_row() {
    return std::move(insert_row_);
  }

  const std::vector<std::unique_ptr<const ResolvedUpdateItem>>& update_item_list() const {
    accessed_ |= (1<<5);
    return update_item_list_;
  }
  int update_item_list_size() const {
    if (update_item_list_.empty()) accessed_ |= (1<<5);
    return static_cast<int>(update_item_list_.size());
  }
  const ResolvedUpdateItem* update_item_list(int i) const {
    accessed_ |= (1<<5);
    return update_item_list_.at(i).get();
  }
  void add_update_item_list(std::unique_ptr<const ResolvedUpdateItem> v) {
    update_item_list_.emplace_back(std::move(v));
  }
  void set_update_item_list(std::vector<std::unique_ptr<const ResolvedUpdateItem>> v) {
    update_item_list_ = std::move(v);
  }

  std::vector<std::unique_ptr<const ResolvedUpdateItem>> release_update_item_list() {
    std::vector<std::unique_ptr<const ResolvedUpdateItem>> tmp;
    update_item_list_.swap(tmp);
    return tmp;
  }

 protected:
  explicit ResolvedMergeWhen(
      MatchType match_type,
      std::unique_ptr<const ResolvedExpr> match_expr,
      ActionType action_type,
      const std::vector<ResolvedColumn>& insert_column_list,
      std::unique_ptr<const ResolvedInsertRow> insert_row,
      std::vector<std::unique_ptr<const ResolvedUpdateItem>> update_item_list,
      ConstructorOverload)
      : ResolvedArgument(
            ConstructorOverload::NEW_CONSTRUCTOR),
      match_type_(match_type),
      match_expr_(std::move(match_expr)),
      action_type_(action_type),
      insert_column_list_(insert_column_list),
      insert_row_(std::move(insert_row)),
      update_item_list_(std::move(update_item_list)) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  MatchType match_type_;
  std::unique_ptr<const ResolvedExpr> match_expr_;
  ActionType action_type_;
  std::vector<ResolvedColumn> insert_column_list_;
  std::unique_ptr<const ResolvedInsertRow> insert_row_;
  std::vector<std::unique_ptr<const ResolvedUpdateItem>> update_item_list_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedMergeWhen> MakeResolvedMergeWhen(
    ResolvedMergeWhen::MatchType match_type,
    std::unique_ptr<const ResolvedExpr> match_expr,
    ResolvedMergeWhen::ActionType action_type,
    const std::vector<ResolvedColumn>& insert_column_list,
    std::unique_ptr<const ResolvedInsertRow> insert_row,
    std::vector<std::unique_ptr<const ResolvedUpdateItem>> update_item_list) {
  return std::unique_ptr<ResolvedMergeWhen>(new ResolvedMergeWhen(
        match_type,
        std::move(match_expr),
        action_type,
        insert_column_list,
        std::move(insert_row),
        std::move(update_item_list),
        ResolvedMergeWhen::NEW_CONSTRUCTOR));
}

// Overloaded factory method for the construction of ResolvedMergeWhen with
// a wider range of inputs for node-vector inputs.  In particular allows:
// 1. unique_ptr element type can be non-const.
// 2. unique_ptr element type can be any descendant of the required type.
// 3. input container can be any object with a `begin()` and `end()`.
//
// Note, initializer lists cannot be used to pass
//  update_item_list
// due to incompatibility with unique_ptr.  Use zetasql::MakeNodeVector
// instead.
template <
  typename update_item_list_t
      = std::vector<std::unique_ptr<const ResolvedUpdateItem>>>
std::unique_ptr<ResolvedMergeWhen> MakeResolvedMergeWhen(
    ResolvedMergeWhen::MatchType match_type,
    std::unique_ptr<const ResolvedExpr> match_expr,
    ResolvedMergeWhen::ActionType action_type,
    const std::vector<ResolvedColumn>& insert_column_list,
    std::unique_ptr<const ResolvedInsertRow> insert_row,
    update_item_list_t update_item_list) {
  static_assert(std::is_base_of<
      ResolvedUpdateItem,
      typename std::decay<decltype(**(update_item_list.begin()))>::type>::value,
      "update_item_list must be a container of unique_ptr with elements of type "
      "ResolvedUpdateItem (or its descendants).");
  return MakeResolvedMergeWhen(
      match_type,
      std::move(match_expr),
      action_type,
      insert_column_list,
      std::move(insert_row),
      {std::make_move_iterator(update_item_list.begin()),
       std::make_move_iterator(update_item_list.end())});
}

inline std::unique_ptr<ResolvedMergeWhen> MakeResolvedMergeWhen() {
  return std::unique_ptr<ResolvedMergeWhen>(
      new ResolvedMergeWhen());
}

// This represents a MERGE statement.
//
// <table_scan> gives the target table to scan and creates ResolvedColumns
// for its columns.
//
// <column_access_list> indicates for each column, whether it was read and/or
// written. The columns in this vector match those of
// <table_scan.column_list>. If a column was not encountered when producing
// the resolved AST, then the value at that index will be
// ResolvedStatement::NONE(0).
//
// The output of <from_scan> is joined with <table_scan> using the join
// expression <merge_expr>.
//
// The order of elements in <when_clause_list> matters, as they are executed
// sequentially. At most one of the <when_clause_list> clause will be applied
// to each row from <table_scan>.
//
// <table_scan>, <from_scan>, <merge_expr> and <when_clause_list> are
// required. <when_clause_list> must be non-empty.
//
// See (broken link) for more detail on MERGE statement.
class ResolvedMergeStmt final : public ResolvedStatement {
 public:
  typedef ResolvedStatement SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_MERGE_STMT;

  friend std::unique_ptr<ResolvedMergeStmt> MakeResolvedMergeStmt();
 protected:
  ResolvedMergeStmt()
      : ResolvedStatement()
      , table_scan_()
      , column_access_list_()
      , from_scan_()
      , merge_expr_()
      , when_clause_list_()
  {}
 public:

  ResolvedMergeStmt(const ResolvedMergeStmt&) = delete;
  ResolvedMergeStmt& operator=(const ResolvedMergeStmt&) = delete;

  friend std::unique_ptr<ResolvedMergeStmt> MakeResolvedMergeStmt(
      std::unique_ptr<const ResolvedTableScan> table_scan,
      std::unique_ptr<const ResolvedScan> from_scan,
      std::unique_ptr<const ResolvedExpr> merge_expr,
      std::vector<std::unique_ptr<const ResolvedMergeWhen>> when_clause_list
  );
  ~ResolvedMergeStmt() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_MERGE_STMT; }
  std::string node_kind_string() const final { return "MergeStmt"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedMergeStmtProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedStatementProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedMergeStmt>> RestoreFrom(
      const ResolvedMergeStmtProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  const ResolvedTableScan* table_scan() const {
    accessed_ |= (1<<0);
    return table_scan_.get();
  }
  void set_table_scan(std::unique_ptr<const ResolvedTableScan> v) {
    table_scan_ = std::move(v);
  }

  std::unique_ptr<const ResolvedTableScan> release_table_scan() {
    return std::move(table_scan_);
  }

  const std::vector<ObjectAccess>& column_access_list() const {
    accessed_ |= (1<<1);
    return column_access_list_;
  }
  int column_access_list_size() const {
    if (column_access_list_.empty()) accessed_ |= (1<<1);
    return static_cast<int>(column_access_list_.size());
  }
  ObjectAccess column_access_list(int i) const {
    accessed_ |= (1<<1);
    return column_access_list_.at(i);
  }
  void add_column_access_list(ObjectAccess v) {
    column_access_list_.push_back(ObjectAccess(v));
  }
  void set_column_access_list(const std::vector<ObjectAccess>& v) {
    column_access_list_ = v;
  }
  std::vector<ObjectAccess>* mutable_column_access_list() {
    accessed_ |= (1<<1);
    return &column_access_list_;
  }

  const ResolvedScan* from_scan() const {
    accessed_ |= (1<<2);
    return from_scan_.get();
  }
  void set_from_scan(std::unique_ptr<const ResolvedScan> v) {
    from_scan_ = std::move(v);
  }

  std::unique_ptr<const ResolvedScan> release_from_scan() {
    return std::move(from_scan_);
  }

  const ResolvedExpr* merge_expr() const {
    accessed_ |= (1<<3);
    return merge_expr_.get();
  }
  void set_merge_expr(std::unique_ptr<const ResolvedExpr> v) {
    merge_expr_ = std::move(v);
  }

  std::unique_ptr<const ResolvedExpr> release_merge_expr() {
    return std::move(merge_expr_);
  }

  const std::vector<std::unique_ptr<const ResolvedMergeWhen>>& when_clause_list() const {
    accessed_ |= (1<<4);
    return when_clause_list_;
  }
  int when_clause_list_size() const {
    if (when_clause_list_.empty()) accessed_ |= (1<<4);
    return static_cast<int>(when_clause_list_.size());
  }
  const ResolvedMergeWhen* when_clause_list(int i) const {
    accessed_ |= (1<<4);
    return when_clause_list_.at(i).get();
  }
  void add_when_clause_list(std::unique_ptr<const ResolvedMergeWhen> v) {
    when_clause_list_.emplace_back(std::move(v));
  }
  void set_when_clause_list(std::vector<std::unique_ptr<const ResolvedMergeWhen>> v) {
    when_clause_list_ = std::move(v);
  }

  std::vector<std::unique_ptr<const ResolvedMergeWhen>> release_when_clause_list() {
    std::vector<std::unique_ptr<const ResolvedMergeWhen>> tmp;
    when_clause_list_.swap(tmp);
    return tmp;
  }

 protected:
  explicit ResolvedMergeStmt(
      std::unique_ptr<const ResolvedTableScan> table_scan,
      std::unique_ptr<const ResolvedScan> from_scan,
      std::unique_ptr<const ResolvedExpr> merge_expr,
      std::vector<std::unique_ptr<const ResolvedMergeWhen>> when_clause_list,
      ConstructorOverload)
      : ResolvedStatement(
            ConstructorOverload::NEW_CONSTRUCTOR),
      table_scan_(std::move(table_scan)),
      column_access_list_(),
      from_scan_(std::move(from_scan)),
      merge_expr_(std::move(merge_expr)),
      when_clause_list_(std::move(when_clause_list)) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  std::unique_ptr<const ResolvedTableScan> table_scan_;
  std::vector<ObjectAccess> column_access_list_;
  std::unique_ptr<const ResolvedScan> from_scan_;
  std::unique_ptr<const ResolvedExpr> merge_expr_;
  std::vector<std::unique_ptr<const ResolvedMergeWhen>> when_clause_list_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedMergeStmt> MakeResolvedMergeStmt(
    std::unique_ptr<const ResolvedTableScan> table_scan,
    std::unique_ptr<const ResolvedScan> from_scan,
    std::unique_ptr<const ResolvedExpr> merge_expr,
    std::vector<std::unique_ptr<const ResolvedMergeWhen>> when_clause_list) {
  return std::unique_ptr<ResolvedMergeStmt>(new ResolvedMergeStmt(
        std::move(table_scan),
        std::move(from_scan),
        std::move(merge_expr),
        std::move(when_clause_list),
        ResolvedMergeStmt::NEW_CONSTRUCTOR));
}

// Overloaded factory method for the construction of ResolvedMergeStmt with
// a wider range of inputs for node-vector inputs.  In particular allows:
// 1. unique_ptr element type can be non-const.
// 2. unique_ptr element type can be any descendant of the required type.
// 3. input container can be any object with a `begin()` and `end()`.
//
// Note, initializer lists cannot be used to pass
//  when_clause_list
// due to incompatibility with unique_ptr.  Use zetasql::MakeNodeVector
// instead.
template <
  typename when_clause_list_t
      = std::vector<std::unique_ptr<const ResolvedMergeWhen>>>
std::unique_ptr<ResolvedMergeStmt> MakeResolvedMergeStmt(
    std::unique_ptr<const ResolvedTableScan> table_scan,
    std::unique_ptr<const ResolvedScan> from_scan,
    std::unique_ptr<const ResolvedExpr> merge_expr,
    when_clause_list_t when_clause_list) {
  static_assert(std::is_base_of<
      ResolvedMergeWhen,
      typename std::decay<decltype(**(when_clause_list.begin()))>::type>::value,
      "when_clause_list must be a container of unique_ptr with elements of type "
      "ResolvedMergeWhen (or its descendants).");
  return MakeResolvedMergeStmt(
      std::move(table_scan),
      std::move(from_scan),
      std::move(merge_expr),
      {std::make_move_iterator(when_clause_list.begin()),
       std::make_move_iterator(when_clause_list.end())});
}

inline std::unique_ptr<ResolvedMergeStmt> MakeResolvedMergeStmt() {
  return std::unique_ptr<ResolvedMergeStmt>(
      new ResolvedMergeStmt());
}

// A grantable privilege.
//
// <action_type> is the type of privilege action, e.g. SELECT, INSERT, UPDATE
// or DELETE.
// <unit_list> is an optional list of units of the object (e.g. columns of a
// table) the privilege is restricted to. Privilege on the whole object
// should be granted/revoked if the list is empty.
class ResolvedPrivilege final : public ResolvedArgument {
 public:
  typedef ResolvedArgument SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_PRIVILEGE;

  friend std::unique_ptr<ResolvedPrivilege> MakeResolvedPrivilege();
 protected:
  ResolvedPrivilege()
      : ResolvedArgument()
      , action_type_()
      , unit_list_()
  {}
 public:

  ResolvedPrivilege(const ResolvedPrivilege&) = delete;
  ResolvedPrivilege& operator=(const ResolvedPrivilege&) = delete;

  friend std::unique_ptr<ResolvedPrivilege> MakeResolvedPrivilege(
      const std::string& action_type,
      const std::vector<std::string>& unit_list
  );
  ~ResolvedPrivilege() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_PRIVILEGE; }
  std::string node_kind_string() const final { return "Privilege"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedPrivilegeProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedArgumentProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedPrivilege>> RestoreFrom(
      const ResolvedPrivilegeProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  const std::string& action_type() const {
    accessed_ |= (1<<0);
    return action_type_;
  }
  void set_action_type(const std::string& v) {
    action_type_ = v;
  }

  const std::vector<std::string>& unit_list() const {
    accessed_ |= (1<<1);
    return unit_list_;
  }
  int unit_list_size() const {
    if (unit_list_.empty()) accessed_ |= (1<<1);
    return static_cast<int>(unit_list_.size());
  }
  std::string unit_list(int i) const {
    accessed_ |= (1<<1);
    return unit_list_.at(i);
  }
  void add_unit_list(std::string v) {
    unit_list_.push_back(std::string(v));
  }
  void set_unit_list(const std::vector<std::string>& v) {
    unit_list_ = v;
  }
  std::vector<std::string>* mutable_unit_list() {
    accessed_ |= (1<<1);
    return &unit_list_;
  }

 protected:
  explicit ResolvedPrivilege(
      const std::string& action_type,
      const std::vector<std::string>& unit_list,
      ConstructorOverload)
      : ResolvedArgument(
            ConstructorOverload::NEW_CONSTRUCTOR),
      action_type_(action_type),
      unit_list_(unit_list) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  std::string action_type_;
  std::vector<std::string> unit_list_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedPrivilege> MakeResolvedPrivilege(
    const std::string& action_type,
    const std::vector<std::string>& unit_list) {
  return std::unique_ptr<ResolvedPrivilege>(new ResolvedPrivilege(
        action_type,
        unit_list,
        ResolvedPrivilege::NEW_CONSTRUCTOR));
}

inline std::unique_ptr<ResolvedPrivilege> MakeResolvedPrivilege() {
  return std::unique_ptr<ResolvedPrivilege>(
      new ResolvedPrivilege());
}

// Common superclass of GRANT/REVOKE statements.
//
// <privilege_list> is the list of privileges to be granted/revoked. ALL
// PRIVILEGES should be granted/fromed if it is empty.
// <object_type> is an optional string identifier, e.g., TABLE, VIEW.
// <name_path> is a vector of segments of the object identifier's pathname.
// <grantee_list> (DEPRECATED) is the list of grantees (strings).
// <grantee_expr_list> is the list of grantees, and may include parameters.
//
// Only one of <grantee_list> or <grantee_expr_list> will be populated,
// depending on whether or not the FEATURE_PARAMETERS_IN_GRANTEE_LIST
// is enabled.  The <grantee_list> is deprecated, and will be removed
// along with the corresponding FEATURE once all engines have migrated to
// use the <grantee_expr_list>.  Once <grantee_expr_list> is the only
// one, then it should be marked as NOT_IGNORABLE.
class ResolvedGrantOrRevokeStmt  : public ResolvedStatement {
 public:
  typedef ResolvedStatement SUPER;

  // Number of leaf node types that exist as descendants of this abstract type.
  static const int NUM_DESCENDANT_LEAF_TYPES = 2;

  ResolvedGrantOrRevokeStmt()
      : ResolvedStatement()
      , privilege_list_()
      , object_type_()
      , name_path_()
      , grantee_list_()
      , grantee_expr_list_()
  {}
 public:

  ResolvedGrantOrRevokeStmt(const ResolvedGrantOrRevokeStmt&) = delete;
  ResolvedGrantOrRevokeStmt& operator=(const ResolvedGrantOrRevokeStmt&) = delete;

  ~ResolvedGrantOrRevokeStmt() override;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const override;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const override;

  zetasql_base::Status CheckFieldsAccessed() const override;
  void ClearFieldsAccessed() const override;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedGrantOrRevokeStmtProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedStatementProto* proto) const final;

  virtual zetasql_base::Status SaveTo(
      Type::FileDescriptorSetMap* file_descriptor_set_map,
      AnyResolvedGrantOrRevokeStmtProto* proto) const = 0;
  static zetasql_base::StatusOr<std::unique_ptr<ResolvedGrantOrRevokeStmt>> RestoreFrom(
      const AnyResolvedGrantOrRevokeStmtProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const override;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) override;

  // Member fields

  const std::vector<std::unique_ptr<const ResolvedPrivilege>>& privilege_list() const {
    accessed_ |= (1<<0);
    return privilege_list_;
  }
  int privilege_list_size() const {
    if (privilege_list_.empty()) accessed_ |= (1<<0);
    return static_cast<int>(privilege_list_.size());
  }
  const ResolvedPrivilege* privilege_list(int i) const {
    accessed_ |= (1<<0);
    return privilege_list_.at(i).get();
  }
  void add_privilege_list(std::unique_ptr<const ResolvedPrivilege> v) {
    privilege_list_.emplace_back(std::move(v));
  }
  void set_privilege_list(std::vector<std::unique_ptr<const ResolvedPrivilege>> v) {
    privilege_list_ = std::move(v);
  }

  std::vector<std::unique_ptr<const ResolvedPrivilege>> release_privilege_list() {
    std::vector<std::unique_ptr<const ResolvedPrivilege>> tmp;
    privilege_list_.swap(tmp);
    return tmp;
  }

  const std::string& object_type() const {
    accessed_ |= (1<<1);
    return object_type_;
  }
  void set_object_type(const std::string& v) {
    object_type_ = v;
  }

  const std::vector<std::string>& name_path() const {
    accessed_ |= (1<<2);
    return name_path_;
  }
  int name_path_size() const {
    if (name_path_.empty()) accessed_ |= (1<<2);
    return static_cast<int>(name_path_.size());
  }
  std::string name_path(int i) const {
    accessed_ |= (1<<2);
    return name_path_.at(i);
  }
  void add_name_path(std::string v) {
    name_path_.push_back(std::string(v));
  }
  void set_name_path(const std::vector<std::string>& v) {
    name_path_ = v;
  }
  std::vector<std::string>* mutable_name_path() {
    accessed_ |= (1<<2);
    return &name_path_;
  }

  const std::vector<std::string>& grantee_list() const {
    accessed_ |= (1<<3);
    return grantee_list_;
  }
  int grantee_list_size() const {
    if (grantee_list_.empty()) accessed_ |= (1<<3);
    return static_cast<int>(grantee_list_.size());
  }
  std::string grantee_list(int i) const {
    accessed_ |= (1<<3);
    return grantee_list_.at(i);
  }
  void add_grantee_list(std::string v) {
    grantee_list_.push_back(std::string(v));
  }
  void set_grantee_list(const std::vector<std::string>& v) {
    grantee_list_ = v;
  }
  std::vector<std::string>* mutable_grantee_list() {
    accessed_ |= (1<<3);
    return &grantee_list_;
  }

  const std::vector<std::unique_ptr<const ResolvedExpr>>& grantee_expr_list() const {
    accessed_ |= (1<<4);
    return grantee_expr_list_;
  }
  int grantee_expr_list_size() const {
    if (grantee_expr_list_.empty()) accessed_ |= (1<<4);
    return static_cast<int>(grantee_expr_list_.size());
  }
  const ResolvedExpr* grantee_expr_list(int i) const {
    accessed_ |= (1<<4);
    return grantee_expr_list_.at(i).get();
  }
  void add_grantee_expr_list(std::unique_ptr<const ResolvedExpr> v) {
    grantee_expr_list_.emplace_back(std::move(v));
  }
  void set_grantee_expr_list(std::vector<std::unique_ptr<const ResolvedExpr>> v) {
    grantee_expr_list_ = std::move(v);
  }

  std::vector<std::unique_ptr<const ResolvedExpr>> release_grantee_expr_list() {
    std::vector<std::unique_ptr<const ResolvedExpr>> tmp;
    grantee_expr_list_.swap(tmp);
    return tmp;
  }

 protected:
  explicit ResolvedGrantOrRevokeStmt(
      std::vector<std::unique_ptr<const ResolvedPrivilege>> privilege_list,
      const std::string& object_type,
      const std::vector<std::string>& name_path,
      const std::vector<std::string>& grantee_list,
      std::vector<std::unique_ptr<const ResolvedExpr>> grantee_expr_list,
      ConstructorOverload)
      : ResolvedStatement(
            ConstructorOverload::NEW_CONSTRUCTOR),
      privilege_list_(std::move(privilege_list)),
      object_type_(object_type),
      name_path_(name_path),
      grantee_list_(grantee_list),
      grantee_expr_list_(std::move(grantee_expr_list)) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const override;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  std::vector<std::unique_ptr<const ResolvedPrivilege>> privilege_list_;
  std::string object_type_;
  std::vector<std::string> name_path_;
  std::vector<std::string> grantee_list_;
  std::vector<std::unique_ptr<const ResolvedExpr>> grantee_expr_list_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

// A GRANT statement. It represents the action to grant a list of privileges
// on a specific object to/from list of grantees.
class ResolvedGrantStmt final : public ResolvedGrantOrRevokeStmt {
 public:
  typedef ResolvedGrantOrRevokeStmt SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_GRANT_STMT;

  friend std::unique_ptr<ResolvedGrantStmt> MakeResolvedGrantStmt();
 protected:
  ResolvedGrantStmt()
      : ResolvedGrantOrRevokeStmt()
  {}
 public:

  ResolvedGrantStmt(const ResolvedGrantStmt&) = delete;
  ResolvedGrantStmt& operator=(const ResolvedGrantStmt&) = delete;

  friend std::unique_ptr<ResolvedGrantStmt> MakeResolvedGrantStmt(
      std::vector<std::unique_ptr<const ResolvedPrivilege>> privilege_list,
      const std::string& object_type,
      const std::vector<std::string>& name_path,
      const std::vector<std::string>& grantee_list,
      std::vector<std::unique_ptr<const ResolvedExpr>> grantee_expr_list
  );
  ~ResolvedGrantStmt() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_GRANT_STMT; }
  std::string node_kind_string() const final { return "GrantStmt"; }

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedGrantStmtProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedGrantOrRevokeStmtProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedGrantStmt>> RestoreFrom(
      const ResolvedGrantStmtProto& proto,
      const ResolvedNode::RestoreParams& params);

  // Member fields

 protected:
  explicit ResolvedGrantStmt(
      std::vector<std::unique_ptr<const ResolvedPrivilege>> privilege_list,
      const std::string& object_type,
      const std::vector<std::string>& name_path,
      const std::vector<std::string>& grantee_list,
      std::vector<std::unique_ptr<const ResolvedExpr>> grantee_expr_list,
      ConstructorOverload)
      : ResolvedGrantOrRevokeStmt(
            std::move(privilege_list),
            object_type,
            name_path,
            grantee_list,
            std::move(grantee_expr_list),
            ConstructorOverload::NEW_CONSTRUCTOR) {
  }

 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

};

inline std::unique_ptr<ResolvedGrantStmt> MakeResolvedGrantStmt(
    std::vector<std::unique_ptr<const ResolvedPrivilege>> privilege_list,
    const std::string& object_type,
    const std::vector<std::string>& name_path,
    const std::vector<std::string>& grantee_list,
    std::vector<std::unique_ptr<const ResolvedExpr>> grantee_expr_list) {
  return std::unique_ptr<ResolvedGrantStmt>(new ResolvedGrantStmt(
        std::move(privilege_list),
        object_type,
        name_path,
        grantee_list,
        std::move(grantee_expr_list),
        ResolvedGrantStmt::NEW_CONSTRUCTOR));
}

// Overloaded factory method for the construction of ResolvedGrantStmt with
// a wider range of inputs for node-vector inputs.  In particular allows:
// 1. unique_ptr element type can be non-const.
// 2. unique_ptr element type can be any descendant of the required type.
// 3. input container can be any object with a `begin()` and `end()`.
//
// Note, initializer lists cannot be used to pass
//  privilege_list, grantee_expr_list
// due to incompatibility with unique_ptr.  Use zetasql::MakeNodeVector
// instead.
template <
  typename privilege_list_t
      = std::vector<std::unique_ptr<const ResolvedPrivilege>>,
  typename grantee_expr_list_t
      = std::vector<std::unique_ptr<const ResolvedExpr>>>
std::unique_ptr<ResolvedGrantStmt> MakeResolvedGrantStmt(
    privilege_list_t privilege_list,
    const std::string& object_type,
    const std::vector<std::string>& name_path,
    const std::vector<std::string>& grantee_list,
    grantee_expr_list_t grantee_expr_list) {
  static_assert(std::is_base_of<
      ResolvedPrivilege,
      typename std::decay<decltype(**(privilege_list.begin()))>::type>::value,
      "privilege_list must be a container of unique_ptr with elements of type "
      "ResolvedPrivilege (or its descendants).");
  static_assert(std::is_base_of<
      ResolvedExpr,
      typename std::decay<decltype(**(grantee_expr_list.begin()))>::type>::value,
      "grantee_expr_list must be a container of unique_ptr with elements of type "
      "ResolvedExpr (or its descendants).");
  return MakeResolvedGrantStmt(
      {std::make_move_iterator(privilege_list.begin()),
       std::make_move_iterator(privilege_list.end())},
      object_type,
      name_path,
      grantee_list,
      {std::make_move_iterator(grantee_expr_list.begin()),
       std::make_move_iterator(grantee_expr_list.end())});
}

inline std::unique_ptr<ResolvedGrantStmt> MakeResolvedGrantStmt() {
  return std::unique_ptr<ResolvedGrantStmt>(
      new ResolvedGrantStmt());
}

// A REVOKE statement. It represents the action to revoke a list of
// privileges on a specific object to/from list of grantees.
class ResolvedRevokeStmt final : public ResolvedGrantOrRevokeStmt {
 public:
  typedef ResolvedGrantOrRevokeStmt SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_REVOKE_STMT;

  friend std::unique_ptr<ResolvedRevokeStmt> MakeResolvedRevokeStmt();
 protected:
  ResolvedRevokeStmt()
      : ResolvedGrantOrRevokeStmt()
  {}
 public:

  ResolvedRevokeStmt(const ResolvedRevokeStmt&) = delete;
  ResolvedRevokeStmt& operator=(const ResolvedRevokeStmt&) = delete;

  friend std::unique_ptr<ResolvedRevokeStmt> MakeResolvedRevokeStmt(
      std::vector<std::unique_ptr<const ResolvedPrivilege>> privilege_list,
      const std::string& object_type,
      const std::vector<std::string>& name_path,
      const std::vector<std::string>& grantee_list,
      std::vector<std::unique_ptr<const ResolvedExpr>> grantee_expr_list
  );
  ~ResolvedRevokeStmt() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_REVOKE_STMT; }
  std::string node_kind_string() const final { return "RevokeStmt"; }

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedRevokeStmtProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedGrantOrRevokeStmtProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedRevokeStmt>> RestoreFrom(
      const ResolvedRevokeStmtProto& proto,
      const ResolvedNode::RestoreParams& params);

  // Member fields

 protected:
  explicit ResolvedRevokeStmt(
      std::vector<std::unique_ptr<const ResolvedPrivilege>> privilege_list,
      const std::string& object_type,
      const std::vector<std::string>& name_path,
      const std::vector<std::string>& grantee_list,
      std::vector<std::unique_ptr<const ResolvedExpr>> grantee_expr_list,
      ConstructorOverload)
      : ResolvedGrantOrRevokeStmt(
            std::move(privilege_list),
            object_type,
            name_path,
            grantee_list,
            std::move(grantee_expr_list),
            ConstructorOverload::NEW_CONSTRUCTOR) {
  }

 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

};

inline std::unique_ptr<ResolvedRevokeStmt> MakeResolvedRevokeStmt(
    std::vector<std::unique_ptr<const ResolvedPrivilege>> privilege_list,
    const std::string& object_type,
    const std::vector<std::string>& name_path,
    const std::vector<std::string>& grantee_list,
    std::vector<std::unique_ptr<const ResolvedExpr>> grantee_expr_list) {
  return std::unique_ptr<ResolvedRevokeStmt>(new ResolvedRevokeStmt(
        std::move(privilege_list),
        object_type,
        name_path,
        grantee_list,
        std::move(grantee_expr_list),
        ResolvedRevokeStmt::NEW_CONSTRUCTOR));
}

// Overloaded factory method for the construction of ResolvedRevokeStmt with
// a wider range of inputs for node-vector inputs.  In particular allows:
// 1. unique_ptr element type can be non-const.
// 2. unique_ptr element type can be any descendant of the required type.
// 3. input container can be any object with a `begin()` and `end()`.
//
// Note, initializer lists cannot be used to pass
//  privilege_list, grantee_expr_list
// due to incompatibility with unique_ptr.  Use zetasql::MakeNodeVector
// instead.
template <
  typename privilege_list_t
      = std::vector<std::unique_ptr<const ResolvedPrivilege>>,
  typename grantee_expr_list_t
      = std::vector<std::unique_ptr<const ResolvedExpr>>>
std::unique_ptr<ResolvedRevokeStmt> MakeResolvedRevokeStmt(
    privilege_list_t privilege_list,
    const std::string& object_type,
    const std::vector<std::string>& name_path,
    const std::vector<std::string>& grantee_list,
    grantee_expr_list_t grantee_expr_list) {
  static_assert(std::is_base_of<
      ResolvedPrivilege,
      typename std::decay<decltype(**(privilege_list.begin()))>::type>::value,
      "privilege_list must be a container of unique_ptr with elements of type "
      "ResolvedPrivilege (or its descendants).");
  static_assert(std::is_base_of<
      ResolvedExpr,
      typename std::decay<decltype(**(grantee_expr_list.begin()))>::type>::value,
      "grantee_expr_list must be a container of unique_ptr with elements of type "
      "ResolvedExpr (or its descendants).");
  return MakeResolvedRevokeStmt(
      {std::make_move_iterator(privilege_list.begin()),
       std::make_move_iterator(privilege_list.end())},
      object_type,
      name_path,
      grantee_list,
      {std::make_move_iterator(grantee_expr_list.begin()),
       std::make_move_iterator(grantee_expr_list.end())});
}

inline std::unique_ptr<ResolvedRevokeStmt> MakeResolvedRevokeStmt() {
  return std::unique_ptr<ResolvedRevokeStmt>(
      new ResolvedRevokeStmt());
}

// Common super class for statements:
//   ALTER <object> [IF EXISTS] <name_path> <alter_action_list>
//
// <name_path> is a vector giving the identifier path in the table <name>.
// <alter_action_list> is a vector of actions to be done to the object.
// <is_if_exists> silently ignores the "name_path does not exist" error.
class ResolvedAlterObjectStmt  : public ResolvedStatement {
 public:
  typedef ResolvedStatement SUPER;

  // Number of leaf node types that exist as descendants of this abstract type.
  static const int NUM_DESCENDANT_LEAF_TYPES = 3;

  ResolvedAlterObjectStmt()
      : ResolvedStatement()
      , name_path_()
      , alter_action_list_()
      , is_if_exists_()
  {}
 public:

  ResolvedAlterObjectStmt(const ResolvedAlterObjectStmt&) = delete;
  ResolvedAlterObjectStmt& operator=(const ResolvedAlterObjectStmt&) = delete;

  ~ResolvedAlterObjectStmt() override;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const override;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const override;

  zetasql_base::Status CheckFieldsAccessed() const override;
  void ClearFieldsAccessed() const override;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedAlterObjectStmtProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedStatementProto* proto) const final;

  virtual zetasql_base::Status SaveTo(
      Type::FileDescriptorSetMap* file_descriptor_set_map,
      AnyResolvedAlterObjectStmtProto* proto) const = 0;
  static zetasql_base::StatusOr<std::unique_ptr<ResolvedAlterObjectStmt>> RestoreFrom(
      const AnyResolvedAlterObjectStmtProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const override;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) override;

  // Member fields

  const std::vector<std::string>& name_path() const {
    accessed_ |= (1<<0);
    return name_path_;
  }
  int name_path_size() const {
    if (name_path_.empty()) accessed_ |= (1<<0);
    return static_cast<int>(name_path_.size());
  }
  std::string name_path(int i) const {
    accessed_ |= (1<<0);
    return name_path_.at(i);
  }
  void add_name_path(std::string v) {
    name_path_.push_back(std::string(v));
  }
  void set_name_path(const std::vector<std::string>& v) {
    name_path_ = v;
  }
  std::vector<std::string>* mutable_name_path() {
    accessed_ |= (1<<0);
    return &name_path_;
  }

  const std::vector<std::unique_ptr<const ResolvedAlterAction>>& alter_action_list() const {
    accessed_ |= (1<<1);
    return alter_action_list_;
  }
  int alter_action_list_size() const {
    if (alter_action_list_.empty()) accessed_ |= (1<<1);
    return static_cast<int>(alter_action_list_.size());
  }
  const ResolvedAlterAction* alter_action_list(int i) const {
    accessed_ |= (1<<1);
    return alter_action_list_.at(i).get();
  }
  void add_alter_action_list(std::unique_ptr<const ResolvedAlterAction> v) {
    alter_action_list_.emplace_back(std::move(v));
  }
  void set_alter_action_list(std::vector<std::unique_ptr<const ResolvedAlterAction>> v) {
    alter_action_list_ = std::move(v);
  }

  std::vector<std::unique_ptr<const ResolvedAlterAction>> release_alter_action_list() {
    std::vector<std::unique_ptr<const ResolvedAlterAction>> tmp;
    alter_action_list_.swap(tmp);
    return tmp;
  }

  bool is_if_exists() const {
    accessed_ |= (1<<2);
    return is_if_exists_;
  }
  void set_is_if_exists(bool v) {
    is_if_exists_ = v;
  }

 protected:
  explicit ResolvedAlterObjectStmt(
      const std::vector<std::string>& name_path,
      std::vector<std::unique_ptr<const ResolvedAlterAction>> alter_action_list,
      bool is_if_exists,
      ConstructorOverload)
      : ResolvedStatement(
            ConstructorOverload::NEW_CONSTRUCTOR),
      name_path_(name_path),
      alter_action_list_(std::move(alter_action_list)),
      is_if_exists_(is_if_exists) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const override;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  std::vector<std::string> name_path_;
  std::vector<std::unique_ptr<const ResolvedAlterAction>> alter_action_list_;
  bool is_if_exists_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

// This statement:
// ALTER MATERIALIZED VIEW [IF EXISTS] <name_path> <alter_action_list>
class ResolvedAlterMaterializedViewStmt final : public ResolvedAlterObjectStmt {
 public:
  typedef ResolvedAlterObjectStmt SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_ALTER_MATERIALIZED_VIEW_STMT;

  friend std::unique_ptr<ResolvedAlterMaterializedViewStmt> MakeResolvedAlterMaterializedViewStmt();
 protected:
  ResolvedAlterMaterializedViewStmt()
      : ResolvedAlterObjectStmt()
  {}
 public:

  ResolvedAlterMaterializedViewStmt(const ResolvedAlterMaterializedViewStmt&) = delete;
  ResolvedAlterMaterializedViewStmt& operator=(const ResolvedAlterMaterializedViewStmt&) = delete;

  friend std::unique_ptr<ResolvedAlterMaterializedViewStmt> MakeResolvedAlterMaterializedViewStmt(
      const std::vector<std::string>& name_path,
      std::vector<std::unique_ptr<const ResolvedAlterAction>> alter_action_list,
      bool is_if_exists
  );
  ~ResolvedAlterMaterializedViewStmt() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_ALTER_MATERIALIZED_VIEW_STMT; }
  std::string node_kind_string() const final { return "AlterMaterializedViewStmt"; }

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedAlterMaterializedViewStmtProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedAlterObjectStmtProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedAlterMaterializedViewStmt>> RestoreFrom(
      const ResolvedAlterMaterializedViewStmtProto& proto,
      const ResolvedNode::RestoreParams& params);

  // Member fields

 protected:
  explicit ResolvedAlterMaterializedViewStmt(
      const std::vector<std::string>& name_path,
      std::vector<std::unique_ptr<const ResolvedAlterAction>> alter_action_list,
      bool is_if_exists,
      ConstructorOverload)
      : ResolvedAlterObjectStmt(
            name_path,
            std::move(alter_action_list),
            is_if_exists,
            ConstructorOverload::NEW_CONSTRUCTOR) {
  }

 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

};

inline std::unique_ptr<ResolvedAlterMaterializedViewStmt> MakeResolvedAlterMaterializedViewStmt(
    const std::vector<std::string>& name_path,
    std::vector<std::unique_ptr<const ResolvedAlterAction>> alter_action_list,
    bool is_if_exists) {
  return std::unique_ptr<ResolvedAlterMaterializedViewStmt>(new ResolvedAlterMaterializedViewStmt(
        name_path,
        std::move(alter_action_list),
        is_if_exists,
        ResolvedAlterMaterializedViewStmt::NEW_CONSTRUCTOR));
}

// Overloaded factory method for the construction of ResolvedAlterMaterializedViewStmt with
// a wider range of inputs for node-vector inputs.  In particular allows:
// 1. unique_ptr element type can be non-const.
// 2. unique_ptr element type can be any descendant of the required type.
// 3. input container can be any object with a `begin()` and `end()`.
//
// Note, initializer lists cannot be used to pass
//  alter_action_list
// due to incompatibility with unique_ptr.  Use zetasql::MakeNodeVector
// instead.
template <
  typename alter_action_list_t
      = std::vector<std::unique_ptr<const ResolvedAlterAction>>>
std::unique_ptr<ResolvedAlterMaterializedViewStmt> MakeResolvedAlterMaterializedViewStmt(
    const std::vector<std::string>& name_path,
    alter_action_list_t alter_action_list,
    bool is_if_exists) {
  static_assert(std::is_base_of<
      ResolvedAlterAction,
      typename std::decay<decltype(**(alter_action_list.begin()))>::type>::value,
      "alter_action_list must be a container of unique_ptr with elements of type "
      "ResolvedAlterAction (or its descendants).");
  return MakeResolvedAlterMaterializedViewStmt(
      name_path,
      {std::make_move_iterator(alter_action_list.begin()),
       std::make_move_iterator(alter_action_list.end())},
      is_if_exists);
}

inline std::unique_ptr<ResolvedAlterMaterializedViewStmt> MakeResolvedAlterMaterializedViewStmt() {
  return std::unique_ptr<ResolvedAlterMaterializedViewStmt>(
      new ResolvedAlterMaterializedViewStmt());
}

// This statement:
// ALTER TABLE [IF EXISTS] <name_path> <alter_action_list>
class ResolvedAlterTableStmt final : public ResolvedAlterObjectStmt {
 public:
  typedef ResolvedAlterObjectStmt SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_ALTER_TABLE_STMT;

  friend std::unique_ptr<ResolvedAlterTableStmt> MakeResolvedAlterTableStmt();
 protected:
  ResolvedAlterTableStmt()
      : ResolvedAlterObjectStmt()
  {}
 public:

  ResolvedAlterTableStmt(const ResolvedAlterTableStmt&) = delete;
  ResolvedAlterTableStmt& operator=(const ResolvedAlterTableStmt&) = delete;

  friend std::unique_ptr<ResolvedAlterTableStmt> MakeResolvedAlterTableStmt(
      const std::vector<std::string>& name_path,
      std::vector<std::unique_ptr<const ResolvedAlterAction>> alter_action_list,
      bool is_if_exists
  );
  ~ResolvedAlterTableStmt() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_ALTER_TABLE_STMT; }
  std::string node_kind_string() const final { return "AlterTableStmt"; }

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedAlterTableStmtProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedAlterObjectStmtProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedAlterTableStmt>> RestoreFrom(
      const ResolvedAlterTableStmtProto& proto,
      const ResolvedNode::RestoreParams& params);

  // Member fields

 protected:
  explicit ResolvedAlterTableStmt(
      const std::vector<std::string>& name_path,
      std::vector<std::unique_ptr<const ResolvedAlterAction>> alter_action_list,
      bool is_if_exists,
      ConstructorOverload)
      : ResolvedAlterObjectStmt(
            name_path,
            std::move(alter_action_list),
            is_if_exists,
            ConstructorOverload::NEW_CONSTRUCTOR) {
  }

 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

};

inline std::unique_ptr<ResolvedAlterTableStmt> MakeResolvedAlterTableStmt(
    const std::vector<std::string>& name_path,
    std::vector<std::unique_ptr<const ResolvedAlterAction>> alter_action_list,
    bool is_if_exists) {
  return std::unique_ptr<ResolvedAlterTableStmt>(new ResolvedAlterTableStmt(
        name_path,
        std::move(alter_action_list),
        is_if_exists,
        ResolvedAlterTableStmt::NEW_CONSTRUCTOR));
}

// Overloaded factory method for the construction of ResolvedAlterTableStmt with
// a wider range of inputs for node-vector inputs.  In particular allows:
// 1. unique_ptr element type can be non-const.
// 2. unique_ptr element type can be any descendant of the required type.
// 3. input container can be any object with a `begin()` and `end()`.
//
// Note, initializer lists cannot be used to pass
//  alter_action_list
// due to incompatibility with unique_ptr.  Use zetasql::MakeNodeVector
// instead.
template <
  typename alter_action_list_t
      = std::vector<std::unique_ptr<const ResolvedAlterAction>>>
std::unique_ptr<ResolvedAlterTableStmt> MakeResolvedAlterTableStmt(
    const std::vector<std::string>& name_path,
    alter_action_list_t alter_action_list,
    bool is_if_exists) {
  static_assert(std::is_base_of<
      ResolvedAlterAction,
      typename std::decay<decltype(**(alter_action_list.begin()))>::type>::value,
      "alter_action_list must be a container of unique_ptr with elements of type "
      "ResolvedAlterAction (or its descendants).");
  return MakeResolvedAlterTableStmt(
      name_path,
      {std::make_move_iterator(alter_action_list.begin()),
       std::make_move_iterator(alter_action_list.end())},
      is_if_exists);
}

inline std::unique_ptr<ResolvedAlterTableStmt> MakeResolvedAlterTableStmt() {
  return std::unique_ptr<ResolvedAlterTableStmt>(
      new ResolvedAlterTableStmt());
}

// This statement:
// ALTER VIEW [IF EXISTS] <name_path> <alter_action_list>
class ResolvedAlterViewStmt final : public ResolvedAlterObjectStmt {
 public:
  typedef ResolvedAlterObjectStmt SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_ALTER_VIEW_STMT;

  friend std::unique_ptr<ResolvedAlterViewStmt> MakeResolvedAlterViewStmt();
 protected:
  ResolvedAlterViewStmt()
      : ResolvedAlterObjectStmt()
  {}
 public:

  ResolvedAlterViewStmt(const ResolvedAlterViewStmt&) = delete;
  ResolvedAlterViewStmt& operator=(const ResolvedAlterViewStmt&) = delete;

  friend std::unique_ptr<ResolvedAlterViewStmt> MakeResolvedAlterViewStmt(
      const std::vector<std::string>& name_path,
      std::vector<std::unique_ptr<const ResolvedAlterAction>> alter_action_list,
      bool is_if_exists
  );
  ~ResolvedAlterViewStmt() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_ALTER_VIEW_STMT; }
  std::string node_kind_string() const final { return "AlterViewStmt"; }

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedAlterViewStmtProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedAlterObjectStmtProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedAlterViewStmt>> RestoreFrom(
      const ResolvedAlterViewStmtProto& proto,
      const ResolvedNode::RestoreParams& params);

  // Member fields

 protected:
  explicit ResolvedAlterViewStmt(
      const std::vector<std::string>& name_path,
      std::vector<std::unique_ptr<const ResolvedAlterAction>> alter_action_list,
      bool is_if_exists,
      ConstructorOverload)
      : ResolvedAlterObjectStmt(
            name_path,
            std::move(alter_action_list),
            is_if_exists,
            ConstructorOverload::NEW_CONSTRUCTOR) {
  }

 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

};

inline std::unique_ptr<ResolvedAlterViewStmt> MakeResolvedAlterViewStmt(
    const std::vector<std::string>& name_path,
    std::vector<std::unique_ptr<const ResolvedAlterAction>> alter_action_list,
    bool is_if_exists) {
  return std::unique_ptr<ResolvedAlterViewStmt>(new ResolvedAlterViewStmt(
        name_path,
        std::move(alter_action_list),
        is_if_exists,
        ResolvedAlterViewStmt::NEW_CONSTRUCTOR));
}

// Overloaded factory method for the construction of ResolvedAlterViewStmt with
// a wider range of inputs for node-vector inputs.  In particular allows:
// 1. unique_ptr element type can be non-const.
// 2. unique_ptr element type can be any descendant of the required type.
// 3. input container can be any object with a `begin()` and `end()`.
//
// Note, initializer lists cannot be used to pass
//  alter_action_list
// due to incompatibility with unique_ptr.  Use zetasql::MakeNodeVector
// instead.
template <
  typename alter_action_list_t
      = std::vector<std::unique_ptr<const ResolvedAlterAction>>>
std::unique_ptr<ResolvedAlterViewStmt> MakeResolvedAlterViewStmt(
    const std::vector<std::string>& name_path,
    alter_action_list_t alter_action_list,
    bool is_if_exists) {
  static_assert(std::is_base_of<
      ResolvedAlterAction,
      typename std::decay<decltype(**(alter_action_list.begin()))>::type>::value,
      "alter_action_list must be a container of unique_ptr with elements of type "
      "ResolvedAlterAction (or its descendants).");
  return MakeResolvedAlterViewStmt(
      name_path,
      {std::make_move_iterator(alter_action_list.begin()),
       std::make_move_iterator(alter_action_list.end())},
      is_if_exists);
}

inline std::unique_ptr<ResolvedAlterViewStmt> MakeResolvedAlterViewStmt() {
  return std::unique_ptr<ResolvedAlterViewStmt>(
      new ResolvedAlterViewStmt());
}

// A common super class for all actions in statement ALTER <object>
class ResolvedAlterAction  : public ResolvedArgument {
 public:
  typedef ResolvedArgument SUPER;

  // Number of leaf node types that exist as descendants of this abstract type.
  static const int NUM_DESCENDANT_LEAF_TYPES = 1;

  ResolvedAlterAction()
      : ResolvedArgument()
  {}
 public:

  ResolvedAlterAction(const ResolvedAlterAction&) = delete;
  ResolvedAlterAction& operator=(const ResolvedAlterAction&) = delete;

  ~ResolvedAlterAction() override;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const override;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const override;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedAlterActionProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedArgumentProto* proto) const final;

  virtual zetasql_base::Status SaveTo(
      Type::FileDescriptorSetMap* file_descriptor_set_map,
      AnyResolvedAlterActionProto* proto) const = 0;
  static zetasql_base::StatusOr<std::unique_ptr<ResolvedAlterAction>> RestoreFrom(
      const AnyResolvedAlterActionProto& proto,
      const ResolvedNode::RestoreParams& params);

  // Member fields

 protected:
  explicit ResolvedAlterAction(
      ConstructorOverload)
      : ResolvedArgument(
            ConstructorOverload::NEW_CONSTRUCTOR) {
  }

 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

};

// SET OPTIONS action for ALTER <object> statement
//
// <option_list> has engine-specific directives that specify how to
//               alter the metadata for this object.
class ResolvedSetOptionsAction final : public ResolvedAlterAction {
 public:
  typedef ResolvedAlterAction SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_SET_OPTIONS_ACTION;

  friend std::unique_ptr<ResolvedSetOptionsAction> MakeResolvedSetOptionsAction();
 protected:
  ResolvedSetOptionsAction()
      : ResolvedAlterAction()
      , option_list_()
  {}
 public:

  ResolvedSetOptionsAction(const ResolvedSetOptionsAction&) = delete;
  ResolvedSetOptionsAction& operator=(const ResolvedSetOptionsAction&) = delete;

  friend std::unique_ptr<ResolvedSetOptionsAction> MakeResolvedSetOptionsAction(
      std::vector<std::unique_ptr<const ResolvedOption>> option_list
  );
  ~ResolvedSetOptionsAction() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_SET_OPTIONS_ACTION; }
  std::string node_kind_string() const final { return "SetOptionsAction"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedSetOptionsActionProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedAlterActionProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedSetOptionsAction>> RestoreFrom(
      const ResolvedSetOptionsActionProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  const std::vector<std::unique_ptr<const ResolvedOption>>& option_list() const {
    accessed_ |= (1<<0);
    return option_list_;
  }
  int option_list_size() const {
    if (option_list_.empty()) accessed_ |= (1<<0);
    return static_cast<int>(option_list_.size());
  }
  const ResolvedOption* option_list(int i) const {
    accessed_ |= (1<<0);
    return option_list_.at(i).get();
  }
  void add_option_list(std::unique_ptr<const ResolvedOption> v) {
    option_list_.emplace_back(std::move(v));
  }
  void set_option_list(std::vector<std::unique_ptr<const ResolvedOption>> v) {
    option_list_ = std::move(v);
  }

  std::vector<std::unique_ptr<const ResolvedOption>> release_option_list() {
    std::vector<std::unique_ptr<const ResolvedOption>> tmp;
    option_list_.swap(tmp);
    return tmp;
  }

 protected:
  explicit ResolvedSetOptionsAction(
      std::vector<std::unique_ptr<const ResolvedOption>> option_list,
      ConstructorOverload)
      : ResolvedAlterAction(
            ConstructorOverload::NEW_CONSTRUCTOR),
      option_list_(std::move(option_list)) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  std::vector<std::unique_ptr<const ResolvedOption>> option_list_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedSetOptionsAction> MakeResolvedSetOptionsAction(
    std::vector<std::unique_ptr<const ResolvedOption>> option_list) {
  return std::unique_ptr<ResolvedSetOptionsAction>(new ResolvedSetOptionsAction(
        std::move(option_list),
        ResolvedSetOptionsAction::NEW_CONSTRUCTOR));
}

// Overloaded factory method for the construction of ResolvedSetOptionsAction with
// a wider range of inputs for node-vector inputs.  In particular allows:
// 1. unique_ptr element type can be non-const.
// 2. unique_ptr element type can be any descendant of the required type.
// 3. input container can be any object with a `begin()` and `end()`.
//
// Note, initializer lists cannot be used to pass
//  option_list
// due to incompatibility with unique_ptr.  Use zetasql::MakeNodeVector
// instead.
template <
  typename option_list_t
      = std::vector<std::unique_ptr<const ResolvedOption>>>
std::unique_ptr<ResolvedSetOptionsAction> MakeResolvedSetOptionsAction(
    option_list_t option_list) {
  static_assert(std::is_base_of<
      ResolvedOption,
      typename std::decay<decltype(**(option_list.begin()))>::type>::value,
      "option_list must be a container of unique_ptr with elements of type "
      "ResolvedOption (or its descendants).");
  return MakeResolvedSetOptionsAction(
      {std::make_move_iterator(option_list.begin()),
       std::make_move_iterator(option_list.end())});
}

inline std::unique_ptr<ResolvedSetOptionsAction> MakeResolvedSetOptionsAction() {
  return std::unique_ptr<ResolvedSetOptionsAction>(
      new ResolvedSetOptionsAction());
}

// This statement:
//   ALTER TABLE [IF EXISTS] <name> SET OPTIONS (...)
//
// NOTE: This is deprecated in favor of ResolvedAlterTableStmt.
//
// <name_path> is a vector giving the identifier path in the table <name>.
// <option_list> has engine-specific directives that specify how to
//               alter the metadata for this table.
// <is_if_exists> silently ignore the "name_path does not exist" error.
class ResolvedAlterTableSetOptionsStmt final : public ResolvedStatement {
 public:
  typedef ResolvedStatement SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_ALTER_TABLE_SET_OPTIONS_STMT;

  friend std::unique_ptr<ResolvedAlterTableSetOptionsStmt> MakeResolvedAlterTableSetOptionsStmt();
 protected:
  ResolvedAlterTableSetOptionsStmt()
      : ResolvedStatement()
      , name_path_()
      , option_list_()
      , is_if_exists_()
  {}
 public:

  ResolvedAlterTableSetOptionsStmt(const ResolvedAlterTableSetOptionsStmt&) = delete;
  ResolvedAlterTableSetOptionsStmt& operator=(const ResolvedAlterTableSetOptionsStmt&) = delete;

  friend std::unique_ptr<ResolvedAlterTableSetOptionsStmt> MakeResolvedAlterTableSetOptionsStmt(
      const std::vector<std::string>& name_path,
      std::vector<std::unique_ptr<const ResolvedOption>> option_list,
      bool is_if_exists
  );
  ~ResolvedAlterTableSetOptionsStmt() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_ALTER_TABLE_SET_OPTIONS_STMT; }
  std::string node_kind_string() const final { return "AlterTableSetOptionsStmt"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedAlterTableSetOptionsStmtProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedStatementProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedAlterTableSetOptionsStmt>> RestoreFrom(
      const ResolvedAlterTableSetOptionsStmtProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  const std::vector<std::string>& name_path() const {
    accessed_ |= (1<<0);
    return name_path_;
  }
  int name_path_size() const {
    if (name_path_.empty()) accessed_ |= (1<<0);
    return static_cast<int>(name_path_.size());
  }
  std::string name_path(int i) const {
    accessed_ |= (1<<0);
    return name_path_.at(i);
  }
  void add_name_path(std::string v) {
    name_path_.push_back(std::string(v));
  }
  void set_name_path(const std::vector<std::string>& v) {
    name_path_ = v;
  }
  std::vector<std::string>* mutable_name_path() {
    accessed_ |= (1<<0);
    return &name_path_;
  }

  const std::vector<std::unique_ptr<const ResolvedOption>>& option_list() const {
    accessed_ |= (1<<1);
    return option_list_;
  }
  int option_list_size() const {
    if (option_list_.empty()) accessed_ |= (1<<1);
    return static_cast<int>(option_list_.size());
  }
  const ResolvedOption* option_list(int i) const {
    accessed_ |= (1<<1);
    return option_list_.at(i).get();
  }
  void add_option_list(std::unique_ptr<const ResolvedOption> v) {
    option_list_.emplace_back(std::move(v));
  }
  void set_option_list(std::vector<std::unique_ptr<const ResolvedOption>> v) {
    option_list_ = std::move(v);
  }

  std::vector<std::unique_ptr<const ResolvedOption>> release_option_list() {
    std::vector<std::unique_ptr<const ResolvedOption>> tmp;
    option_list_.swap(tmp);
    return tmp;
  }

  bool is_if_exists() const {
    accessed_ |= (1<<2);
    return is_if_exists_;
  }
  void set_is_if_exists(bool v) {
    is_if_exists_ = v;
  }

 protected:
  explicit ResolvedAlterTableSetOptionsStmt(
      const std::vector<std::string>& name_path,
      std::vector<std::unique_ptr<const ResolvedOption>> option_list,
      bool is_if_exists,
      ConstructorOverload)
      : ResolvedStatement(
            ConstructorOverload::NEW_CONSTRUCTOR),
      name_path_(name_path),
      option_list_(std::move(option_list)),
      is_if_exists_(is_if_exists) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  std::vector<std::string> name_path_;
  std::vector<std::unique_ptr<const ResolvedOption>> option_list_;
  bool is_if_exists_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedAlterTableSetOptionsStmt> MakeResolvedAlterTableSetOptionsStmt(
    const std::vector<std::string>& name_path,
    std::vector<std::unique_ptr<const ResolvedOption>> option_list,
    bool is_if_exists) {
  return std::unique_ptr<ResolvedAlterTableSetOptionsStmt>(new ResolvedAlterTableSetOptionsStmt(
        name_path,
        std::move(option_list),
        is_if_exists,
        ResolvedAlterTableSetOptionsStmt::NEW_CONSTRUCTOR));
}

// Overloaded factory method for the construction of ResolvedAlterTableSetOptionsStmt with
// a wider range of inputs for node-vector inputs.  In particular allows:
// 1. unique_ptr element type can be non-const.
// 2. unique_ptr element type can be any descendant of the required type.
// 3. input container can be any object with a `begin()` and `end()`.
//
// Note, initializer lists cannot be used to pass
//  option_list
// due to incompatibility with unique_ptr.  Use zetasql::MakeNodeVector
// instead.
template <
  typename option_list_t
      = std::vector<std::unique_ptr<const ResolvedOption>>>
std::unique_ptr<ResolvedAlterTableSetOptionsStmt> MakeResolvedAlterTableSetOptionsStmt(
    const std::vector<std::string>& name_path,
    option_list_t option_list,
    bool is_if_exists) {
  static_assert(std::is_base_of<
      ResolvedOption,
      typename std::decay<decltype(**(option_list.begin()))>::type>::value,
      "option_list must be a container of unique_ptr with elements of type "
      "ResolvedOption (or its descendants).");
  return MakeResolvedAlterTableSetOptionsStmt(
      name_path,
      {std::make_move_iterator(option_list.begin()),
       std::make_move_iterator(option_list.end())},
      is_if_exists);
}

inline std::unique_ptr<ResolvedAlterTableSetOptionsStmt> MakeResolvedAlterTableSetOptionsStmt() {
  return std::unique_ptr<ResolvedAlterTableSetOptionsStmt>(
      new ResolvedAlterTableSetOptionsStmt());
}

// This statement: RENAME <object_type> <old_name_path> TO <new_name_path>;
//
// <object_type> is an string identifier,
//               e.g., "TABLE", "VIEW", "INDEX", "FUNCTION", "TYPE", etc.
// <old_name_path> is a vector giving the identifier path for the object to
//                 be renamed.
// <new_name_path> is a vector giving the identifier path for the object to
//                 be renamed to.
class ResolvedRenameStmt final : public ResolvedStatement {
 public:
  typedef ResolvedStatement SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_RENAME_STMT;

  friend std::unique_ptr<ResolvedRenameStmt> MakeResolvedRenameStmt();
 protected:
  ResolvedRenameStmt()
      : ResolvedStatement()
      , object_type_()
      , old_name_path_()
      , new_name_path_()
  {}
 public:

  ResolvedRenameStmt(const ResolvedRenameStmt&) = delete;
  ResolvedRenameStmt& operator=(const ResolvedRenameStmt&) = delete;

  friend std::unique_ptr<ResolvedRenameStmt> MakeResolvedRenameStmt(
      const std::string& object_type,
      const std::vector<std::string>& old_name_path,
      const std::vector<std::string>& new_name_path
  );
  ~ResolvedRenameStmt() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_RENAME_STMT; }
  std::string node_kind_string() const final { return "RenameStmt"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedRenameStmtProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedStatementProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedRenameStmt>> RestoreFrom(
      const ResolvedRenameStmtProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  const std::string& object_type() const {
    accessed_ |= (1<<0);
    return object_type_;
  }
  void set_object_type(const std::string& v) {
    object_type_ = v;
  }

  const std::vector<std::string>& old_name_path() const {
    accessed_ |= (1<<1);
    return old_name_path_;
  }
  int old_name_path_size() const {
    if (old_name_path_.empty()) accessed_ |= (1<<1);
    return static_cast<int>(old_name_path_.size());
  }
  std::string old_name_path(int i) const {
    accessed_ |= (1<<1);
    return old_name_path_.at(i);
  }
  void add_old_name_path(std::string v) {
    old_name_path_.push_back(std::string(v));
  }
  void set_old_name_path(const std::vector<std::string>& v) {
    old_name_path_ = v;
  }
  std::vector<std::string>* mutable_old_name_path() {
    accessed_ |= (1<<1);
    return &old_name_path_;
  }

  const std::vector<std::string>& new_name_path() const {
    accessed_ |= (1<<2);
    return new_name_path_;
  }
  int new_name_path_size() const {
    if (new_name_path_.empty()) accessed_ |= (1<<2);
    return static_cast<int>(new_name_path_.size());
  }
  std::string new_name_path(int i) const {
    accessed_ |= (1<<2);
    return new_name_path_.at(i);
  }
  void add_new_name_path(std::string v) {
    new_name_path_.push_back(std::string(v));
  }
  void set_new_name_path(const std::vector<std::string>& v) {
    new_name_path_ = v;
  }
  std::vector<std::string>* mutable_new_name_path() {
    accessed_ |= (1<<2);
    return &new_name_path_;
  }

 protected:
  explicit ResolvedRenameStmt(
      const std::string& object_type,
      const std::vector<std::string>& old_name_path,
      const std::vector<std::string>& new_name_path,
      ConstructorOverload)
      : ResolvedStatement(
            ConstructorOverload::NEW_CONSTRUCTOR),
      object_type_(object_type),
      old_name_path_(old_name_path),
      new_name_path_(new_name_path) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  std::string object_type_;
  std::vector<std::string> old_name_path_;
  std::vector<std::string> new_name_path_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedRenameStmt> MakeResolvedRenameStmt(
    const std::string& object_type,
    const std::vector<std::string>& old_name_path,
    const std::vector<std::string>& new_name_path) {
  return std::unique_ptr<ResolvedRenameStmt>(new ResolvedRenameStmt(
        object_type,
        old_name_path,
        new_name_path,
        ResolvedRenameStmt::NEW_CONSTRUCTOR));
}

inline std::unique_ptr<ResolvedRenameStmt> MakeResolvedRenameStmt() {
  return std::unique_ptr<ResolvedRenameStmt>(
      new ResolvedRenameStmt());
}

// This statement: CREATE [OR REPLACE] ROW POLICY [IF NOT EXISTS] [<name>] ON
//                 <target_name_path> TO <grantee_list> USING (<predicate>);
//
// <create_mode> indicates if this was CREATE, CREATE OR REPLACE, or
//               CREATE IF NOT EXISTS.
// <name> is the name of the row policy to be created or an empty string.
// <target_name_path> is a vector giving the identifier path of the target
//                    table.
// <table_scan> is a TableScan for the target table, which is used during
//              resolving and validation. Consumers can use either the table
//              object inside it or target_name_path to reference the table.
// <grantee_list> (DEPRECATED) is the list of user principals the policy
//                should apply to.
// <grantee_expr_list> is the list of user principals the policy should
//                     apply to, and may include parameters.
// <predicate> is a boolean expression that selects the rows that are being
//             made visible.
// <predicate_str> is the string form of the predicate.
//
// Only one of <grantee_list> or <grantee_expr_list> will be populated,
// depending on whether or not the FEATURE_PARAMETERS_IN_GRANTEE_LIST
// is enabled.  The <grantee_list> is deprecated, and will be removed
// along with the corresponding FEATURE once all engines have migrated to
// use the <grantee_expr_list>.  Once <grantee_expr_list> is the only
// one, then it should be marked as NOT_IGNORABLE.
class ResolvedCreateRowPolicyStmt final : public ResolvedStatement {
 public:
  typedef ResolvedStatement SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_CREATE_ROW_POLICY_STMT;

  typedef ResolvedCreateStatement::CreateMode CreateMode;

  friend std::unique_ptr<ResolvedCreateRowPolicyStmt> MakeResolvedCreateRowPolicyStmt();
 protected:
  ResolvedCreateRowPolicyStmt()
      : ResolvedStatement()
      , create_mode_()
      , name_()
      , target_name_path_()
      , grantee_list_()
      , grantee_expr_list_()
      , table_scan_()
      , predicate_()
      , predicate_str_()
  {}
 public:

  ResolvedCreateRowPolicyStmt(const ResolvedCreateRowPolicyStmt&) = delete;
  ResolvedCreateRowPolicyStmt& operator=(const ResolvedCreateRowPolicyStmt&) = delete;

  friend std::unique_ptr<ResolvedCreateRowPolicyStmt> MakeResolvedCreateRowPolicyStmt(
      CreateMode create_mode,
      const std::string& name,
      const std::vector<std::string>& target_name_path,
      const std::vector<std::string>& grantee_list,
      std::vector<std::unique_ptr<const ResolvedExpr>> grantee_expr_list,
      std::unique_ptr<const ResolvedTableScan> table_scan,
      std::unique_ptr<const ResolvedExpr> predicate,
      const std::string& predicate_str
  );
  ~ResolvedCreateRowPolicyStmt() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_CREATE_ROW_POLICY_STMT; }
  std::string node_kind_string() const final { return "CreateRowPolicyStmt"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedCreateRowPolicyStmtProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedStatementProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedCreateRowPolicyStmt>> RestoreFrom(
      const ResolvedCreateRowPolicyStmtProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  CreateMode create_mode() const {
    accessed_ |= (1<<0);
    return create_mode_;
  }
  void set_create_mode(CreateMode v) {
    create_mode_ = v;
  }

  const std::string& name() const {
    accessed_ |= (1<<1);
    return name_;
  }
  void set_name(const std::string& v) {
    name_ = v;
  }

  const std::vector<std::string>& target_name_path() const {
    accessed_ |= (1<<2);
    return target_name_path_;
  }
  int target_name_path_size() const {
    if (target_name_path_.empty()) accessed_ |= (1<<2);
    return static_cast<int>(target_name_path_.size());
  }
  std::string target_name_path(int i) const {
    accessed_ |= (1<<2);
    return target_name_path_.at(i);
  }
  void add_target_name_path(std::string v) {
    target_name_path_.push_back(std::string(v));
  }
  void set_target_name_path(const std::vector<std::string>& v) {
    target_name_path_ = v;
  }
  std::vector<std::string>* mutable_target_name_path() {
    accessed_ |= (1<<2);
    return &target_name_path_;
  }

  const std::vector<std::string>& grantee_list() const {
    accessed_ |= (1<<3);
    return grantee_list_;
  }
  int grantee_list_size() const {
    if (grantee_list_.empty()) accessed_ |= (1<<3);
    return static_cast<int>(grantee_list_.size());
  }
  std::string grantee_list(int i) const {
    accessed_ |= (1<<3);
    return grantee_list_.at(i);
  }
  void add_grantee_list(std::string v) {
    grantee_list_.push_back(std::string(v));
  }
  void set_grantee_list(const std::vector<std::string>& v) {
    grantee_list_ = v;
  }
  std::vector<std::string>* mutable_grantee_list() {
    accessed_ |= (1<<3);
    return &grantee_list_;
  }

  const std::vector<std::unique_ptr<const ResolvedExpr>>& grantee_expr_list() const {
    accessed_ |= (1<<4);
    return grantee_expr_list_;
  }
  int grantee_expr_list_size() const {
    if (grantee_expr_list_.empty()) accessed_ |= (1<<4);
    return static_cast<int>(grantee_expr_list_.size());
  }
  const ResolvedExpr* grantee_expr_list(int i) const {
    accessed_ |= (1<<4);
    return grantee_expr_list_.at(i).get();
  }
  void add_grantee_expr_list(std::unique_ptr<const ResolvedExpr> v) {
    grantee_expr_list_.emplace_back(std::move(v));
  }
  void set_grantee_expr_list(std::vector<std::unique_ptr<const ResolvedExpr>> v) {
    grantee_expr_list_ = std::move(v);
  }

  std::vector<std::unique_ptr<const ResolvedExpr>> release_grantee_expr_list() {
    std::vector<std::unique_ptr<const ResolvedExpr>> tmp;
    grantee_expr_list_.swap(tmp);
    return tmp;
  }

  const ResolvedTableScan* table_scan() const {
    accessed_ |= (1<<5);
    return table_scan_.get();
  }
  void set_table_scan(std::unique_ptr<const ResolvedTableScan> v) {
    table_scan_ = std::move(v);
  }

  std::unique_ptr<const ResolvedTableScan> release_table_scan() {
    return std::move(table_scan_);
  }

  const ResolvedExpr* predicate() const {
    accessed_ |= (1<<6);
    return predicate_.get();
  }
  void set_predicate(std::unique_ptr<const ResolvedExpr> v) {
    predicate_ = std::move(v);
  }

  std::unique_ptr<const ResolvedExpr> release_predicate() {
    return std::move(predicate_);
  }

  const std::string& predicate_str() const {
    accessed_ |= (1<<7);
    return predicate_str_;
  }
  void set_predicate_str(const std::string& v) {
    predicate_str_ = v;
  }

 protected:
  explicit ResolvedCreateRowPolicyStmt(
      CreateMode create_mode,
      const std::string& name,
      const std::vector<std::string>& target_name_path,
      const std::vector<std::string>& grantee_list,
      std::vector<std::unique_ptr<const ResolvedExpr>> grantee_expr_list,
      std::unique_ptr<const ResolvedTableScan> table_scan,
      std::unique_ptr<const ResolvedExpr> predicate,
      const std::string& predicate_str,
      ConstructorOverload)
      : ResolvedStatement(
            ConstructorOverload::NEW_CONSTRUCTOR),
      create_mode_(create_mode),
      name_(name),
      target_name_path_(target_name_path),
      grantee_list_(grantee_list),
      grantee_expr_list_(std::move(grantee_expr_list)),
      table_scan_(std::move(table_scan)),
      predicate_(std::move(predicate)),
      predicate_str_(predicate_str) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  CreateMode create_mode_;
  std::string name_;
  std::vector<std::string> target_name_path_;
  std::vector<std::string> grantee_list_;
  std::vector<std::unique_ptr<const ResolvedExpr>> grantee_expr_list_;
  std::unique_ptr<const ResolvedTableScan> table_scan_;
  std::unique_ptr<const ResolvedExpr> predicate_;
  std::string predicate_str_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedCreateRowPolicyStmt> MakeResolvedCreateRowPolicyStmt(
    ResolvedCreateStatement::CreateMode create_mode,
    const std::string& name,
    const std::vector<std::string>& target_name_path,
    const std::vector<std::string>& grantee_list,
    std::vector<std::unique_ptr<const ResolvedExpr>> grantee_expr_list,
    std::unique_ptr<const ResolvedTableScan> table_scan,
    std::unique_ptr<const ResolvedExpr> predicate,
    const std::string& predicate_str) {
  return std::unique_ptr<ResolvedCreateRowPolicyStmt>(new ResolvedCreateRowPolicyStmt(
        create_mode,
        name,
        target_name_path,
        grantee_list,
        std::move(grantee_expr_list),
        std::move(table_scan),
        std::move(predicate),
        predicate_str,
        ResolvedCreateRowPolicyStmt::NEW_CONSTRUCTOR));
}

// Overloaded factory method for the construction of ResolvedCreateRowPolicyStmt with
// a wider range of inputs for node-vector inputs.  In particular allows:
// 1. unique_ptr element type can be non-const.
// 2. unique_ptr element type can be any descendant of the required type.
// 3. input container can be any object with a `begin()` and `end()`.
//
// Note, initializer lists cannot be used to pass
//  grantee_expr_list
// due to incompatibility with unique_ptr.  Use zetasql::MakeNodeVector
// instead.
template <
  typename grantee_expr_list_t
      = std::vector<std::unique_ptr<const ResolvedExpr>>>
std::unique_ptr<ResolvedCreateRowPolicyStmt> MakeResolvedCreateRowPolicyStmt(
    ResolvedCreateStatement::CreateMode create_mode,
    const std::string& name,
    const std::vector<std::string>& target_name_path,
    const std::vector<std::string>& grantee_list,
    grantee_expr_list_t grantee_expr_list,
    std::unique_ptr<const ResolvedTableScan> table_scan,
    std::unique_ptr<const ResolvedExpr> predicate,
    const std::string& predicate_str) {
  static_assert(std::is_base_of<
      ResolvedExpr,
      typename std::decay<decltype(**(grantee_expr_list.begin()))>::type>::value,
      "grantee_expr_list must be a container of unique_ptr with elements of type "
      "ResolvedExpr (or its descendants).");
  return MakeResolvedCreateRowPolicyStmt(
      create_mode,
      name,
      target_name_path,
      grantee_list,
      {std::make_move_iterator(grantee_expr_list.begin()),
       std::make_move_iterator(grantee_expr_list.end())},
      std::move(table_scan),
      std::move(predicate),
      predicate_str);
}

inline std::unique_ptr<ResolvedCreateRowPolicyStmt> MakeResolvedCreateRowPolicyStmt() {
  return std::unique_ptr<ResolvedCreateRowPolicyStmt>(
      new ResolvedCreateRowPolicyStmt());
}

// This statement:
//     DROP ROW POLICY <name> ON <target_name_path>; or
//     DROP ALL ROW POLICIES ON <target_name_path>;
//
// <is_drop_all> indicates that all policies should be dropped.
// <is_if_exists> silently ignore the "policy <name> does not exist" error.
//                This is not allowed if is_drop_all is true.
// <name> is the name of the row policy to be dropped or an empty string.
// <target_name_path> is a vector giving the identifier path of the target
//                    table.
class ResolvedDropRowPolicyStmt final : public ResolvedStatement {
 public:
  typedef ResolvedStatement SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_DROP_ROW_POLICY_STMT;

  friend std::unique_ptr<ResolvedDropRowPolicyStmt> MakeResolvedDropRowPolicyStmt();
 protected:
  ResolvedDropRowPolicyStmt()
      : ResolvedStatement()
      , is_drop_all_()
      , is_if_exists_()
      , name_()
      , target_name_path_()
  {}
 public:

  ResolvedDropRowPolicyStmt(const ResolvedDropRowPolicyStmt&) = delete;
  ResolvedDropRowPolicyStmt& operator=(const ResolvedDropRowPolicyStmt&) = delete;

  friend std::unique_ptr<ResolvedDropRowPolicyStmt> MakeResolvedDropRowPolicyStmt(
      bool is_drop_all,
      bool is_if_exists,
      const std::string& name,
      const std::vector<std::string>& target_name_path
  );
  ~ResolvedDropRowPolicyStmt() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_DROP_ROW_POLICY_STMT; }
  std::string node_kind_string() const final { return "DropRowPolicyStmt"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedDropRowPolicyStmtProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedStatementProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedDropRowPolicyStmt>> RestoreFrom(
      const ResolvedDropRowPolicyStmtProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  bool is_drop_all() const {
    accessed_ |= (1<<0);
    return is_drop_all_;
  }
  void set_is_drop_all(bool v) {
    is_drop_all_ = v;
  }

  bool is_if_exists() const {
    accessed_ |= (1<<1);
    return is_if_exists_;
  }
  void set_is_if_exists(bool v) {
    is_if_exists_ = v;
  }

  const std::string& name() const {
    accessed_ |= (1<<2);
    return name_;
  }
  void set_name(const std::string& v) {
    name_ = v;
  }

  const std::vector<std::string>& target_name_path() const {
    accessed_ |= (1<<3);
    return target_name_path_;
  }
  int target_name_path_size() const {
    if (target_name_path_.empty()) accessed_ |= (1<<3);
    return static_cast<int>(target_name_path_.size());
  }
  std::string target_name_path(int i) const {
    accessed_ |= (1<<3);
    return target_name_path_.at(i);
  }
  void add_target_name_path(std::string v) {
    target_name_path_.push_back(std::string(v));
  }
  void set_target_name_path(const std::vector<std::string>& v) {
    target_name_path_ = v;
  }
  std::vector<std::string>* mutable_target_name_path() {
    accessed_ |= (1<<3);
    return &target_name_path_;
  }

 protected:
  explicit ResolvedDropRowPolicyStmt(
      bool is_drop_all,
      bool is_if_exists,
      const std::string& name,
      const std::vector<std::string>& target_name_path,
      ConstructorOverload)
      : ResolvedStatement(
            ConstructorOverload::NEW_CONSTRUCTOR),
      is_drop_all_(is_drop_all),
      is_if_exists_(is_if_exists),
      name_(name),
      target_name_path_(target_name_path) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  bool is_drop_all_;
  bool is_if_exists_;
  std::string name_;
  std::vector<std::string> target_name_path_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedDropRowPolicyStmt> MakeResolvedDropRowPolicyStmt(
    bool is_drop_all,
    bool is_if_exists,
    const std::string& name,
    const std::vector<std::string>& target_name_path) {
  return std::unique_ptr<ResolvedDropRowPolicyStmt>(new ResolvedDropRowPolicyStmt(
        is_drop_all,
        is_if_exists,
        name,
        target_name_path,
        ResolvedDropRowPolicyStmt::NEW_CONSTRUCTOR));
}

inline std::unique_ptr<ResolvedDropRowPolicyStmt> MakeResolvedDropRowPolicyStmt() {
  return std::unique_ptr<ResolvedDropRowPolicyStmt>(
      new ResolvedDropRowPolicyStmt());
}

// This statement:
//     ALTER ROW POLICY [<name>] [RENAME TO <new_name>] ON <target_name_path>
//     [TO <grantee_list>] [USING (<predicate>)];
//
// <name> is the name of the row policy to be altered.
// <new_name> is the optional new name of the row policy to be renamed to.
//            Empty when RENAME TO clause is absent.
// <target_name_path> is a vector giving the identifier path of the target
//                    table.
// <table_scan> is a TableScan for the target table, which is used during
//              resolving and validation. Consumers can use either the table
//              object inside it or target_name_path to reference the table.
// <grantee_list> (DEPRECATED) is the optional list of user principals the
//                policy should apply to. Empty when TO <grantee_list>
//                clause is absent.
// <grantee_expr_list> is the optional list of user principals the policy
//                     should apply to, and may include parameters.  Empty
//                     when TO <grantee_list> clause is absent.
// <predicate> is an optional boolean expression that selects the rows that
//             are being made visible. Null if USING clause is absent.
// <predicate_str> is the string form of the predicate. Empty if USING clause
//                 is absent.
//
// Only one of <grantee_list> or <grantee_expr_list> will be populated,
// depending on whether or not the FEATURE_PARAMETERS_IN_GRANTEE_LIST
// is enabled.  The <grantee_list> is deprecated, and will be removed
// along with the corresponding FEATURE once all engines have migrated to
// use the <grantee_expr_list>.
class ResolvedAlterRowPolicyStmt final : public ResolvedStatement {
 public:
  typedef ResolvedStatement SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_ALTER_ROW_POLICY_STMT;

  friend std::unique_ptr<ResolvedAlterRowPolicyStmt> MakeResolvedAlterRowPolicyStmt();
 protected:
  ResolvedAlterRowPolicyStmt()
      : ResolvedStatement()
      , name_()
      , new_name_()
      , target_name_path_()
      , grantee_list_()
      , grantee_expr_list_()
      , table_scan_()
      , predicate_()
      , predicate_str_()
  {}
 public:

  ResolvedAlterRowPolicyStmt(const ResolvedAlterRowPolicyStmt&) = delete;
  ResolvedAlterRowPolicyStmt& operator=(const ResolvedAlterRowPolicyStmt&) = delete;

  friend std::unique_ptr<ResolvedAlterRowPolicyStmt> MakeResolvedAlterRowPolicyStmt(
      const std::string& name,
      const std::string& new_name,
      const std::vector<std::string>& target_name_path,
      const std::vector<std::string>& grantee_list,
      std::vector<std::unique_ptr<const ResolvedExpr>> grantee_expr_list,
      std::unique_ptr<const ResolvedTableScan> table_scan,
      std::unique_ptr<const ResolvedExpr> predicate,
      const std::string& predicate_str
  );
  ~ResolvedAlterRowPolicyStmt() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_ALTER_ROW_POLICY_STMT; }
  std::string node_kind_string() const final { return "AlterRowPolicyStmt"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedAlterRowPolicyStmtProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedStatementProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedAlterRowPolicyStmt>> RestoreFrom(
      const ResolvedAlterRowPolicyStmtProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  const std::string& name() const {
    accessed_ |= (1<<0);
    return name_;
  }
  void set_name(const std::string& v) {
    name_ = v;
  }

  const std::string& new_name() const {
    accessed_ |= (1<<1);
    return new_name_;
  }
  void set_new_name(const std::string& v) {
    new_name_ = v;
  }

  const std::vector<std::string>& target_name_path() const {
    accessed_ |= (1<<2);
    return target_name_path_;
  }
  int target_name_path_size() const {
    if (target_name_path_.empty()) accessed_ |= (1<<2);
    return static_cast<int>(target_name_path_.size());
  }
  std::string target_name_path(int i) const {
    accessed_ |= (1<<2);
    return target_name_path_.at(i);
  }
  void add_target_name_path(std::string v) {
    target_name_path_.push_back(std::string(v));
  }
  void set_target_name_path(const std::vector<std::string>& v) {
    target_name_path_ = v;
  }
  std::vector<std::string>* mutable_target_name_path() {
    accessed_ |= (1<<2);
    return &target_name_path_;
  }

  const std::vector<std::string>& grantee_list() const {
    accessed_ |= (1<<3);
    return grantee_list_;
  }
  int grantee_list_size() const {
    if (grantee_list_.empty()) accessed_ |= (1<<3);
    return static_cast<int>(grantee_list_.size());
  }
  std::string grantee_list(int i) const {
    accessed_ |= (1<<3);
    return grantee_list_.at(i);
  }
  void add_grantee_list(std::string v) {
    grantee_list_.push_back(std::string(v));
  }
  void set_grantee_list(const std::vector<std::string>& v) {
    grantee_list_ = v;
  }
  std::vector<std::string>* mutable_grantee_list() {
    accessed_ |= (1<<3);
    return &grantee_list_;
  }

  const std::vector<std::unique_ptr<const ResolvedExpr>>& grantee_expr_list() const {
    accessed_ |= (1<<4);
    return grantee_expr_list_;
  }
  int grantee_expr_list_size() const {
    if (grantee_expr_list_.empty()) accessed_ |= (1<<4);
    return static_cast<int>(grantee_expr_list_.size());
  }
  const ResolvedExpr* grantee_expr_list(int i) const {
    accessed_ |= (1<<4);
    return grantee_expr_list_.at(i).get();
  }
  void add_grantee_expr_list(std::unique_ptr<const ResolvedExpr> v) {
    grantee_expr_list_.emplace_back(std::move(v));
  }
  void set_grantee_expr_list(std::vector<std::unique_ptr<const ResolvedExpr>> v) {
    grantee_expr_list_ = std::move(v);
  }

  std::vector<std::unique_ptr<const ResolvedExpr>> release_grantee_expr_list() {
    std::vector<std::unique_ptr<const ResolvedExpr>> tmp;
    grantee_expr_list_.swap(tmp);
    return tmp;
  }

  const ResolvedTableScan* table_scan() const {
    accessed_ |= (1<<5);
    return table_scan_.get();
  }
  void set_table_scan(std::unique_ptr<const ResolvedTableScan> v) {
    table_scan_ = std::move(v);
  }

  std::unique_ptr<const ResolvedTableScan> release_table_scan() {
    return std::move(table_scan_);
  }

  const ResolvedExpr* predicate() const {
    accessed_ |= (1<<6);
    return predicate_.get();
  }
  void set_predicate(std::unique_ptr<const ResolvedExpr> v) {
    predicate_ = std::move(v);
  }

  std::unique_ptr<const ResolvedExpr> release_predicate() {
    return std::move(predicate_);
  }

  const std::string& predicate_str() const {
    accessed_ |= (1<<7);
    return predicate_str_;
  }
  void set_predicate_str(const std::string& v) {
    predicate_str_ = v;
  }

 protected:
  explicit ResolvedAlterRowPolicyStmt(
      const std::string& name,
      const std::string& new_name,
      const std::vector<std::string>& target_name_path,
      const std::vector<std::string>& grantee_list,
      std::vector<std::unique_ptr<const ResolvedExpr>> grantee_expr_list,
      std::unique_ptr<const ResolvedTableScan> table_scan,
      std::unique_ptr<const ResolvedExpr> predicate,
      const std::string& predicate_str,
      ConstructorOverload)
      : ResolvedStatement(
            ConstructorOverload::NEW_CONSTRUCTOR),
      name_(name),
      new_name_(new_name),
      target_name_path_(target_name_path),
      grantee_list_(grantee_list),
      grantee_expr_list_(std::move(grantee_expr_list)),
      table_scan_(std::move(table_scan)),
      predicate_(std::move(predicate)),
      predicate_str_(predicate_str) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  std::string name_;
  std::string new_name_;
  std::vector<std::string> target_name_path_;
  std::vector<std::string> grantee_list_;
  std::vector<std::unique_ptr<const ResolvedExpr>> grantee_expr_list_;
  std::unique_ptr<const ResolvedTableScan> table_scan_;
  std::unique_ptr<const ResolvedExpr> predicate_;
  std::string predicate_str_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedAlterRowPolicyStmt> MakeResolvedAlterRowPolicyStmt(
    const std::string& name,
    const std::string& new_name,
    const std::vector<std::string>& target_name_path,
    const std::vector<std::string>& grantee_list,
    std::vector<std::unique_ptr<const ResolvedExpr>> grantee_expr_list,
    std::unique_ptr<const ResolvedTableScan> table_scan,
    std::unique_ptr<const ResolvedExpr> predicate,
    const std::string& predicate_str) {
  return std::unique_ptr<ResolvedAlterRowPolicyStmt>(new ResolvedAlterRowPolicyStmt(
        name,
        new_name,
        target_name_path,
        grantee_list,
        std::move(grantee_expr_list),
        std::move(table_scan),
        std::move(predicate),
        predicate_str,
        ResolvedAlterRowPolicyStmt::NEW_CONSTRUCTOR));
}

// Overloaded factory method for the construction of ResolvedAlterRowPolicyStmt with
// a wider range of inputs for node-vector inputs.  In particular allows:
// 1. unique_ptr element type can be non-const.
// 2. unique_ptr element type can be any descendant of the required type.
// 3. input container can be any object with a `begin()` and `end()`.
//
// Note, initializer lists cannot be used to pass
//  grantee_expr_list
// due to incompatibility with unique_ptr.  Use zetasql::MakeNodeVector
// instead.
template <
  typename grantee_expr_list_t
      = std::vector<std::unique_ptr<const ResolvedExpr>>>
std::unique_ptr<ResolvedAlterRowPolicyStmt> MakeResolvedAlterRowPolicyStmt(
    const std::string& name,
    const std::string& new_name,
    const std::vector<std::string>& target_name_path,
    const std::vector<std::string>& grantee_list,
    grantee_expr_list_t grantee_expr_list,
    std::unique_ptr<const ResolvedTableScan> table_scan,
    std::unique_ptr<const ResolvedExpr> predicate,
    const std::string& predicate_str) {
  static_assert(std::is_base_of<
      ResolvedExpr,
      typename std::decay<decltype(**(grantee_expr_list.begin()))>::type>::value,
      "grantee_expr_list must be a container of unique_ptr with elements of type "
      "ResolvedExpr (or its descendants).");
  return MakeResolvedAlterRowPolicyStmt(
      name,
      new_name,
      target_name_path,
      grantee_list,
      {std::make_move_iterator(grantee_expr_list.begin()),
       std::make_move_iterator(grantee_expr_list.end())},
      std::move(table_scan),
      std::move(predicate),
      predicate_str);
}

inline std::unique_ptr<ResolvedAlterRowPolicyStmt> MakeResolvedAlterRowPolicyStmt() {
  return std::unique_ptr<ResolvedAlterRowPolicyStmt>(
      new ResolvedAlterRowPolicyStmt());
}

// This statement creates a user-defined named constant:
// CREATE [OR REPLACE] [TEMP | TEMPORARY | PUBLIC | PRIVATE] CONSTANT
//   [IF NOT EXISTS] <name_path> = <expression>
//
// <name_path> is the identifier path of the named constants.
// <expr> is the expression that determines the type and the value of the
//        named constant. Note that <expr> need not be constant. Its value
//        is bound to the named constant which is then treated as
//        immutable. <expr> can be evaluated at the time this statement is
//        processed or later (lazy evaluation during query execution).
class ResolvedCreateConstantStmt final : public ResolvedCreateStatement {
 public:
  typedef ResolvedCreateStatement SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_CREATE_CONSTANT_STMT;

  friend std::unique_ptr<ResolvedCreateConstantStmt> MakeResolvedCreateConstantStmt(
      const std::vector<std::string>& name_path,
      CreateScope create_scope,
      CreateMode create_mode,
      std::unique_ptr<const ResolvedExpr> expr
  );
  ~ResolvedCreateConstantStmt() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_CREATE_CONSTANT_STMT; }
  std::string node_kind_string() const final { return "CreateConstantStmt"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedCreateConstantStmtProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedCreateStatementProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedCreateConstantStmt>> RestoreFrom(
      const ResolvedCreateConstantStmtProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  const ResolvedExpr* expr() const {
    accessed_ |= (1<<0);
    return expr_.get();
  }
  void set_expr(std::unique_ptr<const ResolvedExpr> v) {
    expr_ = std::move(v);
  }

  std::unique_ptr<const ResolvedExpr> release_expr() {
    return std::move(expr_);
  }

 protected:
  explicit ResolvedCreateConstantStmt(
      const std::vector<std::string>& name_path,
      CreateScope create_scope,
      CreateMode create_mode,
      std::unique_ptr<const ResolvedExpr> expr,
      ConstructorOverload)
      : ResolvedCreateStatement(
            name_path,
            create_scope,
            create_mode,
            ConstructorOverload::NEW_CONSTRUCTOR),
      expr_(std::move(expr)) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  std::unique_ptr<const ResolvedExpr> expr_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedCreateConstantStmt> MakeResolvedCreateConstantStmt(
    const std::vector<std::string>& name_path,
    ResolvedCreateStatement::CreateScope create_scope,
    ResolvedCreateStatement::CreateMode create_mode,
    std::unique_ptr<const ResolvedExpr> expr) {
  return std::unique_ptr<ResolvedCreateConstantStmt>(new ResolvedCreateConstantStmt(
        name_path,
        create_scope,
        create_mode,
        std::move(expr),
        ResolvedCreateConstantStmt::NEW_CONSTRUCTOR));
}

// This statement creates a user-defined function:
//   CREATE [TEMP] FUNCTION [IF NOT EXISTS] <name_path> (<arg_list>)
//     [RETURNS <return_type>] [LANGUAGE <language>]
//     [AS <code> | AS ( <function_expression> )] [OPTIONS (<option_list>)]
//
//   <name_path> is the identifier path of the function.
//   <has_explicit_return_type> is true iff RETURNS clause is present.
//   <return_type> is the return type for the function, which can be any
//          valid ZetaSQL type, including ARRAY or STRUCT. It is inferred
//          from <function_expression> if not explicitly set.
//          TODO: Deprecate and remove this. The return type is
//          already specified by the <signature>.
//   <argument_name_list> The names of the function arguments.
//   <signature> is the FunctionSignature of the created function, with all
//          options.  This can be used to create a Function to load into a
//          Catalog for future queries.
//   <is_aggregate> is true if this is an aggregate function.  All arguments
//          are assumed to be aggregate input arguments that may vary for
//          every row.
//   <language> is the programming language used by the function. This field
//          is set to 'SQL' for SQL functions and otherwise to the language
//          name specified in the LANGUAGE clause.
//   <code> is a string literal that contains the function definition.  Some
//          engines may allow this argument to be omitted for certain types
//          of external functions. This will always be set for SQL functions.
//   <aggregate_expression_list> is a list of SQL aggregate functions to
//          compute prior to computing the final <function_expression>.
//          See below.
//   <function_expression> is the resolved SQL expression invoked for the
//          function. This will be unset for external language functions. For
//          non-template SQL functions, this is a resolved representation of
//          the expression in <code>.
//   <option_list> has engine-specific directives for modifying functions.
//   <sql_security> is the declared security mode for the function. Values
//          include 'INVOKER', 'DEFINER'.
//
// Note that <function_expression> and <code> are both marked as IGNORABLE
// because an engine could look at either one (but might not look at both).
// An engine must look at one (and cannot ignore both) to be semantically
// valid, but there is currently no way to enforce that.
//
// For aggregate functions, <is_aggregate> will be true.
// Aggregate functions will only occur if LanguageOptions has
// FEATURE_CREATE_AGGREGATE_FUNCTION enabled.
//
// Arguments to aggregate functions must have
// <FunctionSignatureArgumentTypeOptions::is_not_aggregate> true or false.
// Non-aggregate arguments must be passed constant values only.
//
// For SQL aggregate functions, there will be both an
// <aggregate_expression_list>, with aggregate expressions to compute first,
// and then a final <function_expression> to compute on the results
// of the aggregates.  Each aggregate expression is a
// ResolvedAggregateFunctionCall, and may reference any input arguments.
// Each ResolvedComputedColumn in <aggregate_expression_list> gives the
// aggregate expression a column id.  The final <function_expression> can
// reference these created aggregate columns, and any input arguments
// with <argument_kind>=NOT_AGGREGATE.
//
// For example, with
//   CREATE TEMP FUNCTION my_avg(x) = (SUM(x) / COUNT(x));
// we would have an <aggregate_expression_list> with
//   agg1#1 := SUM(ResolvedArgumentRef(x))
//   agg2#2 := COUNT(ResolvedArgumentRef(x))
// and a <function_expression>
//   ResolvedColumnRef(agg1#1) / ResolvedColumnRef(agg2#2)
//
// For example, with
//   CREATE FUNCTION scaled_avg(x,y NOT AGGREGATE) = (SUM(x) / COUNT(x) * y);
// we would have an <aggregate_expression_list> with
//   agg1#1 := SUM(ResolvedArgumentRef(x))
//   agg2#2 := COUNT(ResolvedArgumentRef(x))
// and a <function_expression>
//   ResolvedColumnRef(agg1#1) / ResolvedColumnRef(agg2#2) * ResolvedArgumentRef(y)
//
// When resolving a query that calls an aggregate UDF, the query will
// have a ResolvedAggregateScan that invokes the UDF function.  The engine
// should remove the UDF aggregate function from the <aggregate_list>, and
// instead compute the additional aggregates from the
// UDF's <aggregate_expression_list>, and then add an additional Project
// to compute the final <function_expression>, which should produce the
// value for the original ResolvedAggregateScan's computed column for the
// UDF.  Some rewrites of the ResolvedColumn references inside the UDF will
// be required.  TODO If using ResolvedColumns makes this renaming
// too complicated, we could switch to use ResolvedArgumentRefs, or
// something new.
class ResolvedCreateFunctionStmt final : public ResolvedCreateStatement {
 public:
  typedef ResolvedCreateStatement SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_CREATE_FUNCTION_STMT;

  friend std::unique_ptr<ResolvedCreateFunctionStmt> MakeResolvedCreateFunctionStmt(
      const std::vector<std::string>& name_path,
      CreateScope create_scope,
      CreateMode create_mode,
      bool has_explicit_return_type,
      const Type* return_type,
      const std::vector<std::string>& argument_name_list,
      const FunctionSignature& signature,
      bool is_aggregate,
      const std::string& language,
      const std::string& code,
      std::vector<std::unique_ptr<const ResolvedComputedColumn>> aggregate_expression_list,
      std::unique_ptr<const ResolvedExpr> function_expression,
      std::vector<std::unique_ptr<const ResolvedOption>> option_list,
      SqlSecurity sql_security
  );
  ~ResolvedCreateFunctionStmt() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_CREATE_FUNCTION_STMT; }
  std::string node_kind_string() const final { return "CreateFunctionStmt"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedCreateFunctionStmtProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedCreateStatementProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedCreateFunctionStmt>> RestoreFrom(
      const ResolvedCreateFunctionStmtProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  bool has_explicit_return_type() const {
    accessed_ |= (1<<0);
    return has_explicit_return_type_;
  }
  void set_has_explicit_return_type(bool v) {
    has_explicit_return_type_ = v;
  }

  const Type* return_type() const {
    accessed_ |= (1<<1);
    return return_type_;
  }
  void set_return_type(const Type* v) {
    return_type_ = v;
  }

  const std::vector<std::string>& argument_name_list() const {
    accessed_ |= (1<<2);
    return argument_name_list_;
  }
  int argument_name_list_size() const {
    if (argument_name_list_.empty()) accessed_ |= (1<<2);
    return static_cast<int>(argument_name_list_.size());
  }
  std::string argument_name_list(int i) const {
    accessed_ |= (1<<2);
    return argument_name_list_.at(i);
  }
  void add_argument_name_list(std::string v) {
    argument_name_list_.push_back(std::string(v));
  }
  void set_argument_name_list(const std::vector<std::string>& v) {
    argument_name_list_ = v;
  }
  std::vector<std::string>* mutable_argument_name_list() {
    accessed_ |= (1<<2);
    return &argument_name_list_;
  }

  const FunctionSignature& signature() const {
    accessed_ |= (1<<3);
    return signature_;
  }
  void set_signature(const FunctionSignature& v) {
    signature_ = v;
  }

  bool is_aggregate() const {
    accessed_ |= (1<<4);
    return is_aggregate_;
  }
  void set_is_aggregate(bool v) {
    is_aggregate_ = v;
  }

  const std::string& language() const {
    accessed_ |= (1<<5);
    return language_;
  }
  void set_language(const std::string& v) {
    language_ = v;
  }

  const std::string& code() const {
    accessed_ |= (1<<6);
    return code_;
  }
  void set_code(const std::string& v) {
    code_ = v;
  }

  const std::vector<std::unique_ptr<const ResolvedComputedColumn>>& aggregate_expression_list() const {
    accessed_ |= (1<<7);
    return aggregate_expression_list_;
  }
  int aggregate_expression_list_size() const {
    if (aggregate_expression_list_.empty()) accessed_ |= (1<<7);
    return static_cast<int>(aggregate_expression_list_.size());
  }
  const ResolvedComputedColumn* aggregate_expression_list(int i) const {
    accessed_ |= (1<<7);
    return aggregate_expression_list_.at(i).get();
  }
  void add_aggregate_expression_list(std::unique_ptr<const ResolvedComputedColumn> v) {
    aggregate_expression_list_.emplace_back(std::move(v));
  }
  void set_aggregate_expression_list(std::vector<std::unique_ptr<const ResolvedComputedColumn>> v) {
    aggregate_expression_list_ = std::move(v);
  }

  std::vector<std::unique_ptr<const ResolvedComputedColumn>> release_aggregate_expression_list() {
    std::vector<std::unique_ptr<const ResolvedComputedColumn>> tmp;
    aggregate_expression_list_.swap(tmp);
    return tmp;
  }

  const ResolvedExpr* function_expression() const {
    accessed_ |= (1<<8);
    return function_expression_.get();
  }
  void set_function_expression(std::unique_ptr<const ResolvedExpr> v) {
    function_expression_ = std::move(v);
  }

  std::unique_ptr<const ResolvedExpr> release_function_expression() {
    return std::move(function_expression_);
  }

  const std::vector<std::unique_ptr<const ResolvedOption>>& option_list() const {
    accessed_ |= (1<<9);
    return option_list_;
  }
  int option_list_size() const {
    if (option_list_.empty()) accessed_ |= (1<<9);
    return static_cast<int>(option_list_.size());
  }
  const ResolvedOption* option_list(int i) const {
    accessed_ |= (1<<9);
    return option_list_.at(i).get();
  }
  void add_option_list(std::unique_ptr<const ResolvedOption> v) {
    option_list_.emplace_back(std::move(v));
  }
  void set_option_list(std::vector<std::unique_ptr<const ResolvedOption>> v) {
    option_list_ = std::move(v);
  }

  std::vector<std::unique_ptr<const ResolvedOption>> release_option_list() {
    std::vector<std::unique_ptr<const ResolvedOption>> tmp;
    option_list_.swap(tmp);
    return tmp;
  }

  SqlSecurity sql_security() const {
    accessed_ |= (1<<10);
    return sql_security_;
  }
  void set_sql_security(SqlSecurity v) {
    sql_security_ = v;
  }

 protected:
  explicit ResolvedCreateFunctionStmt(
      const std::vector<std::string>& name_path,
      CreateScope create_scope,
      CreateMode create_mode,
      bool has_explicit_return_type,
      const Type* return_type,
      const std::vector<std::string>& argument_name_list,
      const FunctionSignature& signature,
      bool is_aggregate,
      const std::string& language,
      const std::string& code,
      std::vector<std::unique_ptr<const ResolvedComputedColumn>> aggregate_expression_list,
      std::unique_ptr<const ResolvedExpr> function_expression,
      std::vector<std::unique_ptr<const ResolvedOption>> option_list,
      SqlSecurity sql_security,
      ConstructorOverload)
      : ResolvedCreateStatement(
            name_path,
            create_scope,
            create_mode,
            ConstructorOverload::NEW_CONSTRUCTOR),
      has_explicit_return_type_(has_explicit_return_type),
      return_type_(return_type),
      argument_name_list_(argument_name_list),
      signature_(signature),
      is_aggregate_(is_aggregate),
      language_(language),
      code_(code),
      aggregate_expression_list_(std::move(aggregate_expression_list)),
      function_expression_(std::move(function_expression)),
      option_list_(std::move(option_list)),
      sql_security_(sql_security) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  bool has_explicit_return_type_;
  const Type* return_type_;
  std::vector<std::string> argument_name_list_;
  FunctionSignature signature_;
  bool is_aggregate_;
  std::string language_;
  std::string code_;
  std::vector<std::unique_ptr<const ResolvedComputedColumn>> aggregate_expression_list_;
  std::unique_ptr<const ResolvedExpr> function_expression_;
  std::vector<std::unique_ptr<const ResolvedOption>> option_list_;
  SqlSecurity sql_security_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedCreateFunctionStmt> MakeResolvedCreateFunctionStmt(
    const std::vector<std::string>& name_path,
    ResolvedCreateStatement::CreateScope create_scope,
    ResolvedCreateStatement::CreateMode create_mode,
    bool has_explicit_return_type,
    const Type* return_type,
    const std::vector<std::string>& argument_name_list,
    const FunctionSignature& signature,
    bool is_aggregate,
    const std::string& language,
    const std::string& code,
    std::vector<std::unique_ptr<const ResolvedComputedColumn>> aggregate_expression_list,
    std::unique_ptr<const ResolvedExpr> function_expression,
    std::vector<std::unique_ptr<const ResolvedOption>> option_list,
    ResolvedCreateStatement::SqlSecurity sql_security) {
  return std::unique_ptr<ResolvedCreateFunctionStmt>(new ResolvedCreateFunctionStmt(
        name_path,
        create_scope,
        create_mode,
        has_explicit_return_type,
        return_type,
        argument_name_list,
        signature,
        is_aggregate,
        language,
        code,
        std::move(aggregate_expression_list),
        std::move(function_expression),
        std::move(option_list),
        sql_security,
        ResolvedCreateFunctionStmt::NEW_CONSTRUCTOR));
}

// Overloaded factory method for the construction of ResolvedCreateFunctionStmt with
// a wider range of inputs for node-vector inputs.  In particular allows:
// 1. unique_ptr element type can be non-const.
// 2. unique_ptr element type can be any descendant of the required type.
// 3. input container can be any object with a `begin()` and `end()`.
//
// Note, initializer lists cannot be used to pass
//  aggregate_expression_list, option_list
// due to incompatibility with unique_ptr.  Use zetasql::MakeNodeVector
// instead.
template <
  typename aggregate_expression_list_t
      = std::vector<std::unique_ptr<const ResolvedComputedColumn>>,
  typename option_list_t
      = std::vector<std::unique_ptr<const ResolvedOption>>>
std::unique_ptr<ResolvedCreateFunctionStmt> MakeResolvedCreateFunctionStmt(
    const std::vector<std::string>& name_path,
    ResolvedCreateStatement::CreateScope create_scope,
    ResolvedCreateStatement::CreateMode create_mode,
    bool has_explicit_return_type,
    const Type* return_type,
    const std::vector<std::string>& argument_name_list,
    const FunctionSignature& signature,
    bool is_aggregate,
    const std::string& language,
    const std::string& code,
    aggregate_expression_list_t aggregate_expression_list,
    std::unique_ptr<const ResolvedExpr> function_expression,
    option_list_t option_list,
    ResolvedCreateStatement::SqlSecurity sql_security) {
  static_assert(std::is_base_of<
      ResolvedComputedColumn,
      typename std::decay<decltype(**(aggregate_expression_list.begin()))>::type>::value,
      "aggregate_expression_list must be a container of unique_ptr with elements of type "
      "ResolvedComputedColumn (or its descendants).");
  static_assert(std::is_base_of<
      ResolvedOption,
      typename std::decay<decltype(**(option_list.begin()))>::type>::value,
      "option_list must be a container of unique_ptr with elements of type "
      "ResolvedOption (or its descendants).");
  return MakeResolvedCreateFunctionStmt(
      name_path,
      create_scope,
      create_mode,
      has_explicit_return_type,
      return_type,
      argument_name_list,
      signature,
      is_aggregate,
      language,
      code,
      {std::make_move_iterator(aggregate_expression_list.begin()),
       std::make_move_iterator(aggregate_expression_list.end())},
      std::move(function_expression),
      {std::make_move_iterator(option_list.begin()),
       std::make_move_iterator(option_list.end())},
      sql_security);
}

// This represents an argument definition, e.g. in a function's argument
// list.
//
// <name> is the name of the argument; optional for DROP FUNCTION statements.
// <type> is the type of the argument.
// <argument_kind> indicates what kind of argument this is, including scalar
//         vs aggregate.  NOT_AGGREGATE means this is a non-aggregate
//         argument in an aggregate function, which can only passed constant
//         values only.
//
// NOTE: Statements that create functions now include a FunctionSignature
// directly, and an argument_name_list if applicable.  These completely
// describe the function signature, so the ResolvedArgumentDef list can
// be considered unnecessary and deprecated.
// TODO We could remove this node in the future.
class ResolvedArgumentDef final : public ResolvedArgument {
 public:
  typedef ResolvedArgument SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_ARGUMENT_DEF;

  typedef ResolvedArgumentDefEnums::ArgumentKind ArgumentKind;
  static const ArgumentKind SCALAR = ResolvedArgumentDefEnums::SCALAR;
  static const ArgumentKind AGGREGATE = ResolvedArgumentDefEnums::AGGREGATE;
  static const ArgumentKind NOT_AGGREGATE = ResolvedArgumentDefEnums::NOT_AGGREGATE;

  friend std::unique_ptr<ResolvedArgumentDef> MakeResolvedArgumentDef();
 protected:
  ResolvedArgumentDef()
      : ResolvedArgument()
      , name_()
      , type_()
      , argument_kind_()
  {}
 public:

  ResolvedArgumentDef(const ResolvedArgumentDef&) = delete;
  ResolvedArgumentDef& operator=(const ResolvedArgumentDef&) = delete;

  friend std::unique_ptr<ResolvedArgumentDef> MakeResolvedArgumentDef(
      const std::string& name,
      const Type* type,
      ArgumentKind argument_kind
  );
  ~ResolvedArgumentDef() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_ARGUMENT_DEF; }
  std::string node_kind_string() const final { return "ArgumentDef"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedArgumentDefProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedArgumentProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedArgumentDef>> RestoreFrom(
      const ResolvedArgumentDefProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  const std::string& name() const {
    accessed_ |= (1<<0);
    return name_;
  }
  void set_name(const std::string& v) {
    name_ = v;
  }

  const Type* type() const {
    accessed_ |= (1<<1);
    return type_;
  }
  void set_type(const Type* v) {
    type_ = v;
  }

  ArgumentKind argument_kind() const {
    accessed_ |= (1<<2);
    return argument_kind_;
  }
  void set_argument_kind(ArgumentKind v) {
    argument_kind_ = v;
  }

 protected:
  explicit ResolvedArgumentDef(
      const std::string& name,
      const Type* type,
      ArgumentKind argument_kind,
      ConstructorOverload)
      : ResolvedArgument(
            ConstructorOverload::NEW_CONSTRUCTOR),
      name_(name),
      type_(type),
      argument_kind_(argument_kind) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  std::string name_;
  const Type* type_;
  ArgumentKind argument_kind_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedArgumentDef> MakeResolvedArgumentDef(
    const std::string& name,
    const Type* type,
    ResolvedArgumentDef::ArgumentKind argument_kind) {
  return std::unique_ptr<ResolvedArgumentDef>(new ResolvedArgumentDef(
        name,
        type,
        argument_kind,
        ResolvedArgumentDef::NEW_CONSTRUCTOR));
}

inline std::unique_ptr<ResolvedArgumentDef> MakeResolvedArgumentDef() {
  return std::unique_ptr<ResolvedArgumentDef>(
      new ResolvedArgumentDef());
}

// This represents an argument reference, e.g. in a function's body.
// <name> is the name of the argument.
// <argument_kind> is the ArgumentKind from the ResolvedArgumentDef.
//         For scalar functions, this is always SCALAR.
//         For aggregate functions, it can be AGGREGATE or NOT_AGGREGATE.
//         If NOT_AGGREGATE, then this is a non-aggregate argument
//         to an aggregate function, which has one constant value
//         for the entire function call (over all rows in all groups).
//         (This is copied from the ResolvedArgumentDef for convenience.)
class ResolvedArgumentRef final : public ResolvedExpr {
 public:
  typedef ResolvedExpr SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_ARGUMENT_REF;

  typedef ResolvedArgumentDefEnums::ArgumentKind ArgumentKind;
  static const ArgumentKind SCALAR = ResolvedArgumentDefEnums::SCALAR;
  static const ArgumentKind AGGREGATE = ResolvedArgumentDefEnums::AGGREGATE;
  static const ArgumentKind NOT_AGGREGATE = ResolvedArgumentDefEnums::NOT_AGGREGATE;

  friend std::unique_ptr<ResolvedArgumentRef> MakeResolvedArgumentRef();
 protected:
  ResolvedArgumentRef()
      : ResolvedExpr()
      , name_()
      , argument_kind_()
  {}
 public:

  ResolvedArgumentRef(const ResolvedArgumentRef&) = delete;
  ResolvedArgumentRef& operator=(const ResolvedArgumentRef&) = delete;

  friend std::unique_ptr<ResolvedArgumentRef> MakeResolvedArgumentRef(
      const Type* type,
      const std::string& name,
      ArgumentKind argument_kind
  );
  ~ResolvedArgumentRef() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_ARGUMENT_REF; }
  std::string node_kind_string() const final { return "ArgumentRef"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedArgumentRefProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedExprProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedArgumentRef>> RestoreFrom(
      const ResolvedArgumentRefProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  const std::string& name() const {
    accessed_ |= (1<<0);
    return name_;
  }
  void set_name(const std::string& v) {
    name_ = v;
  }

  ArgumentKind argument_kind() const {
    accessed_ |= (1<<1);
    return argument_kind_;
  }
  void set_argument_kind(ArgumentKind v) {
    argument_kind_ = v;
  }

 protected:
  explicit ResolvedArgumentRef(
      const Type* type,
      const std::string& name,
      ArgumentKind argument_kind,
      ConstructorOverload)
      : ResolvedExpr(
            type,
            ConstructorOverload::NEW_CONSTRUCTOR),
      name_(name),
      argument_kind_(argument_kind) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  std::string name_;
  ArgumentKind argument_kind_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedArgumentRef> MakeResolvedArgumentRef(
    const Type* type,
    const std::string& name,
    ResolvedArgumentDef::ArgumentKind argument_kind) {
  return std::unique_ptr<ResolvedArgumentRef>(new ResolvedArgumentRef(
        type,
        name,
        argument_kind,
        ResolvedArgumentRef::NEW_CONSTRUCTOR));
}

inline std::unique_ptr<ResolvedArgumentRef> MakeResolvedArgumentRef() {
  return std::unique_ptr<ResolvedArgumentRef>(
      new ResolvedArgumentRef());
}

// This statement creates a user-defined table-valued function:
//   CREATE [TEMP] TABLE FUNCTION [IF NOT EXISTS]
//     <name_path> (<argument_name_list>)
//     [RETURNS <return_type>]
//     [OPTIONS (<option_list>)]
//     [LANGUAGE <language>]
//     [AS <code> | AS ( <query> )]
//
//   <argument_name_list> contains the names of the function arguments.
//   <signature> is the FunctionSignature of the created function, with all
//          options.  This can be used to create a Function to load into a
//          Catalog for future queries.
//   <option_list> has engine-specific directives for modifying functions.
//   <language> is the programming language used by the function. This field
//          is set to 'SQL' for SQL functions, to the language name specified
//          in the LANGUAGE clause if present, and to 'UNDECLARED' if both
//          the LANGUAGE clause and query are not present.
//   <code> is an optional string literal that contains the function
//          definition.  Some engines may allow this argument to be omitted
//          for certain types of external functions.  This will always be set
//          for SQL functions.
//   <query> is the SQL query invoked for the function.  This will be unset
//          for external language functions. For non-templated SQL functions,
//          this is a resolved representation of the query in <code>.
//   <output_column_list> is the list of resolved output
//          columns returned by the table-valued function.
//   <is_value_table> If true, this function returns a value table.
//          Rather than producing rows with named columns, it produces
//          rows with a single unnamed value type. <output_column_list> will
//          have exactly one anonymous column (with no name).
//          See (broken link).
//   <sql_security> is the declared security mode for the function. Values
//          include 'INVOKER', 'DEFINER'.
//
// ----------------------
// Table-Valued Functions
// ----------------------
//
// This is a statement to create a new table-valued function. Each
// table-valued function returns an entire table as output instead of a
// single scalar value. Table-valued functions can only be created if
// LanguageOptions has FEATURE_CREATE_TABLE_FUNCTION enabled.
//
// For SQL table-valued functions that include a defined SQL body, the
// <query> is non-NULL and contains the resolved SQL body.
// In this case, <output_column_list> contains a list of the
// output columns of the SQL body. The <query> uses
// ResolvedArgumentRefs to refer to scalar arguments and
// ResolvedRelationArgumentScans to refer to relation arguments.
//
// The table-valued function may include RETURNS TABLE<...> to explicitly
// specify a schema for the output table returned by the function. If the
// function declaration includes a SQL body, then the names and types of the
// output columns of the corresponding <query> will have been
// coerced to exactly match 1:1 with the names and types of the columns
// specified in the RETURNS TABLE<...> section.
//
// When resolving a query that calls a table-valued function, the query will
// have a ResolvedTVFScan that invokes the function.
//
// Value tables: If the function declaration includes a value-table
// parameter, this is written as an argument of type "TABLE" where the table
// contains a single anonymous column with a type but no name. In this case,
// calls to the function may pass a (regular or value) table with a single
// (named or unnamed) column for any of these parameters, and ZetaSQL
// accepts these arguments as long as the column type matches.
//
// Similarly, if the CREATE TABLE FUNCTION statement includes a "RETURNS
// TABLE" section with a single column with no name, then this defines a
// value-table return type. The function then returns a value table as long
// as the SQL body returns a single column whose type matches (independent of
// whether the SQL body result is a value table or not, and whether the
// returned column is named or unnamed).
//
// --------------------------------
// Templated Table-Valued Functions
// --------------------------------
//
// ZetaSQL supports table-valued function declarations with parameters of
// type ANY TABLE. This type indicates that any schema is valid for tables
// passed for this parameter. In this case:
//
// * the IsTemplated() method of the <signature> field returns true,
// * the <output_column_list> field is empty,
// * the <is_value_table> field is set to a default value of false (since
//   ZetaSQL cannot analyze the function body in the presence of templated
//   parameters, it is not possible to detect this property yet),
//
// TODO: Update this description once ZetaSQL supports more types
// of templated function parameters. Currently only ANY TABLE is supported.
class ResolvedCreateTableFunctionStmt final : public ResolvedCreateStatement {
 public:
  typedef ResolvedCreateStatement SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_CREATE_TABLE_FUNCTION_STMT;

  friend std::unique_ptr<ResolvedCreateTableFunctionStmt> MakeResolvedCreateTableFunctionStmt(
      const std::vector<std::string>& name_path,
      CreateScope create_scope,
      CreateMode create_mode,
      const std::vector<std::string>& argument_name_list,
      const FunctionSignature& signature,
      std::vector<std::unique_ptr<const ResolvedOption>> option_list,
      const std::string& language,
      const std::string& code,
      std::unique_ptr<const ResolvedScan> query,
      std::vector<std::unique_ptr<const ResolvedOutputColumn>> output_column_list,
      bool is_value_table,
      SqlSecurity sql_security
  );
  ~ResolvedCreateTableFunctionStmt() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_CREATE_TABLE_FUNCTION_STMT; }
  std::string node_kind_string() const final { return "CreateTableFunctionStmt"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedCreateTableFunctionStmtProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedCreateStatementProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedCreateTableFunctionStmt>> RestoreFrom(
      const ResolvedCreateTableFunctionStmtProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  const std::vector<std::string>& argument_name_list() const {
    accessed_ |= (1<<0);
    return argument_name_list_;
  }
  int argument_name_list_size() const {
    if (argument_name_list_.empty()) accessed_ |= (1<<0);
    return static_cast<int>(argument_name_list_.size());
  }
  std::string argument_name_list(int i) const {
    accessed_ |= (1<<0);
    return argument_name_list_.at(i);
  }
  void add_argument_name_list(std::string v) {
    argument_name_list_.push_back(std::string(v));
  }
  void set_argument_name_list(const std::vector<std::string>& v) {
    argument_name_list_ = v;
  }
  std::vector<std::string>* mutable_argument_name_list() {
    accessed_ |= (1<<0);
    return &argument_name_list_;
  }

  const FunctionSignature& signature() const {
    accessed_ |= (1<<1);
    return signature_;
  }
  void set_signature(const FunctionSignature& v) {
    signature_ = v;
  }

  const std::vector<std::unique_ptr<const ResolvedOption>>& option_list() const {
    accessed_ |= (1<<2);
    return option_list_;
  }
  int option_list_size() const {
    if (option_list_.empty()) accessed_ |= (1<<2);
    return static_cast<int>(option_list_.size());
  }
  const ResolvedOption* option_list(int i) const {
    accessed_ |= (1<<2);
    return option_list_.at(i).get();
  }
  void add_option_list(std::unique_ptr<const ResolvedOption> v) {
    option_list_.emplace_back(std::move(v));
  }
  void set_option_list(std::vector<std::unique_ptr<const ResolvedOption>> v) {
    option_list_ = std::move(v);
  }

  std::vector<std::unique_ptr<const ResolvedOption>> release_option_list() {
    std::vector<std::unique_ptr<const ResolvedOption>> tmp;
    option_list_.swap(tmp);
    return tmp;
  }

  const std::string& language() const {
    accessed_ |= (1<<3);
    return language_;
  }
  void set_language(const std::string& v) {
    language_ = v;
  }

  const std::string& code() const {
    accessed_ |= (1<<4);
    return code_;
  }
  void set_code(const std::string& v) {
    code_ = v;
  }

  const ResolvedScan* query() const {
    accessed_ |= (1<<5);
    return query_.get();
  }
  void set_query(std::unique_ptr<const ResolvedScan> v) {
    query_ = std::move(v);
  }

  std::unique_ptr<const ResolvedScan> release_query() {
    return std::move(query_);
  }

  const std::vector<std::unique_ptr<const ResolvedOutputColumn>>& output_column_list() const {
    accessed_ |= (1<<6);
    return output_column_list_;
  }
  int output_column_list_size() const {
    if (output_column_list_.empty()) accessed_ |= (1<<6);
    return static_cast<int>(output_column_list_.size());
  }
  const ResolvedOutputColumn* output_column_list(int i) const {
    accessed_ |= (1<<6);
    return output_column_list_.at(i).get();
  }
  void add_output_column_list(std::unique_ptr<const ResolvedOutputColumn> v) {
    output_column_list_.emplace_back(std::move(v));
  }
  void set_output_column_list(std::vector<std::unique_ptr<const ResolvedOutputColumn>> v) {
    output_column_list_ = std::move(v);
  }

  std::vector<std::unique_ptr<const ResolvedOutputColumn>> release_output_column_list() {
    std::vector<std::unique_ptr<const ResolvedOutputColumn>> tmp;
    output_column_list_.swap(tmp);
    return tmp;
  }

  bool is_value_table() const {
    accessed_ |= (1<<7);
    return is_value_table_;
  }
  void set_is_value_table(bool v) {
    is_value_table_ = v;
  }

  SqlSecurity sql_security() const {
    accessed_ |= (1<<8);
    return sql_security_;
  }
  void set_sql_security(SqlSecurity v) {
    sql_security_ = v;
  }

 protected:
  explicit ResolvedCreateTableFunctionStmt(
      const std::vector<std::string>& name_path,
      CreateScope create_scope,
      CreateMode create_mode,
      const std::vector<std::string>& argument_name_list,
      const FunctionSignature& signature,
      std::vector<std::unique_ptr<const ResolvedOption>> option_list,
      const std::string& language,
      const std::string& code,
      std::unique_ptr<const ResolvedScan> query,
      std::vector<std::unique_ptr<const ResolvedOutputColumn>> output_column_list,
      bool is_value_table,
      SqlSecurity sql_security,
      ConstructorOverload)
      : ResolvedCreateStatement(
            name_path,
            create_scope,
            create_mode,
            ConstructorOverload::NEW_CONSTRUCTOR),
      argument_name_list_(argument_name_list),
      signature_(signature),
      option_list_(std::move(option_list)),
      language_(language),
      code_(code),
      query_(std::move(query)),
      output_column_list_(std::move(output_column_list)),
      is_value_table_(is_value_table),
      sql_security_(sql_security) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  std::vector<std::string> argument_name_list_;
  FunctionSignature signature_;
  std::vector<std::unique_ptr<const ResolvedOption>> option_list_;
  std::string language_;
  std::string code_;
  std::unique_ptr<const ResolvedScan> query_;
  std::vector<std::unique_ptr<const ResolvedOutputColumn>> output_column_list_;
  bool is_value_table_;
  SqlSecurity sql_security_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedCreateTableFunctionStmt> MakeResolvedCreateTableFunctionStmt(
    const std::vector<std::string>& name_path,
    ResolvedCreateStatement::CreateScope create_scope,
    ResolvedCreateStatement::CreateMode create_mode,
    const std::vector<std::string>& argument_name_list,
    const FunctionSignature& signature,
    std::vector<std::unique_ptr<const ResolvedOption>> option_list,
    const std::string& language,
    const std::string& code,
    std::unique_ptr<const ResolvedScan> query,
    std::vector<std::unique_ptr<const ResolvedOutputColumn>> output_column_list,
    bool is_value_table,
    ResolvedCreateStatement::SqlSecurity sql_security) {
  return std::unique_ptr<ResolvedCreateTableFunctionStmt>(new ResolvedCreateTableFunctionStmt(
        name_path,
        create_scope,
        create_mode,
        argument_name_list,
        signature,
        std::move(option_list),
        language,
        code,
        std::move(query),
        std::move(output_column_list),
        is_value_table,
        sql_security,
        ResolvedCreateTableFunctionStmt::NEW_CONSTRUCTOR));
}

// Overloaded factory method for the construction of ResolvedCreateTableFunctionStmt with
// a wider range of inputs for node-vector inputs.  In particular allows:
// 1. unique_ptr element type can be non-const.
// 2. unique_ptr element type can be any descendant of the required type.
// 3. input container can be any object with a `begin()` and `end()`.
//
// Note, initializer lists cannot be used to pass
//  option_list, output_column_list
// due to incompatibility with unique_ptr.  Use zetasql::MakeNodeVector
// instead.
template <
  typename option_list_t
      = std::vector<std::unique_ptr<const ResolvedOption>>,
  typename output_column_list_t
      = std::vector<std::unique_ptr<const ResolvedOutputColumn>>>
std::unique_ptr<ResolvedCreateTableFunctionStmt> MakeResolvedCreateTableFunctionStmt(
    const std::vector<std::string>& name_path,
    ResolvedCreateStatement::CreateScope create_scope,
    ResolvedCreateStatement::CreateMode create_mode,
    const std::vector<std::string>& argument_name_list,
    const FunctionSignature& signature,
    option_list_t option_list,
    const std::string& language,
    const std::string& code,
    std::unique_ptr<const ResolvedScan> query,
    output_column_list_t output_column_list,
    bool is_value_table,
    ResolvedCreateStatement::SqlSecurity sql_security) {
  static_assert(std::is_base_of<
      ResolvedOption,
      typename std::decay<decltype(**(option_list.begin()))>::type>::value,
      "option_list must be a container of unique_ptr with elements of type "
      "ResolvedOption (or its descendants).");
  static_assert(std::is_base_of<
      ResolvedOutputColumn,
      typename std::decay<decltype(**(output_column_list.begin()))>::type>::value,
      "output_column_list must be a container of unique_ptr with elements of type "
      "ResolvedOutputColumn (or its descendants).");
  return MakeResolvedCreateTableFunctionStmt(
      name_path,
      create_scope,
      create_mode,
      argument_name_list,
      signature,
      {std::make_move_iterator(option_list.begin()),
       std::make_move_iterator(option_list.end())},
      language,
      code,
      std::move(query),
      {std::make_move_iterator(output_column_list.begin()),
       std::make_move_iterator(output_column_list.end())},
      is_value_table,
      sql_security);
}

// This represents a relation argument reference in a table-valued function's
// body. The 'column_list' of this ResolvedScan includes column names from
// the relation argument in the table-valued function signature.
class ResolvedRelationArgumentScan final : public ResolvedScan {
 public:
  typedef ResolvedScan SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_RELATION_ARGUMENT_SCAN;

  friend std::unique_ptr<ResolvedRelationArgumentScan> MakeResolvedRelationArgumentScan();
 protected:
  ResolvedRelationArgumentScan()
      : ResolvedScan()
      , name_()
      , is_value_table_()
  {}
 public:

  ResolvedRelationArgumentScan(const ResolvedRelationArgumentScan&) = delete;
  ResolvedRelationArgumentScan& operator=(const ResolvedRelationArgumentScan&) = delete;

  friend std::unique_ptr<ResolvedRelationArgumentScan> MakeResolvedRelationArgumentScan(
      const std::vector<ResolvedColumn>& column_list,
      const std::string& name,
      bool is_value_table
  );
  ~ResolvedRelationArgumentScan() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_RELATION_ARGUMENT_SCAN; }
  std::string node_kind_string() const final { return "RelationArgumentScan"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedRelationArgumentScanProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedScanProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedRelationArgumentScan>> RestoreFrom(
      const ResolvedRelationArgumentScanProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  // This is the name of the relation argument for the table-valued
  // function.  It is used to match this relation argument reference in
  // a TVF SQL function body with one of possibly several relation
  // arguments in the TVF call.
  const std::string& name() const {
    accessed_ |= (1<<0);
    return name_;
  }
  void set_name(const std::string& v) {
    name_ = v;
  }

  // If true, the result of this query is a value table. Rather than
  // producing rows with named columns, it produces rows with a single
  // unnamed value type. See (broken link).
  bool is_value_table() const {
    accessed_ |= (1<<1);
    return is_value_table_;
  }
  void set_is_value_table(bool v) {
    is_value_table_ = v;
  }

 protected:
  explicit ResolvedRelationArgumentScan(
      const std::vector<ResolvedColumn>& column_list,
      const std::string& name,
      bool is_value_table,
      ConstructorOverload)
      : ResolvedScan(
            column_list,
            ConstructorOverload::NEW_CONSTRUCTOR),
      name_(name),
      is_value_table_(is_value_table) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  std::string name_;
  bool is_value_table_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedRelationArgumentScan> MakeResolvedRelationArgumentScan(
    const std::vector<ResolvedColumn>& column_list,
    const std::string& name,
    bool is_value_table) {
  return std::unique_ptr<ResolvedRelationArgumentScan>(new ResolvedRelationArgumentScan(
        column_list,
        name,
        is_value_table,
        ResolvedRelationArgumentScan::NEW_CONSTRUCTOR));
}

inline std::unique_ptr<ResolvedRelationArgumentScan> MakeResolvedRelationArgumentScan() {
  return std::unique_ptr<ResolvedRelationArgumentScan>(
      new ResolvedRelationArgumentScan());
}

// This statement: [ (<arg_list>) ];
//
// <arg_list> is an optional list of parameters.  If given, each parameter
//            may consist of a type, or a name and a type.
//
// NOTE: This can be considered deprecated in favor of the FunctionSignature
//       stored directly in the statement.
//
// NOTE: ResolvedArgumentList is not related to the ResolvedArgument class,
//       which just exists to organize node classes.
class ResolvedArgumentList final : public ResolvedArgument {
 public:
  typedef ResolvedArgument SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_ARGUMENT_LIST;

  friend std::unique_ptr<ResolvedArgumentList> MakeResolvedArgumentList();
 protected:
  ResolvedArgumentList()
      : ResolvedArgument()
      , arg_list_()
  {}
 public:

  ResolvedArgumentList(const ResolvedArgumentList&) = delete;
  ResolvedArgumentList& operator=(const ResolvedArgumentList&) = delete;

  friend std::unique_ptr<ResolvedArgumentList> MakeResolvedArgumentList(
      std::vector<std::unique_ptr<const ResolvedArgumentDef>> arg_list
  );
  ~ResolvedArgumentList() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_ARGUMENT_LIST; }
  std::string node_kind_string() const final { return "ArgumentList"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedArgumentListProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedArgumentProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedArgumentList>> RestoreFrom(
      const ResolvedArgumentListProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  const std::vector<std::unique_ptr<const ResolvedArgumentDef>>& arg_list() const {
    accessed_ |= (1<<0);
    return arg_list_;
  }
  int arg_list_size() const {
    if (arg_list_.empty()) accessed_ |= (1<<0);
    return static_cast<int>(arg_list_.size());
  }
  const ResolvedArgumentDef* arg_list(int i) const {
    accessed_ |= (1<<0);
    return arg_list_.at(i).get();
  }
  void add_arg_list(std::unique_ptr<const ResolvedArgumentDef> v) {
    arg_list_.emplace_back(std::move(v));
  }
  void set_arg_list(std::vector<std::unique_ptr<const ResolvedArgumentDef>> v) {
    arg_list_ = std::move(v);
  }

  std::vector<std::unique_ptr<const ResolvedArgumentDef>> release_arg_list() {
    std::vector<std::unique_ptr<const ResolvedArgumentDef>> tmp;
    arg_list_.swap(tmp);
    return tmp;
  }

 protected:
  explicit ResolvedArgumentList(
      std::vector<std::unique_ptr<const ResolvedArgumentDef>> arg_list,
      ConstructorOverload)
      : ResolvedArgument(
            ConstructorOverload::NEW_CONSTRUCTOR),
      arg_list_(std::move(arg_list)) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  std::vector<std::unique_ptr<const ResolvedArgumentDef>> arg_list_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedArgumentList> MakeResolvedArgumentList(
    std::vector<std::unique_ptr<const ResolvedArgumentDef>> arg_list) {
  return std::unique_ptr<ResolvedArgumentList>(new ResolvedArgumentList(
        std::move(arg_list),
        ResolvedArgumentList::NEW_CONSTRUCTOR));
}

// Overloaded factory method for the construction of ResolvedArgumentList with
// a wider range of inputs for node-vector inputs.  In particular allows:
// 1. unique_ptr element type can be non-const.
// 2. unique_ptr element type can be any descendant of the required type.
// 3. input container can be any object with a `begin()` and `end()`.
//
// Note, initializer lists cannot be used to pass
//  arg_list
// due to incompatibility with unique_ptr.  Use zetasql::MakeNodeVector
// instead.
template <
  typename arg_list_t
      = std::vector<std::unique_ptr<const ResolvedArgumentDef>>>
std::unique_ptr<ResolvedArgumentList> MakeResolvedArgumentList(
    arg_list_t arg_list) {
  static_assert(std::is_base_of<
      ResolvedArgumentDef,
      typename std::decay<decltype(**(arg_list.begin()))>::type>::value,
      "arg_list must be a container of unique_ptr with elements of type "
      "ResolvedArgumentDef (or its descendants).");
  return MakeResolvedArgumentList(
      {std::make_move_iterator(arg_list.begin()),
       std::make_move_iterator(arg_list.end())});
}

inline std::unique_ptr<ResolvedArgumentList> MakeResolvedArgumentList() {
  return std::unique_ptr<ResolvedArgumentList>(
      new ResolvedArgumentList());
}

// This wrapper is used for an optional FunctionSignature.
class ResolvedFunctionSignatureHolder final : public ResolvedArgument {
 public:
  typedef ResolvedArgument SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_FUNCTION_SIGNATURE_HOLDER;

  friend std::unique_ptr<ResolvedFunctionSignatureHolder> MakeResolvedFunctionSignatureHolder(
      const FunctionSignature& signature
  );
  ~ResolvedFunctionSignatureHolder() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_FUNCTION_SIGNATURE_HOLDER; }
  std::string node_kind_string() const final { return "FunctionSignatureHolder"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedFunctionSignatureHolderProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedArgumentProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedFunctionSignatureHolder>> RestoreFrom(
      const ResolvedFunctionSignatureHolderProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  const FunctionSignature& signature() const {
    accessed_ |= (1<<0);
    return signature_;
  }
  void set_signature(const FunctionSignature& v) {
    signature_ = v;
  }

 protected:
  explicit ResolvedFunctionSignatureHolder(
      const FunctionSignature& signature,
      ConstructorOverload)
      : ResolvedArgument(
            ConstructorOverload::NEW_CONSTRUCTOR),
      signature_(signature) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  FunctionSignature signature_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedFunctionSignatureHolder> MakeResolvedFunctionSignatureHolder(
    const FunctionSignature& signature) {
  return std::unique_ptr<ResolvedFunctionSignatureHolder>(new ResolvedFunctionSignatureHolder(
        signature,
        ResolvedFunctionSignatureHolder::NEW_CONSTRUCTOR));
}

// This statement: DROP FUNCTION [IF EXISTS] <name_path>
//   [ (<arguments>) ];
//
// <is_if_exists> silently ignore the "name_path does not exist" error.
// <name_path> is the identifier path of the function to be dropped.
// <arguments> is an optional list of parameters.  If given, each parameter
//            may consist of a type, or a name and a type.  The name is
//            disregarded, and is allowed to permit copy-paste from CREATE
//            FUNCTION statements.
// <signature> is the signature of the dropped function.  Argument names and
//            argument options are ignored because only the types matter
//            for matching signatures in DROP FUNCTION.  The return type
//            in this signature will always be <void>, since return type
//            is ignored when matching signatures for DROP.
//            TODO <arguments> could be deprecated in favor of this.
class ResolvedDropFunctionStmt final : public ResolvedStatement {
 public:
  typedef ResolvedStatement SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_DROP_FUNCTION_STMT;

  friend std::unique_ptr<ResolvedDropFunctionStmt> MakeResolvedDropFunctionStmt();
 protected:
  ResolvedDropFunctionStmt()
      : ResolvedStatement()
      , is_if_exists_()
      , name_path_()
      , arguments_()
      , signature_()
  {}
 public:

  ResolvedDropFunctionStmt(const ResolvedDropFunctionStmt&) = delete;
  ResolvedDropFunctionStmt& operator=(const ResolvedDropFunctionStmt&) = delete;

  friend std::unique_ptr<ResolvedDropFunctionStmt> MakeResolvedDropFunctionStmt(
      bool is_if_exists,
      const std::vector<std::string>& name_path,
      std::unique_ptr<const ResolvedArgumentList> arguments,
      std::unique_ptr<const ResolvedFunctionSignatureHolder> signature
  );
  ~ResolvedDropFunctionStmt() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_DROP_FUNCTION_STMT; }
  std::string node_kind_string() const final { return "DropFunctionStmt"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedDropFunctionStmtProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedStatementProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedDropFunctionStmt>> RestoreFrom(
      const ResolvedDropFunctionStmtProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  bool is_if_exists() const {
    accessed_ |= (1<<0);
    return is_if_exists_;
  }
  void set_is_if_exists(bool v) {
    is_if_exists_ = v;
  }

  const std::vector<std::string>& name_path() const {
    accessed_ |= (1<<1);
    return name_path_;
  }
  int name_path_size() const {
    if (name_path_.empty()) accessed_ |= (1<<1);
    return static_cast<int>(name_path_.size());
  }
  std::string name_path(int i) const {
    accessed_ |= (1<<1);
    return name_path_.at(i);
  }
  void add_name_path(std::string v) {
    name_path_.push_back(std::string(v));
  }
  void set_name_path(const std::vector<std::string>& v) {
    name_path_ = v;
  }
  std::vector<std::string>* mutable_name_path() {
    accessed_ |= (1<<1);
    return &name_path_;
  }

  // NOTE: arguments for DROP FUNCTION statements are matched only on
  // type; names for any arguments in ResolvedArgumentList will be set
  // to the empty string irrespective of whether or not argument names
  // were given in the DROP FUNCTION statement.
  const ResolvedArgumentList* arguments() const {
    accessed_ |= (1<<2);
    return arguments_.get();
  }
  void set_arguments(std::unique_ptr<const ResolvedArgumentList> v) {
    arguments_ = std::move(v);
  }

  std::unique_ptr<const ResolvedArgumentList> release_arguments() {
    return std::move(arguments_);
  }

  // NOTE: arguments for DROP FUNCTION statements are matched only on
  // type; names are irrelevant, so no argument names are saved to use
  // with this signature.  Additionally, the return type will always be
  // <void>, since return types are ignored for DROP FUNCTION.
  const ResolvedFunctionSignatureHolder* signature() const {
    accessed_ |= (1<<3);
    return signature_.get();
  }
  void set_signature(std::unique_ptr<const ResolvedFunctionSignatureHolder> v) {
    signature_ = std::move(v);
  }

  std::unique_ptr<const ResolvedFunctionSignatureHolder> release_signature() {
    return std::move(signature_);
  }

 protected:
  explicit ResolvedDropFunctionStmt(
      bool is_if_exists,
      const std::vector<std::string>& name_path,
      std::unique_ptr<const ResolvedArgumentList> arguments,
      std::unique_ptr<const ResolvedFunctionSignatureHolder> signature,
      ConstructorOverload)
      : ResolvedStatement(
            ConstructorOverload::NEW_CONSTRUCTOR),
      is_if_exists_(is_if_exists),
      name_path_(name_path),
      arguments_(std::move(arguments)),
      signature_(std::move(signature)) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  bool is_if_exists_;
  std::vector<std::string> name_path_;
  std::unique_ptr<const ResolvedArgumentList> arguments_;
  std::unique_ptr<const ResolvedFunctionSignatureHolder> signature_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedDropFunctionStmt> MakeResolvedDropFunctionStmt(
    bool is_if_exists,
    const std::vector<std::string>& name_path,
    std::unique_ptr<const ResolvedArgumentList> arguments,
    std::unique_ptr<const ResolvedFunctionSignatureHolder> signature) {
  return std::unique_ptr<ResolvedDropFunctionStmt>(new ResolvedDropFunctionStmt(
        is_if_exists,
        name_path,
        std::move(arguments),
        std::move(signature),
        ResolvedDropFunctionStmt::NEW_CONSTRUCTOR));
}

inline std::unique_ptr<ResolvedDropFunctionStmt> MakeResolvedDropFunctionStmt() {
  return std::unique_ptr<ResolvedDropFunctionStmt>(
      new ResolvedDropFunctionStmt());
}

// This statement: CALL <procedure>;
//
// <procedure> Procedure to call.
// <signature> Resolved FunctionSignature for this procedure.
// <argument_list> Procedure arguments.
class ResolvedCallStmt final : public ResolvedStatement {
 public:
  typedef ResolvedStatement SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_CALL_STMT;

  friend std::unique_ptr<ResolvedCallStmt> MakeResolvedCallStmt(
      const Procedure* procedure,
      const FunctionSignature& signature,
      std::vector<std::unique_ptr<const ResolvedExpr>> argument_list
  );
  ~ResolvedCallStmt() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_CALL_STMT; }
  std::string node_kind_string() const final { return "CallStmt"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedCallStmtProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedStatementProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedCallStmt>> RestoreFrom(
      const ResolvedCallStmtProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  const Procedure* procedure() const {
    accessed_ |= (1<<0);
    return procedure_;
  }
  void set_procedure(const Procedure* v) {
    procedure_ = v;
  }

  const FunctionSignature& signature() const {
    accessed_ |= (1<<1);
    return signature_;
  }
  void set_signature(const FunctionSignature& v) {
    signature_ = v;
  }

  const std::vector<std::unique_ptr<const ResolvedExpr>>& argument_list() const {
    accessed_ |= (1<<2);
    return argument_list_;
  }
  int argument_list_size() const {
    if (argument_list_.empty()) accessed_ |= (1<<2);
    return static_cast<int>(argument_list_.size());
  }
  const ResolvedExpr* argument_list(int i) const {
    accessed_ |= (1<<2);
    return argument_list_.at(i).get();
  }
  void add_argument_list(std::unique_ptr<const ResolvedExpr> v) {
    argument_list_.emplace_back(std::move(v));
  }
  void set_argument_list(std::vector<std::unique_ptr<const ResolvedExpr>> v) {
    argument_list_ = std::move(v);
  }

  std::vector<std::unique_ptr<const ResolvedExpr>> release_argument_list() {
    std::vector<std::unique_ptr<const ResolvedExpr>> tmp;
    argument_list_.swap(tmp);
    return tmp;
  }

 protected:
  explicit ResolvedCallStmt(
      const Procedure* procedure,
      const FunctionSignature& signature,
      std::vector<std::unique_ptr<const ResolvedExpr>> argument_list,
      ConstructorOverload)
      : ResolvedStatement(
            ConstructorOverload::NEW_CONSTRUCTOR),
      procedure_(procedure),
      signature_(signature),
      argument_list_(std::move(argument_list)) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  const Procedure* procedure_;
  FunctionSignature signature_;
  std::vector<std::unique_ptr<const ResolvedExpr>> argument_list_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedCallStmt> MakeResolvedCallStmt(
    const Procedure* procedure,
    const FunctionSignature& signature,
    std::vector<std::unique_ptr<const ResolvedExpr>> argument_list) {
  return std::unique_ptr<ResolvedCallStmt>(new ResolvedCallStmt(
        procedure,
        signature,
        std::move(argument_list),
        ResolvedCallStmt::NEW_CONSTRUCTOR));
}

// Overloaded factory method for the construction of ResolvedCallStmt with
// a wider range of inputs for node-vector inputs.  In particular allows:
// 1. unique_ptr element type can be non-const.
// 2. unique_ptr element type can be any descendant of the required type.
// 3. input container can be any object with a `begin()` and `end()`.
//
// Note, initializer lists cannot be used to pass
//  argument_list
// due to incompatibility with unique_ptr.  Use zetasql::MakeNodeVector
// instead.
template <
  typename argument_list_t
      = std::vector<std::unique_ptr<const ResolvedExpr>>>
std::unique_ptr<ResolvedCallStmt> MakeResolvedCallStmt(
    const Procedure* procedure,
    const FunctionSignature& signature,
    argument_list_t argument_list) {
  static_assert(std::is_base_of<
      ResolvedExpr,
      typename std::decay<decltype(**(argument_list.begin()))>::type>::value,
      "argument_list must be a container of unique_ptr with elements of type "
      "ResolvedExpr (or its descendants).");
  return MakeResolvedCallStmt(
      procedure,
      signature,
      {std::make_move_iterator(argument_list.begin()),
       std::make_move_iterator(argument_list.end())});
}

// This statement: IMPORT <import_kind>
//                              [<name_path> [AS|INTO <alias_path>]
//                              |<file_path>]
//                        [<option_list>];
//
// <import_kind> The type of the object, currently supports MODULE and PROTO.
// <name_path>   The identifier path of the object to import, e.g., foo.bar,
//               used in IMPORT MODULE statement.
// <file_path>   The file path of the object to import, e.g., "file.proto",
//               used in IMPORT PROTO statement.
// <alias_path>  The AS alias path for the object.
// <into_alias_path>  The INTO alias path for the object.
// <option_list> Engine-specific directives for the import.
//
// Either <name_path> or <file_path> will be populated but not both.
//       <name_path> will be populated for IMPORT MODULE.
//       <file_path> will be populated for IMPORT PROTO.
//
// At most one of <alias_path> or <into_alias_path> will be populated.
//       <alias_path> may be populated for IMPORT MODULE.
//       <into_alias_path> may be populated for IMPORT PROTO.
//
// IMPORT MODULE and IMPORT PROTO both support options.
//
// See (broken link) for more detail on IMPORT MODULE.
// See (broken link) for more detail on IMPORT PROTO.
class ResolvedImportStmt final : public ResolvedStatement {
 public:
  typedef ResolvedStatement SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_IMPORT_STMT;

  typedef ResolvedImportStmtEnums::ImportKind ImportKind;
  static const ImportKind MODULE = ResolvedImportStmtEnums::MODULE;
  static const ImportKind PROTO = ResolvedImportStmtEnums::PROTO;
  static const ImportKind __ImportKind__switch_must_have_a_default__ = ResolvedImportStmtEnums::__ImportKind__switch_must_have_a_default__;

  std::string GetImportKindString() const;
  static std::string ImportKindToString(ImportKind kind);

  friend std::unique_ptr<ResolvedImportStmt> MakeResolvedImportStmt();
 protected:
  ResolvedImportStmt()
      : ResolvedStatement()
      , import_kind_()
      , name_path_()
      , file_path_()
      , alias_path_()
      , into_alias_path_()
      , option_list_()
  {}
 public:

  ResolvedImportStmt(const ResolvedImportStmt&) = delete;
  ResolvedImportStmt& operator=(const ResolvedImportStmt&) = delete;

  friend std::unique_ptr<ResolvedImportStmt> MakeResolvedImportStmt(
      ImportKind import_kind,
      const std::vector<std::string>& name_path,
      const std::string& file_path,
      const std::vector<std::string>& alias_path,
      const std::vector<std::string>& into_alias_path,
      std::vector<std::unique_ptr<const ResolvedOption>> option_list
  );
  ~ResolvedImportStmt() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_IMPORT_STMT; }
  std::string node_kind_string() const final { return "ImportStmt"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedImportStmtProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedStatementProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedImportStmt>> RestoreFrom(
      const ResolvedImportStmtProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  ImportKind import_kind() const {
    accessed_ |= (1<<0);
    return import_kind_;
  }
  void set_import_kind(ImportKind v) {
    import_kind_ = v;
  }

  const std::vector<std::string>& name_path() const {
    accessed_ |= (1<<1);
    return name_path_;
  }
  int name_path_size() const {
    if (name_path_.empty()) accessed_ |= (1<<1);
    return static_cast<int>(name_path_.size());
  }
  std::string name_path(int i) const {
    accessed_ |= (1<<1);
    return name_path_.at(i);
  }
  void add_name_path(std::string v) {
    name_path_.push_back(std::string(v));
  }
  void set_name_path(const std::vector<std::string>& v) {
    name_path_ = v;
  }
  std::vector<std::string>* mutable_name_path() {
    accessed_ |= (1<<1);
    return &name_path_;
  }

  const std::string& file_path() const {
    accessed_ |= (1<<2);
    return file_path_;
  }
  void set_file_path(const std::string& v) {
    file_path_ = v;
  }

  const std::vector<std::string>& alias_path() const {
    accessed_ |= (1<<3);
    return alias_path_;
  }
  int alias_path_size() const {
    if (alias_path_.empty()) accessed_ |= (1<<3);
    return static_cast<int>(alias_path_.size());
  }
  std::string alias_path(int i) const {
    accessed_ |= (1<<3);
    return alias_path_.at(i);
  }
  void add_alias_path(std::string v) {
    alias_path_.push_back(std::string(v));
  }
  void set_alias_path(const std::vector<std::string>& v) {
    alias_path_ = v;
  }
  std::vector<std::string>* mutable_alias_path() {
    accessed_ |= (1<<3);
    return &alias_path_;
  }

  const std::vector<std::string>& into_alias_path() const {
    accessed_ |= (1<<4);
    return into_alias_path_;
  }
  int into_alias_path_size() const {
    if (into_alias_path_.empty()) accessed_ |= (1<<4);
    return static_cast<int>(into_alias_path_.size());
  }
  std::string into_alias_path(int i) const {
    accessed_ |= (1<<4);
    return into_alias_path_.at(i);
  }
  void add_into_alias_path(std::string v) {
    into_alias_path_.push_back(std::string(v));
  }
  void set_into_alias_path(const std::vector<std::string>& v) {
    into_alias_path_ = v;
  }
  std::vector<std::string>* mutable_into_alias_path() {
    accessed_ |= (1<<4);
    return &into_alias_path_;
  }

  const std::vector<std::unique_ptr<const ResolvedOption>>& option_list() const {
    accessed_ |= (1<<5);
    return option_list_;
  }
  int option_list_size() const {
    if (option_list_.empty()) accessed_ |= (1<<5);
    return static_cast<int>(option_list_.size());
  }
  const ResolvedOption* option_list(int i) const {
    accessed_ |= (1<<5);
    return option_list_.at(i).get();
  }
  void add_option_list(std::unique_ptr<const ResolvedOption> v) {
    option_list_.emplace_back(std::move(v));
  }
  void set_option_list(std::vector<std::unique_ptr<const ResolvedOption>> v) {
    option_list_ = std::move(v);
  }

  std::vector<std::unique_ptr<const ResolvedOption>> release_option_list() {
    std::vector<std::unique_ptr<const ResolvedOption>> tmp;
    option_list_.swap(tmp);
    return tmp;
  }

 protected:
  explicit ResolvedImportStmt(
      ImportKind import_kind,
      const std::vector<std::string>& name_path,
      const std::string& file_path,
      const std::vector<std::string>& alias_path,
      const std::vector<std::string>& into_alias_path,
      std::vector<std::unique_ptr<const ResolvedOption>> option_list,
      ConstructorOverload)
      : ResolvedStatement(
            ConstructorOverload::NEW_CONSTRUCTOR),
      import_kind_(import_kind),
      name_path_(name_path),
      file_path_(file_path),
      alias_path_(alias_path),
      into_alias_path_(into_alias_path),
      option_list_(std::move(option_list)) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  ImportKind import_kind_;
  std::vector<std::string> name_path_;
  std::string file_path_;
  std::vector<std::string> alias_path_;
  std::vector<std::string> into_alias_path_;
  std::vector<std::unique_ptr<const ResolvedOption>> option_list_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedImportStmt> MakeResolvedImportStmt(
    ResolvedImportStmt::ImportKind import_kind,
    const std::vector<std::string>& name_path,
    const std::string& file_path,
    const std::vector<std::string>& alias_path,
    const std::vector<std::string>& into_alias_path,
    std::vector<std::unique_ptr<const ResolvedOption>> option_list) {
  return std::unique_ptr<ResolvedImportStmt>(new ResolvedImportStmt(
        import_kind,
        name_path,
        file_path,
        alias_path,
        into_alias_path,
        std::move(option_list),
        ResolvedImportStmt::NEW_CONSTRUCTOR));
}

// Overloaded factory method for the construction of ResolvedImportStmt with
// a wider range of inputs for node-vector inputs.  In particular allows:
// 1. unique_ptr element type can be non-const.
// 2. unique_ptr element type can be any descendant of the required type.
// 3. input container can be any object with a `begin()` and `end()`.
//
// Note, initializer lists cannot be used to pass
//  option_list
// due to incompatibility with unique_ptr.  Use zetasql::MakeNodeVector
// instead.
template <
  typename option_list_t
      = std::vector<std::unique_ptr<const ResolvedOption>>>
std::unique_ptr<ResolvedImportStmt> MakeResolvedImportStmt(
    ResolvedImportStmt::ImportKind import_kind,
    const std::vector<std::string>& name_path,
    const std::string& file_path,
    const std::vector<std::string>& alias_path,
    const std::vector<std::string>& into_alias_path,
    option_list_t option_list) {
  static_assert(std::is_base_of<
      ResolvedOption,
      typename std::decay<decltype(**(option_list.begin()))>::type>::value,
      "option_list must be a container of unique_ptr with elements of type "
      "ResolvedOption (or its descendants).");
  return MakeResolvedImportStmt(
      import_kind,
      name_path,
      file_path,
      alias_path,
      into_alias_path,
      {std::make_move_iterator(option_list.begin()),
       std::make_move_iterator(option_list.end())});
}

inline std::unique_ptr<ResolvedImportStmt> MakeResolvedImportStmt() {
  return std::unique_ptr<ResolvedImportStmt>(
      new ResolvedImportStmt());
}

// This statement: MODULE <name_path> [<option_list>];
//
// <name_path> is the identifier path of the module.
// <option_list> Engine-specific directives for the module statement.
//
// See (broken link) for more detail on MODULEs.
class ResolvedModuleStmt final : public ResolvedStatement {
 public:
  typedef ResolvedStatement SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_MODULE_STMT;

  friend std::unique_ptr<ResolvedModuleStmt> MakeResolvedModuleStmt();
 protected:
  ResolvedModuleStmt()
      : ResolvedStatement()
      , name_path_()
      , option_list_()
  {}
 public:

  ResolvedModuleStmt(const ResolvedModuleStmt&) = delete;
  ResolvedModuleStmt& operator=(const ResolvedModuleStmt&) = delete;

  friend std::unique_ptr<ResolvedModuleStmt> MakeResolvedModuleStmt(
      const std::vector<std::string>& name_path,
      std::vector<std::unique_ptr<const ResolvedOption>> option_list
  );
  ~ResolvedModuleStmt() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_MODULE_STMT; }
  std::string node_kind_string() const final { return "ModuleStmt"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedModuleStmtProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedStatementProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedModuleStmt>> RestoreFrom(
      const ResolvedModuleStmtProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  const std::vector<std::string>& name_path() const {
    accessed_ |= (1<<0);
    return name_path_;
  }
  int name_path_size() const {
    if (name_path_.empty()) accessed_ |= (1<<0);
    return static_cast<int>(name_path_.size());
  }
  std::string name_path(int i) const {
    accessed_ |= (1<<0);
    return name_path_.at(i);
  }
  void add_name_path(std::string v) {
    name_path_.push_back(std::string(v));
  }
  void set_name_path(const std::vector<std::string>& v) {
    name_path_ = v;
  }
  std::vector<std::string>* mutable_name_path() {
    accessed_ |= (1<<0);
    return &name_path_;
  }

  const std::vector<std::unique_ptr<const ResolvedOption>>& option_list() const {
    accessed_ |= (1<<1);
    return option_list_;
  }
  int option_list_size() const {
    if (option_list_.empty()) accessed_ |= (1<<1);
    return static_cast<int>(option_list_.size());
  }
  const ResolvedOption* option_list(int i) const {
    accessed_ |= (1<<1);
    return option_list_.at(i).get();
  }
  void add_option_list(std::unique_ptr<const ResolvedOption> v) {
    option_list_.emplace_back(std::move(v));
  }
  void set_option_list(std::vector<std::unique_ptr<const ResolvedOption>> v) {
    option_list_ = std::move(v);
  }

  std::vector<std::unique_ptr<const ResolvedOption>> release_option_list() {
    std::vector<std::unique_ptr<const ResolvedOption>> tmp;
    option_list_.swap(tmp);
    return tmp;
  }

 protected:
  explicit ResolvedModuleStmt(
      const std::vector<std::string>& name_path,
      std::vector<std::unique_ptr<const ResolvedOption>> option_list,
      ConstructorOverload)
      : ResolvedStatement(
            ConstructorOverload::NEW_CONSTRUCTOR),
      name_path_(name_path),
      option_list_(std::move(option_list)) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  std::vector<std::string> name_path_;
  std::vector<std::unique_ptr<const ResolvedOption>> option_list_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedModuleStmt> MakeResolvedModuleStmt(
    const std::vector<std::string>& name_path,
    std::vector<std::unique_ptr<const ResolvedOption>> option_list) {
  return std::unique_ptr<ResolvedModuleStmt>(new ResolvedModuleStmt(
        name_path,
        std::move(option_list),
        ResolvedModuleStmt::NEW_CONSTRUCTOR));
}

// Overloaded factory method for the construction of ResolvedModuleStmt with
// a wider range of inputs for node-vector inputs.  In particular allows:
// 1. unique_ptr element type can be non-const.
// 2. unique_ptr element type can be any descendant of the required type.
// 3. input container can be any object with a `begin()` and `end()`.
//
// Note, initializer lists cannot be used to pass
//  option_list
// due to incompatibility with unique_ptr.  Use zetasql::MakeNodeVector
// instead.
template <
  typename option_list_t
      = std::vector<std::unique_ptr<const ResolvedOption>>>
std::unique_ptr<ResolvedModuleStmt> MakeResolvedModuleStmt(
    const std::vector<std::string>& name_path,
    option_list_t option_list) {
  static_assert(std::is_base_of<
      ResolvedOption,
      typename std::decay<decltype(**(option_list.begin()))>::type>::value,
      "option_list must be a container of unique_ptr with elements of type "
      "ResolvedOption (or its descendants).");
  return MakeResolvedModuleStmt(
      name_path,
      {std::make_move_iterator(option_list.begin()),
       std::make_move_iterator(option_list.end())});
}

inline std::unique_ptr<ResolvedModuleStmt> MakeResolvedModuleStmt() {
  return std::unique_ptr<ResolvedModuleStmt>(
      new ResolvedModuleStmt());
}

// This represents a HAVING MAX or HAVING MIN modifier in an aggregate
// expression. If an aggregate has arguments (x HAVING {MAX/MIN} y),
// the aggregate will be computed over only the x values in the rows with the
// maximal/minimal values of y.
//
// <kind> the MAX/MIN kind of this HAVING
// <having_expr> the HAVING expression (y in the above example)
class ResolvedAggregateHavingModifier final : public ResolvedArgument {
 public:
  typedef ResolvedArgument SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_AGGREGATE_HAVING_MODIFIER;

  typedef ResolvedAggregateHavingModifierEnums::HavingModifierKind HavingModifierKind;
  static const HavingModifierKind INVALID = ResolvedAggregateHavingModifierEnums::INVALID;
  static const HavingModifierKind MAX = ResolvedAggregateHavingModifierEnums::MAX;
  static const HavingModifierKind MIN = ResolvedAggregateHavingModifierEnums::MIN;

  std::string GetHavingModifierKindString() const;
  static std::string HavingModifierKindToString(HavingModifierKind kind);

  friend std::unique_ptr<ResolvedAggregateHavingModifier> MakeResolvedAggregateHavingModifier();
 protected:
  ResolvedAggregateHavingModifier()
      : ResolvedArgument()
      , kind_()
      , having_expr_()
  {}
 public:

  ResolvedAggregateHavingModifier(const ResolvedAggregateHavingModifier&) = delete;
  ResolvedAggregateHavingModifier& operator=(const ResolvedAggregateHavingModifier&) = delete;

  friend std::unique_ptr<ResolvedAggregateHavingModifier> MakeResolvedAggregateHavingModifier(
      HavingModifierKind kind,
      std::unique_ptr<const ResolvedExpr> having_expr
  );
  ~ResolvedAggregateHavingModifier() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_AGGREGATE_HAVING_MODIFIER; }
  std::string node_kind_string() const final { return "AggregateHavingModifier"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedAggregateHavingModifierProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedArgumentProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedAggregateHavingModifier>> RestoreFrom(
      const ResolvedAggregateHavingModifierProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  HavingModifierKind kind() const {
    accessed_ |= (1<<0);
    return kind_;
  }
  void set_kind(HavingModifierKind v) {
    kind_ = v;
  }

  const ResolvedExpr* having_expr() const {
    accessed_ |= (1<<1);
    return having_expr_.get();
  }
  void set_having_expr(std::unique_ptr<const ResolvedExpr> v) {
    having_expr_ = std::move(v);
  }

  std::unique_ptr<const ResolvedExpr> release_having_expr() {
    return std::move(having_expr_);
  }

 protected:
  explicit ResolvedAggregateHavingModifier(
      HavingModifierKind kind,
      std::unique_ptr<const ResolvedExpr> having_expr,
      ConstructorOverload)
      : ResolvedArgument(
            ConstructorOverload::NEW_CONSTRUCTOR),
      kind_(kind),
      having_expr_(std::move(having_expr)) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  HavingModifierKind kind_;
  std::unique_ptr<const ResolvedExpr> having_expr_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedAggregateHavingModifier> MakeResolvedAggregateHavingModifier(
    ResolvedAggregateHavingModifier::HavingModifierKind kind,
    std::unique_ptr<const ResolvedExpr> having_expr) {
  return std::unique_ptr<ResolvedAggregateHavingModifier>(new ResolvedAggregateHavingModifier(
        kind,
        std::move(having_expr),
        ResolvedAggregateHavingModifier::NEW_CONSTRUCTOR));
}

inline std::unique_ptr<ResolvedAggregateHavingModifier> MakeResolvedAggregateHavingModifier() {
  return std::unique_ptr<ResolvedAggregateHavingModifier>(
      new ResolvedAggregateHavingModifier());
}

// This statement:
// CREATE MATERIALIZED VIEW <name> [OPTIONS (...)] AS SELECT ...
class ResolvedCreateMaterializedViewStmt final : public ResolvedCreateViewBase {
 public:
  typedef ResolvedCreateViewBase SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_CREATE_MATERIALIZED_VIEW_STMT;

  friend std::unique_ptr<ResolvedCreateMaterializedViewStmt> MakeResolvedCreateMaterializedViewStmt();
 protected:
  ResolvedCreateMaterializedViewStmt()
      : ResolvedCreateViewBase()
  {}
 public:

  ResolvedCreateMaterializedViewStmt(const ResolvedCreateMaterializedViewStmt&) = delete;
  ResolvedCreateMaterializedViewStmt& operator=(const ResolvedCreateMaterializedViewStmt&) = delete;

  friend std::unique_ptr<ResolvedCreateMaterializedViewStmt> MakeResolvedCreateMaterializedViewStmt(
      const std::vector<std::string>& name_path,
      CreateScope create_scope,
      CreateMode create_mode,
      std::vector<std::unique_ptr<const ResolvedOption>> option_list,
      std::vector<std::unique_ptr<const ResolvedOutputColumn>> output_column_list,
      std::unique_ptr<const ResolvedScan> query,
      const std::string& sql,
      SqlSecurity sql_security,
      bool is_value_table
  );
  ~ResolvedCreateMaterializedViewStmt() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_CREATE_MATERIALIZED_VIEW_STMT; }
  std::string node_kind_string() const final { return "CreateMaterializedViewStmt"; }

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedCreateMaterializedViewStmtProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedCreateViewBaseProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedCreateMaterializedViewStmt>> RestoreFrom(
      const ResolvedCreateMaterializedViewStmtProto& proto,
      const ResolvedNode::RestoreParams& params);

  // Member fields

 protected:
  explicit ResolvedCreateMaterializedViewStmt(
      const std::vector<std::string>& name_path,
      CreateScope create_scope,
      CreateMode create_mode,
      std::vector<std::unique_ptr<const ResolvedOption>> option_list,
      std::vector<std::unique_ptr<const ResolvedOutputColumn>> output_column_list,
      std::unique_ptr<const ResolvedScan> query,
      const std::string& sql,
      SqlSecurity sql_security,
      bool is_value_table,
      ConstructorOverload)
      : ResolvedCreateViewBase(
            name_path,
            create_scope,
            create_mode,
            std::move(option_list),
            std::move(output_column_list),
            std::move(query),
            sql,
            sql_security,
            is_value_table,
            ConstructorOverload::NEW_CONSTRUCTOR) {
  }

 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

};

inline std::unique_ptr<ResolvedCreateMaterializedViewStmt> MakeResolvedCreateMaterializedViewStmt(
    const std::vector<std::string>& name_path,
    ResolvedCreateStatement::CreateScope create_scope,
    ResolvedCreateStatement::CreateMode create_mode,
    std::vector<std::unique_ptr<const ResolvedOption>> option_list,
    std::vector<std::unique_ptr<const ResolvedOutputColumn>> output_column_list,
    std::unique_ptr<const ResolvedScan> query,
    const std::string& sql,
    ResolvedCreateStatement::SqlSecurity sql_security,
    bool is_value_table) {
  return std::unique_ptr<ResolvedCreateMaterializedViewStmt>(new ResolvedCreateMaterializedViewStmt(
        name_path,
        create_scope,
        create_mode,
        std::move(option_list),
        std::move(output_column_list),
        std::move(query),
        sql,
        sql_security,
        is_value_table,
        ResolvedCreateMaterializedViewStmt::NEW_CONSTRUCTOR));
}

// Overloaded factory method for the construction of ResolvedCreateMaterializedViewStmt with
// a wider range of inputs for node-vector inputs.  In particular allows:
// 1. unique_ptr element type can be non-const.
// 2. unique_ptr element type can be any descendant of the required type.
// 3. input container can be any object with a `begin()` and `end()`.
//
// Note, initializer lists cannot be used to pass
//  option_list, output_column_list
// due to incompatibility with unique_ptr.  Use zetasql::MakeNodeVector
// instead.
template <
  typename option_list_t
      = std::vector<std::unique_ptr<const ResolvedOption>>,
  typename output_column_list_t
      = std::vector<std::unique_ptr<const ResolvedOutputColumn>>>
std::unique_ptr<ResolvedCreateMaterializedViewStmt> MakeResolvedCreateMaterializedViewStmt(
    const std::vector<std::string>& name_path,
    ResolvedCreateStatement::CreateScope create_scope,
    ResolvedCreateStatement::CreateMode create_mode,
    option_list_t option_list,
    output_column_list_t output_column_list,
    std::unique_ptr<const ResolvedScan> query,
    const std::string& sql,
    ResolvedCreateStatement::SqlSecurity sql_security,
    bool is_value_table) {
  static_assert(std::is_base_of<
      ResolvedOption,
      typename std::decay<decltype(**(option_list.begin()))>::type>::value,
      "option_list must be a container of unique_ptr with elements of type "
      "ResolvedOption (or its descendants).");
  static_assert(std::is_base_of<
      ResolvedOutputColumn,
      typename std::decay<decltype(**(output_column_list.begin()))>::type>::value,
      "output_column_list must be a container of unique_ptr with elements of type "
      "ResolvedOutputColumn (or its descendants).");
  return MakeResolvedCreateMaterializedViewStmt(
      name_path,
      create_scope,
      create_mode,
      {std::make_move_iterator(option_list.begin()),
       std::make_move_iterator(option_list.end())},
      {std::make_move_iterator(output_column_list.begin()),
       std::make_move_iterator(output_column_list.end())},
      std::move(query),
      sql,
      sql_security,
      is_value_table);
}

inline std::unique_ptr<ResolvedCreateMaterializedViewStmt> MakeResolvedCreateMaterializedViewStmt() {
  return std::unique_ptr<ResolvedCreateMaterializedViewStmt>(
      new ResolvedCreateMaterializedViewStmt());
}

// This statement creates a user-defined procedure:
// CREATE [OR REPLACE] [TEMP] PROCEDURE [IF NOT EXISTS] <name_path>
// (<arg_list>) [OPTIONS (<option_list>)]
// BEGIN
// <procedure_body>
// END;
//
// <name_path> is the identifier path of the procedure.
// <argument_name_list> The names of the function arguments.
// <signature> is the FunctionSignature of the created procedure, with all
//        options.  This can be used to create a procedure to load into a
//        Catalog for future queries.
// <option_list> has engine-specific directives for modifying procedures.
// <procedure_body> is a string literal that contains the procedure body.
//        It includes everything between BEGIN and END. Procedure body is
//        a list of SQL statement which was parsed to be syntactically
//        correct when CREATE PROCEDURE is parsed, but will only be
//        analyzed when procedure is called later.
class ResolvedCreateProcedureStmt final : public ResolvedCreateStatement {
 public:
  typedef ResolvedCreateStatement SUPER;

  static const ResolvedNodeKind TYPE = RESOLVED_CREATE_PROCEDURE_STMT;

  friend std::unique_ptr<ResolvedCreateProcedureStmt> MakeResolvedCreateProcedureStmt(
      const std::vector<std::string>& name_path,
      CreateScope create_scope,
      CreateMode create_mode,
      const std::vector<std::string>& argument_name_list,
      const FunctionSignature& signature,
      std::vector<std::unique_ptr<const ResolvedOption>> option_list,
      const std::string& procedure_body
  );
  ~ResolvedCreateProcedureStmt() final;

  zetasql_base::Status Accept(ResolvedASTVisitor* visitor) const final;
  zetasql_base::Status ChildrenAccept(ResolvedASTVisitor* visitor) const final;

  ResolvedNodeKind node_kind() const final { return RESOLVED_CREATE_PROCEDURE_STMT; }
  std::string node_kind_string() const final { return "CreateProcedureStmt"; }

  zetasql_base::Status CheckFieldsAccessed() const final;
  void ClearFieldsAccessed() const final;

  template <typename SUBTYPE>
  const SUBTYPE* GetAs() const {
    return static_cast<const SUBTYPE*>(this);
  }

  using SUPER::SaveTo;
  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      ResolvedCreateProcedureStmtProto* proto) const;

  zetasql_base::Status SaveTo(Type::FileDescriptorSetMap* file_descriptor_set_map,
                      AnyResolvedCreateStatementProto* proto) const final;

  static zetasql_base::StatusOr<std::unique_ptr<ResolvedCreateProcedureStmt>> RestoreFrom(
      const ResolvedCreateProcedureStmtProto& proto,
      const ResolvedNode::RestoreParams& params);

  void GetChildNodes(
      std::vector<const ResolvedNode*>* child_nodes)
          const final;

  void AddMutableChildNodePointers(
      std::vector<std::unique_ptr<const ResolvedNode>*>*
          mutable_child_node_ptrs) final;

  // Member fields

  const std::vector<std::string>& argument_name_list() const {
    accessed_ |= (1<<0);
    return argument_name_list_;
  }
  int argument_name_list_size() const {
    if (argument_name_list_.empty()) accessed_ |= (1<<0);
    return static_cast<int>(argument_name_list_.size());
  }
  std::string argument_name_list(int i) const {
    accessed_ |= (1<<0);
    return argument_name_list_.at(i);
  }
  void add_argument_name_list(std::string v) {
    argument_name_list_.push_back(std::string(v));
  }
  void set_argument_name_list(const std::vector<std::string>& v) {
    argument_name_list_ = v;
  }
  std::vector<std::string>* mutable_argument_name_list() {
    accessed_ |= (1<<0);
    return &argument_name_list_;
  }

  const FunctionSignature& signature() const {
    accessed_ |= (1<<1);
    return signature_;
  }
  void set_signature(const FunctionSignature& v) {
    signature_ = v;
  }

  const std::vector<std::unique_ptr<const ResolvedOption>>& option_list() const {
    accessed_ |= (1<<2);
    return option_list_;
  }
  int option_list_size() const {
    if (option_list_.empty()) accessed_ |= (1<<2);
    return static_cast<int>(option_list_.size());
  }
  const ResolvedOption* option_list(int i) const {
    accessed_ |= (1<<2);
    return option_list_.at(i).get();
  }
  void add_option_list(std::unique_ptr<const ResolvedOption> v) {
    option_list_.emplace_back(std::move(v));
  }
  void set_option_list(std::vector<std::unique_ptr<const ResolvedOption>> v) {
    option_list_ = std::move(v);
  }

  std::vector<std::unique_ptr<const ResolvedOption>> release_option_list() {
    std::vector<std::unique_ptr<const ResolvedOption>> tmp;
    option_list_.swap(tmp);
    return tmp;
  }

  const std::string& procedure_body() const {
    accessed_ |= (1<<3);
    return procedure_body_;
  }
  void set_procedure_body(const std::string& v) {
    procedure_body_ = v;
  }

 protected:
  explicit ResolvedCreateProcedureStmt(
      const std::vector<std::string>& name_path,
      CreateScope create_scope,
      CreateMode create_mode,
      const std::vector<std::string>& argument_name_list,
      const FunctionSignature& signature,
      std::vector<std::unique_ptr<const ResolvedOption>> option_list,
      const std::string& procedure_body,
      ConstructorOverload)
      : ResolvedCreateStatement(
            name_path,
            create_scope,
            create_mode,
            ConstructorOverload::NEW_CONSTRUCTOR),
      argument_name_list_(argument_name_list),
      signature_(signature),
      option_list_(std::move(option_list)),
      procedure_body_(procedure_body) {
  }

  void CollectDebugStringFields(
      std::vector<DebugStringField>* fields) const final;
 private:
  // Define this locally so our free function factories (friends) can access it.
  constexpr static ConstructorOverload NEW_CONSTRUCTOR =
      ResolvedNode::ConstructorOverload::NEW_CONSTRUCTOR;

  std::vector<std::string> argument_name_list_;
  FunctionSignature signature_;
  std::vector<std::unique_ptr<const ResolvedOption>> option_list_;
  std::string procedure_body_;
  mutable std::atomic<uint32_t> accessed_ = {0};
};

inline std::unique_ptr<ResolvedCreateProcedureStmt> MakeResolvedCreateProcedureStmt(
    const std::vector<std::string>& name_path,
    ResolvedCreateStatement::CreateScope create_scope,
    ResolvedCreateStatement::CreateMode create_mode,
    const std::vector<std::string>& argument_name_list,
    const FunctionSignature& signature,
    std::vector<std::unique_ptr<const ResolvedOption>> option_list,
    const std::string& procedure_body) {
  return std::unique_ptr<ResolvedCreateProcedureStmt>(new ResolvedCreateProcedureStmt(
        name_path,
        create_scope,
        create_mode,
        argument_name_list,
        signature,
        std::move(option_list),
        procedure_body,
        ResolvedCreateProcedureStmt::NEW_CONSTRUCTOR));
}

// Overloaded factory method for the construction of ResolvedCreateProcedureStmt with
// a wider range of inputs for node-vector inputs.  In particular allows:
// 1. unique_ptr element type can be non-const.
// 2. unique_ptr element type can be any descendant of the required type.
// 3. input container can be any object with a `begin()` and `end()`.
//
// Note, initializer lists cannot be used to pass
//  option_list
// due to incompatibility with unique_ptr.  Use zetasql::MakeNodeVector
// instead.
template <
  typename option_list_t
      = std::vector<std::unique_ptr<const ResolvedOption>>>
std::unique_ptr<ResolvedCreateProcedureStmt> MakeResolvedCreateProcedureStmt(
    const std::vector<std::string>& name_path,
    ResolvedCreateStatement::CreateScope create_scope,
    ResolvedCreateStatement::CreateMode create_mode,
    const std::vector<std::string>& argument_name_list,
    const FunctionSignature& signature,
    option_list_t option_list,
    const std::string& procedure_body) {
  static_assert(std::is_base_of<
      ResolvedOption,
      typename std::decay<decltype(**(option_list.begin()))>::type>::value,
      "option_list must be a container of unique_ptr with elements of type "
      "ResolvedOption (or its descendants).");
  return MakeResolvedCreateProcedureStmt(
      name_path,
      create_scope,
      create_mode,
      argument_name_list,
      signature,
      {std::make_move_iterator(option_list.begin()),
       std::make_move_iterator(option_list.end())},
      procedure_body);
}

inline std::unique_ptr<ResolvedLiteral> MakeResolvedLiteral(
    const Value& value) {
  // The float_literal_id is 0 for any ResolvedLiterals whose original images
  // are not stored in the resolver's float literal cache.
  return MakeResolvedLiteral(value.type(), value, false /* has_explicit_type */,
                             0 /* float_literal_id */);
}

inline std::unique_ptr<ResolvedLiteral> MakeResolvedLiteral(
    const Type* type, const Value& value) {
  // The float_literal_id is 0 for any ResolvedLiterals whose original images
  // are not stored in the resolver's float literal cache.
  return MakeResolvedLiteral(type, value, false /* has_explicit_type */,
                             0 /* literal_id */);
}

inline std::unique_ptr<ResolvedLiteral> MakeResolvedLiteral(
    const Type* type, const Value& value, bool has_explicit_type) {
  // The float_literal_id is 0 for any ResolvedLiterals whose original images
  // are not stored in the resolver's float literal cache.
  return MakeResolvedLiteral(type, value, has_explicit_type,
                             0 /* literal_id */);
}

inline std::unique_ptr<ResolvedParameter> MakeResolvedParameter(
    const Type* type, const std::string& name) {
  return MakeResolvedParameter(
      type, name, 0 /*position*/, false /* is_untyped */);
}

// Helper constructor to create a new ResolvedFunctionCall with an
// empty <function_call_info> field, for convenience.
inline std::unique_ptr<ResolvedFunctionCall> MakeResolvedFunctionCall(
    const Type* type,
    const Function* function,
    const FunctionSignature& signature,
    std::vector<std::unique_ptr<const ResolvedExpr>> argument_list,
    ResolvedFunctionCall::ErrorMode error_mode) {
  return MakeResolvedFunctionCall(
      type,
      function,
      signature,
      std::move(argument_list),
      error_mode,
      std::make_shared<ResolvedFunctionCallInfo>() /* function_call_info */);
}

// Helper constructor to create a new ResolvedFunctionCall with an
// empty <function_call_info> field, for convenience. Also, supports wider
// variety of inputs for `argument_list`.
template <
    typename argument_list_t = std::vector<std::unique_ptr<const ResolvedExpr>>>
inline std::unique_ptr<ResolvedFunctionCall> MakeResolvedFunctionCall(
    const Type* type, const Function* function,
    const FunctionSignature& signature, argument_list_t argument_list,
    ResolvedFunctionCallBase::ErrorMode error_mode) {
  return MakeResolvedFunctionCall(
      type, function, signature,
      {std::make_move_iterator(argument_list.begin()),
       std::make_move_iterator(argument_list.end())},
      error_mode,
      std::shared_ptr<ResolvedFunctionCallInfo>(new ResolvedFunctionCallInfo));
}

// Helper constructor to create a new ResolvedAggregateFunctionCall with an
// empty <function_call_info> field, for convenience.
inline std::unique_ptr<ResolvedAggregateFunctionCall>
MakeResolvedAggregateFunctionCall(
    const Type* type,
    const Function* function,
    const FunctionSignature& signature,
    std::vector<std::unique_ptr<const ResolvedExpr>> argument_list,
    ResolvedAggregateFunctionCall::ErrorMode error_mode,
    bool distinct,
    ResolvedAggregateFunctionCall::NullHandlingModifier null_handling_modifier,
    std::unique_ptr<const ResolvedAggregateHavingModifier> having_modifier,
    std::vector<std::unique_ptr<const ResolvedOrderByItem>> order_by_item_list,
    std::unique_ptr<const ResolvedExpr> limit) {
  return MakeResolvedAggregateFunctionCall(
      type,
      function,
      signature,
      std::move(argument_list),
      error_mode,
      distinct,
      null_handling_modifier,
      std::move(having_modifier),
      std::move(order_by_item_list),
      std::move(limit),
      std::make_shared<ResolvedFunctionCallInfo>() /* function_call_info */);
}

// Helper constructor to create a new ResolvedAggregateFunctionCall with an
// empty <function_call_info> field, for convenience.  Also, supports wider
// variety of inputs for `argument_list`.
template <
    typename argument_list_t = std::vector<std::unique_ptr<const ResolvedExpr>>,
    typename order_by_item_list_t =
        std::vector<std::unique_ptr<const ResolvedOrderByItem>>>
inline std::unique_ptr<ResolvedAggregateFunctionCall>
MakeResolvedAggregateFunctionCall(
    const Type* type, const Function* function,
    const FunctionSignature& signature, argument_list_t argument_list,
    ResolvedAggregateFunctionCall::ErrorMode error_mode, bool distinct,
    ResolvedAggregateFunctionCall::NullHandlingModifier null_handling_modifier,
    std::unique_ptr<const ResolvedAggregateHavingModifier> having_modifier,
    order_by_item_list_t order_by_item_list,
    std::unique_ptr<const ResolvedExpr> limit) {
  return MakeResolvedAggregateFunctionCall(
      type, function, signature,
      {std::make_move_iterator(argument_list.begin()),
       std::make_move_iterator(argument_list.end())},
      error_mode, distinct, null_handling_modifier, std::move(having_modifier),
      {std::make_move_iterator(order_by_item_list.begin()),
       std::make_move_iterator(order_by_item_list.end())},
      std::move(limit),
      std::make_shared<ResolvedFunctionCallInfo>() /* function_call_info */);
}

inline std::unique_ptr<ResolvedTableScan> MakeResolvedTableScan(
    const std::vector<ResolvedColumn>& column_list,
    const Table* table,
    std::unique_ptr<const ResolvedExpr> for_system_time_expr) {
  return MakeResolvedTableScan(
      column_list,
      table,
      std::move(for_system_time_expr),
      "" /* alias */);
}

// Helper that initializes the output_column_list to match
// input_scan's column_list.  This is helpful because it avoids the argument
// evaluation order problem in
// MakeResolvedSetOperationItem(std::move(scan), scan->column_list());
inline std::unique_ptr<ResolvedSetOperationItem> MakeResolvedSetOperationItem(
    std::unique_ptr<const ResolvedScan> input_scan) {
  const std::vector<ResolvedColumn>& output_column_list =
      input_scan->column_list();
  return
      MakeResolvedSetOperationItem(std::move(input_scan), output_column_list);
}

}  // namespace zetasql

#endif  // ZETASQL_RESOLVED_AST_RESOLVED_AST_H_