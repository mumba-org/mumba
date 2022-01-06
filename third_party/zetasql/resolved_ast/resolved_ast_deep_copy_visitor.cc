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

// resolved_ast_deep_copy_visitor.cc GENERATED FROM resolved_ast_deep_copy_visitor.cc.template
#include "zetasql/resolved_ast/resolved_ast_deep_copy_visitor.h"

#include <string>

#include "absl/memory/memory.h"

namespace zetasql {

// Default visit for the AST. This will throw an error, because we want to
// ensure that the entire AST is copied.
zetasql_base::Status ResolvedASTDeepCopyVisitor::DefaultVisit(
    const ResolvedNode* node) {
  return ::zetasql_base::InvalidArgumentErrorBuilder(ZETASQL_LOC)
         << "Unhandled node type in deep copy:\n"
         << node->DebugString();
}

// The individual visit methods for each of the node types. We will always
// return CopyVisitX, where X is the node kind. This will deep copy the tree
// recursively.
zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedLiteral(
    const ResolvedLiteral* node) {
  return CopyVisitResolvedLiteral(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedParameter(
    const ResolvedParameter* node) {
  return CopyVisitResolvedParameter(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedExpressionColumn(
    const ResolvedExpressionColumn* node) {
  return CopyVisitResolvedExpressionColumn(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedColumnRef(
    const ResolvedColumnRef* node) {
  return CopyVisitResolvedColumnRef(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedConstant(
    const ResolvedConstant* node) {
  return CopyVisitResolvedConstant(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedFunctionCall(
    const ResolvedFunctionCall* node) {
  return CopyVisitResolvedFunctionCall(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedAggregateFunctionCall(
    const ResolvedAggregateFunctionCall* node) {
  return CopyVisitResolvedAggregateFunctionCall(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedAnalyticFunctionCall(
    const ResolvedAnalyticFunctionCall* node) {
  return CopyVisitResolvedAnalyticFunctionCall(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedCast(
    const ResolvedCast* node) {
  return CopyVisitResolvedCast(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedMakeStruct(
    const ResolvedMakeStruct* node) {
  return CopyVisitResolvedMakeStruct(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedMakeProto(
    const ResolvedMakeProto* node) {
  return CopyVisitResolvedMakeProto(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedMakeProtoField(
    const ResolvedMakeProtoField* node) {
  return CopyVisitResolvedMakeProtoField(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedGetStructField(
    const ResolvedGetStructField* node) {
  return CopyVisitResolvedGetStructField(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedGetProtoField(
    const ResolvedGetProtoField* node) {
  return CopyVisitResolvedGetProtoField(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedSubqueryExpr(
    const ResolvedSubqueryExpr* node) {
  return CopyVisitResolvedSubqueryExpr(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedModel(
    const ResolvedModel* node) {
  return CopyVisitResolvedModel(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedSingleRowScan(
    const ResolvedSingleRowScan* node) {
  return CopyVisitResolvedSingleRowScan(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedTableScan(
    const ResolvedTableScan* node) {
  return CopyVisitResolvedTableScan(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedJoinScan(
    const ResolvedJoinScan* node) {
  return CopyVisitResolvedJoinScan(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedArrayScan(
    const ResolvedArrayScan* node) {
  return CopyVisitResolvedArrayScan(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedColumnHolder(
    const ResolvedColumnHolder* node) {
  return CopyVisitResolvedColumnHolder(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedFilterScan(
    const ResolvedFilterScan* node) {
  return CopyVisitResolvedFilterScan(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedGroupingSet(
    const ResolvedGroupingSet* node) {
  return CopyVisitResolvedGroupingSet(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedAggregateScan(
    const ResolvedAggregateScan* node) {
  return CopyVisitResolvedAggregateScan(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedSetOperationItem(
    const ResolvedSetOperationItem* node) {
  return CopyVisitResolvedSetOperationItem(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedSetOperationScan(
    const ResolvedSetOperationScan* node) {
  return CopyVisitResolvedSetOperationScan(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedOrderByScan(
    const ResolvedOrderByScan* node) {
  return CopyVisitResolvedOrderByScan(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedLimitOffsetScan(
    const ResolvedLimitOffsetScan* node) {
  return CopyVisitResolvedLimitOffsetScan(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedWithRefScan(
    const ResolvedWithRefScan* node) {
  return CopyVisitResolvedWithRefScan(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedAnalyticScan(
    const ResolvedAnalyticScan* node) {
  return CopyVisitResolvedAnalyticScan(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedSampleScan(
    const ResolvedSampleScan* node) {
  return CopyVisitResolvedSampleScan(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedComputedColumn(
    const ResolvedComputedColumn* node) {
  return CopyVisitResolvedComputedColumn(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedOrderByItem(
    const ResolvedOrderByItem* node) {
  return CopyVisitResolvedOrderByItem(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedColumnAnnotations(
    const ResolvedColumnAnnotations* node) {
  return CopyVisitResolvedColumnAnnotations(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedGeneratedColumnInfo(
    const ResolvedGeneratedColumnInfo* node) {
  return CopyVisitResolvedGeneratedColumnInfo(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedColumnDefinition(
    const ResolvedColumnDefinition* node) {
  return CopyVisitResolvedColumnDefinition(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedPrimaryKey(
    const ResolvedPrimaryKey* node) {
  return CopyVisitResolvedPrimaryKey(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedForeignKey(
    const ResolvedForeignKey* node) {
  return CopyVisitResolvedForeignKey(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedCheckConstraint(
    const ResolvedCheckConstraint* node) {
  return CopyVisitResolvedCheckConstraint(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedOutputColumn(
    const ResolvedOutputColumn* node) {
  return CopyVisitResolvedOutputColumn(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedProjectScan(
    const ResolvedProjectScan* node) {
  return CopyVisitResolvedProjectScan(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedTVFScan(
    const ResolvedTVFScan* node) {
  return CopyVisitResolvedTVFScan(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedTVFArgument(
    const ResolvedTVFArgument* node) {
  return CopyVisitResolvedTVFArgument(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedExplainStmt(
    const ResolvedExplainStmt* node) {
  return CopyVisitResolvedExplainStmt(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedQueryStmt(
    const ResolvedQueryStmt* node) {
  return CopyVisitResolvedQueryStmt(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedCreateDatabaseStmt(
    const ResolvedCreateDatabaseStmt* node) {
  return CopyVisitResolvedCreateDatabaseStmt(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedIndexItem(
    const ResolvedIndexItem* node) {
  return CopyVisitResolvedIndexItem(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedUnnestItem(
    const ResolvedUnnestItem* node) {
  return CopyVisitResolvedUnnestItem(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedCreateIndexStmt(
    const ResolvedCreateIndexStmt* node) {
  return CopyVisitResolvedCreateIndexStmt(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedCreateTableStmt(
    const ResolvedCreateTableStmt* node) {
  return CopyVisitResolvedCreateTableStmt(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedCreateTableAsSelectStmt(
    const ResolvedCreateTableAsSelectStmt* node) {
  return CopyVisitResolvedCreateTableAsSelectStmt(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedCreateModelStmt(
    const ResolvedCreateModelStmt* node) {
  return CopyVisitResolvedCreateModelStmt(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedCreateViewStmt(
    const ResolvedCreateViewStmt* node) {
  return CopyVisitResolvedCreateViewStmt(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedCreateExternalTableStmt(
    const ResolvedCreateExternalTableStmt* node) {
  return CopyVisitResolvedCreateExternalTableStmt(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedExportDataStmt(
    const ResolvedExportDataStmt* node) {
  return CopyVisitResolvedExportDataStmt(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedDefineTableStmt(
    const ResolvedDefineTableStmt* node) {
  return CopyVisitResolvedDefineTableStmt(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedDescribeStmt(
    const ResolvedDescribeStmt* node) {
  return CopyVisitResolvedDescribeStmt(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedShowStmt(
    const ResolvedShowStmt* node) {
  return CopyVisitResolvedShowStmt(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedBeginStmt(
    const ResolvedBeginStmt* node) {
  return CopyVisitResolvedBeginStmt(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedSetTransactionStmt(
    const ResolvedSetTransactionStmt* node) {
  return CopyVisitResolvedSetTransactionStmt(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedCommitStmt(
    const ResolvedCommitStmt* node) {
  return CopyVisitResolvedCommitStmt(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedRollbackStmt(
    const ResolvedRollbackStmt* node) {
  return CopyVisitResolvedRollbackStmt(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedStartBatchStmt(
    const ResolvedStartBatchStmt* node) {
  return CopyVisitResolvedStartBatchStmt(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedRunBatchStmt(
    const ResolvedRunBatchStmt* node) {
  return CopyVisitResolvedRunBatchStmt(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedAbortBatchStmt(
    const ResolvedAbortBatchStmt* node) {
  return CopyVisitResolvedAbortBatchStmt(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedDropStmt(
    const ResolvedDropStmt* node) {
  return CopyVisitResolvedDropStmt(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedDropMaterializedViewStmt(
    const ResolvedDropMaterializedViewStmt* node) {
  return CopyVisitResolvedDropMaterializedViewStmt(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedWithScan(
    const ResolvedWithScan* node) {
  return CopyVisitResolvedWithScan(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedWithEntry(
    const ResolvedWithEntry* node) {
  return CopyVisitResolvedWithEntry(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedOption(
    const ResolvedOption* node) {
  return CopyVisitResolvedOption(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedWindowPartitioning(
    const ResolvedWindowPartitioning* node) {
  return CopyVisitResolvedWindowPartitioning(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedWindowOrdering(
    const ResolvedWindowOrdering* node) {
  return CopyVisitResolvedWindowOrdering(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedWindowFrame(
    const ResolvedWindowFrame* node) {
  return CopyVisitResolvedWindowFrame(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedAnalyticFunctionGroup(
    const ResolvedAnalyticFunctionGroup* node) {
  return CopyVisitResolvedAnalyticFunctionGroup(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedWindowFrameExpr(
    const ResolvedWindowFrameExpr* node) {
  return CopyVisitResolvedWindowFrameExpr(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedDMLValue(
    const ResolvedDMLValue* node) {
  return CopyVisitResolvedDMLValue(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedDMLDefault(
    const ResolvedDMLDefault* node) {
  return CopyVisitResolvedDMLDefault(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedAssertStmt(
    const ResolvedAssertStmt* node) {
  return CopyVisitResolvedAssertStmt(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedAssertRowsModified(
    const ResolvedAssertRowsModified* node) {
  return CopyVisitResolvedAssertRowsModified(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedInsertRow(
    const ResolvedInsertRow* node) {
  return CopyVisitResolvedInsertRow(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedInsertStmt(
    const ResolvedInsertStmt* node) {
  return CopyVisitResolvedInsertStmt(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedDeleteStmt(
    const ResolvedDeleteStmt* node) {
  return CopyVisitResolvedDeleteStmt(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedUpdateItem(
    const ResolvedUpdateItem* node) {
  return CopyVisitResolvedUpdateItem(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedUpdateArrayItem(
    const ResolvedUpdateArrayItem* node) {
  return CopyVisitResolvedUpdateArrayItem(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedUpdateStmt(
    const ResolvedUpdateStmt* node) {
  return CopyVisitResolvedUpdateStmt(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedMergeWhen(
    const ResolvedMergeWhen* node) {
  return CopyVisitResolvedMergeWhen(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedMergeStmt(
    const ResolvedMergeStmt* node) {
  return CopyVisitResolvedMergeStmt(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedPrivilege(
    const ResolvedPrivilege* node) {
  return CopyVisitResolvedPrivilege(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedGrantStmt(
    const ResolvedGrantStmt* node) {
  return CopyVisitResolvedGrantStmt(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedRevokeStmt(
    const ResolvedRevokeStmt* node) {
  return CopyVisitResolvedRevokeStmt(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedAlterMaterializedViewStmt(
    const ResolvedAlterMaterializedViewStmt* node) {
  return CopyVisitResolvedAlterMaterializedViewStmt(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedAlterTableStmt(
    const ResolvedAlterTableStmt* node) {
  return CopyVisitResolvedAlterTableStmt(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedAlterViewStmt(
    const ResolvedAlterViewStmt* node) {
  return CopyVisitResolvedAlterViewStmt(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedSetOptionsAction(
    const ResolvedSetOptionsAction* node) {
  return CopyVisitResolvedSetOptionsAction(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedAlterTableSetOptionsStmt(
    const ResolvedAlterTableSetOptionsStmt* node) {
  return CopyVisitResolvedAlterTableSetOptionsStmt(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedRenameStmt(
    const ResolvedRenameStmt* node) {
  return CopyVisitResolvedRenameStmt(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedCreateRowPolicyStmt(
    const ResolvedCreateRowPolicyStmt* node) {
  return CopyVisitResolvedCreateRowPolicyStmt(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedDropRowPolicyStmt(
    const ResolvedDropRowPolicyStmt* node) {
  return CopyVisitResolvedDropRowPolicyStmt(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedAlterRowPolicyStmt(
    const ResolvedAlterRowPolicyStmt* node) {
  return CopyVisitResolvedAlterRowPolicyStmt(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedCreateConstantStmt(
    const ResolvedCreateConstantStmt* node) {
  return CopyVisitResolvedCreateConstantStmt(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedCreateFunctionStmt(
    const ResolvedCreateFunctionStmt* node) {
  return CopyVisitResolvedCreateFunctionStmt(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedArgumentDef(
    const ResolvedArgumentDef* node) {
  return CopyVisitResolvedArgumentDef(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedArgumentRef(
    const ResolvedArgumentRef* node) {
  return CopyVisitResolvedArgumentRef(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedCreateTableFunctionStmt(
    const ResolvedCreateTableFunctionStmt* node) {
  return CopyVisitResolvedCreateTableFunctionStmt(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedRelationArgumentScan(
    const ResolvedRelationArgumentScan* node) {
  return CopyVisitResolvedRelationArgumentScan(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedArgumentList(
    const ResolvedArgumentList* node) {
  return CopyVisitResolvedArgumentList(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedFunctionSignatureHolder(
    const ResolvedFunctionSignatureHolder* node) {
  return CopyVisitResolvedFunctionSignatureHolder(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedDropFunctionStmt(
    const ResolvedDropFunctionStmt* node) {
  return CopyVisitResolvedDropFunctionStmt(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedCallStmt(
    const ResolvedCallStmt* node) {
  return CopyVisitResolvedCallStmt(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedImportStmt(
    const ResolvedImportStmt* node) {
  return CopyVisitResolvedImportStmt(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedModuleStmt(
    const ResolvedModuleStmt* node) {
  return CopyVisitResolvedModuleStmt(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedAggregateHavingModifier(
    const ResolvedAggregateHavingModifier* node) {
  return CopyVisitResolvedAggregateHavingModifier(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedCreateMaterializedViewStmt(
    const ResolvedCreateMaterializedViewStmt* node) {
  return CopyVisitResolvedCreateMaterializedViewStmt(node);
}

zetasql_base::Status ResolvedASTDeepCopyVisitor::VisitResolvedCreateProcedureStmt(
    const ResolvedCreateProcedureStmt* node) {
  return CopyVisitResolvedCreateProcedureStmt(node);
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedLiteral(
    const ResolvedLiteral* node) {
  // Create a mutable instance of ResolvedLiteral.
  auto copy = MakeResolvedLiteral(
    node->type(),
    node->value(),
    node->has_explicit_type(),
    node->float_literal_id()
  );

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedParameter(
    const ResolvedParameter* node) {
  // Create a mutable instance of ResolvedParameter.
  auto copy = MakeResolvedParameter(
    node->type(),
    node->name(),
    node->position(),
    node->is_untyped()
  );

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedExpressionColumn(
    const ResolvedExpressionColumn* node) {
  // Create a mutable instance of ResolvedExpressionColumn.
  auto copy = MakeResolvedExpressionColumn(
    node->type(),
    node->name()
  );

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedColumnRef(
    const ResolvedColumnRef* node) {
  // Create a mutable instance of ResolvedColumnRef.
  auto copy = MakeResolvedColumnRef(
    node->type(),
    node->column(),
    node->is_correlated()
  );

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedConstant(
    const ResolvedConstant* node) {
  // Create a mutable instance of ResolvedConstant.
  auto copy = MakeResolvedConstant(
    node->type(),
    node->constant()
  );

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedFunctionCall(
    const ResolvedFunctionCall* node) {
  // Get a deep copy of argument_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedExpr>> argument_list,
      ProcessNodeList(node->argument_list()));

  // Create a mutable instance of ResolvedFunctionCall.
  auto copy = MakeResolvedFunctionCall(
    node->type(),
    node->function(),
    node->signature(),
    std::move(argument_list),
    node->error_mode(),
    node->function_call_info()
  );

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedAggregateFunctionCall(
    const ResolvedAggregateFunctionCall* node) {
  // Get deep copy of having_modifier field.
  ZETASQL_ASSIGN_OR_RETURN(
      std::unique_ptr<ResolvedAggregateHavingModifier> having_modifier,
      ProcessNode(node->having_modifier()));

  // Get a deep copy of order_by_item_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedOrderByItem>> order_by_item_list,
      ProcessNodeList(node->order_by_item_list()));

  // Get deep copy of limit field.
  ZETASQL_ASSIGN_OR_RETURN(
      std::unique_ptr<ResolvedExpr> limit,
      ProcessNode(node->limit()));

  // Get a deep copy of argument_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedExpr>> argument_list,
      ProcessNodeList(node->argument_list()));

  // Create a mutable instance of ResolvedAggregateFunctionCall.
  auto copy = MakeResolvedAggregateFunctionCall(
    node->type(),
    node->function(),
    node->signature(),
    std::move(argument_list),
    node->error_mode(),
    node->distinct(),
    node->null_handling_modifier(),
    std::move(having_modifier),
    std::move(order_by_item_list),
    std::move(limit),
    node->function_call_info()
  );

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedAnalyticFunctionCall(
    const ResolvedAnalyticFunctionCall* node) {
  // Get deep copy of window_frame field.
  ZETASQL_ASSIGN_OR_RETURN(
      std::unique_ptr<ResolvedWindowFrame> window_frame,
      ProcessNode(node->window_frame()));

  // Get a deep copy of argument_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedExpr>> argument_list,
      ProcessNodeList(node->argument_list()));

  // Create a mutable instance of ResolvedAnalyticFunctionCall.
  auto copy = MakeResolvedAnalyticFunctionCall(
    node->type(),
    node->function(),
    node->signature(),
    std::move(argument_list),
    node->error_mode(),
    node->distinct(),
    node->null_handling_modifier(),
    std::move(window_frame)
  );

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedCast(
    const ResolvedCast* node) {
  // Get deep copy of expr field.
  ZETASQL_ASSIGN_OR_RETURN(
      std::unique_ptr<ResolvedExpr> expr,
      ProcessNode(node->expr()));

  // Create a mutable instance of ResolvedCast.
  auto copy = MakeResolvedCast(
    node->type(),
    std::move(expr),
    node->return_null_on_error()
  );

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedMakeStruct(
    const ResolvedMakeStruct* node) {
  // Get a deep copy of field_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedExpr>> field_list,
      ProcessNodeList(node->field_list()));

  // Create a mutable instance of ResolvedMakeStruct.
  auto copy = MakeResolvedMakeStruct(
    node->type(),
    std::move(field_list)
  );

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedMakeProto(
    const ResolvedMakeProto* node) {
  // Get a deep copy of field_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedMakeProtoField>> field_list,
      ProcessNodeList(node->field_list()));

  // Create a mutable instance of ResolvedMakeProto.
  auto copy = MakeResolvedMakeProto(
    node->type(),
    std::move(field_list)
  );

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedMakeProtoField(
    const ResolvedMakeProtoField* node) {
  // Get deep copy of expr field.
  ZETASQL_ASSIGN_OR_RETURN(
      std::unique_ptr<ResolvedExpr> expr,
      ProcessNode(node->expr()));

  // Create a mutable instance of ResolvedMakeProtoField.
  auto copy = MakeResolvedMakeProtoField(
    node->field_descriptor(),
    node->format(),
    std::move(expr)
  );

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedGetStructField(
    const ResolvedGetStructField* node) {
  // Get deep copy of expr field.
  ZETASQL_ASSIGN_OR_RETURN(
      std::unique_ptr<ResolvedExpr> expr,
      ProcessNode(node->expr()));

  // Create a mutable instance of ResolvedGetStructField.
  auto copy = MakeResolvedGetStructField(
    node->type(),
    std::move(expr),
    node->field_idx()
  );

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedGetProtoField(
    const ResolvedGetProtoField* node) {
  // Get deep copy of expr field.
  ZETASQL_ASSIGN_OR_RETURN(
      std::unique_ptr<ResolvedExpr> expr,
      ProcessNode(node->expr()));

  // Create a mutable instance of ResolvedGetProtoField.
  auto copy = MakeResolvedGetProtoField(
    node->type(),
    std::move(expr),
    node->field_descriptor(),
    node->default_value(),
    node->get_has_bit(),
    node->format(),
    node->return_default_value_when_unset()
  );

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedSubqueryExpr(
    const ResolvedSubqueryExpr* node) {
  // Get a deep copy of parameter_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedColumnRef>> parameter_list,
      ProcessNodeList(node->parameter_list()));

  // Get deep copy of in_expr field.
  ZETASQL_ASSIGN_OR_RETURN(
      std::unique_ptr<ResolvedExpr> in_expr,
      ProcessNode(node->in_expr()));

  // Get deep copy of subquery field.
  ZETASQL_ASSIGN_OR_RETURN(
      std::unique_ptr<ResolvedScan> subquery,
      ProcessNode(node->subquery()));

  // Get a deep copy of hint_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedOption>> hint_list,
      ProcessNodeList(node->hint_list()));

  // Create a mutable instance of ResolvedSubqueryExpr.
  auto copy = MakeResolvedSubqueryExpr(
    node->type(),
    node->subquery_type(),
    std::move(parameter_list),
    std::move(in_expr),
    std::move(subquery)
  );

  // Copy the hint list explicitly because hint_list is not a constructor arg.
  // Because it is not a constructor arg, the only way to copy the value is to
  // copy it explicitly.
  ZETASQL_RETURN_IF_ERROR(CopyHintList<ResolvedSubqueryExpr>(node, copy.get()));

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedModel(
    const ResolvedModel* node) {
  // Create a mutable instance of ResolvedModel.
  auto copy = MakeResolvedModel(
    node->model()
  );

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedSingleRowScan(
    const ResolvedSingleRowScan* node) {
  // Get a deep copy of hint_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedOption>> hint_list,
      ProcessNodeList(node->hint_list()));

  // Create a mutable instance of ResolvedSingleRowScan.
  auto copy = MakeResolvedSingleRowScan(
    node->column_list()
  );

  // Copy the hint list explicitly because hint_list is not a constructor arg.
  // Because it is not a constructor arg, the only way to copy the value is to
  // copy it explicitly.
  ZETASQL_RETURN_IF_ERROR(CopyHintList<ResolvedSingleRowScan>(node, copy.get()));

  // Copy the is_ordered field explicitly because it is not a constructor arg.
  copy.get()->set_is_ordered(node->is_ordered());

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedTableScan(
    const ResolvedTableScan* node) {
  // Get deep copy of for_system_time_expr field.
  ZETASQL_ASSIGN_OR_RETURN(
      std::unique_ptr<ResolvedExpr> for_system_time_expr,
      ProcessNode(node->for_system_time_expr()));

  // Get a deep copy of hint_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedOption>> hint_list,
      ProcessNodeList(node->hint_list()));

  // Create a mutable instance of ResolvedTableScan.
  auto copy = MakeResolvedTableScan(
    node->column_list(),
    node->table(),
    std::move(for_system_time_expr),
    node->alias()
  );

  // Copy the hint list explicitly because hint_list is not a constructor arg.
  // Because it is not a constructor arg, the only way to copy the value is to
  // copy it explicitly.
  ZETASQL_RETURN_IF_ERROR(CopyHintList<ResolvedTableScan>(node, copy.get()));

  // Copy the is_ordered field explicitly because it is not a constructor arg.
  copy.get()->set_is_ordered(node->is_ordered());

  // Copy the column_index_list field explicitly because it is not a constructor
  // arg.
  copy.get()->set_column_index_list(node->column_index_list());

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedJoinScan(
    const ResolvedJoinScan* node) {
  // Get deep copy of left_scan field.
  ZETASQL_ASSIGN_OR_RETURN(
      std::unique_ptr<ResolvedScan> left_scan,
      ProcessNode(node->left_scan()));

  // Get deep copy of right_scan field.
  ZETASQL_ASSIGN_OR_RETURN(
      std::unique_ptr<ResolvedScan> right_scan,
      ProcessNode(node->right_scan()));

  // Get deep copy of join_expr field.
  ZETASQL_ASSIGN_OR_RETURN(
      std::unique_ptr<ResolvedExpr> join_expr,
      ProcessNode(node->join_expr()));

  // Get a deep copy of hint_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedOption>> hint_list,
      ProcessNodeList(node->hint_list()));

  // Create a mutable instance of ResolvedJoinScan.
  auto copy = MakeResolvedJoinScan(
    node->column_list(),
    node->join_type(),
    std::move(left_scan),
    std::move(right_scan),
    std::move(join_expr)
  );

  // Copy the hint list explicitly because hint_list is not a constructor arg.
  // Because it is not a constructor arg, the only way to copy the value is to
  // copy it explicitly.
  ZETASQL_RETURN_IF_ERROR(CopyHintList<ResolvedJoinScan>(node, copy.get()));

  // Copy the is_ordered field explicitly because it is not a constructor arg.
  copy.get()->set_is_ordered(node->is_ordered());

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedArrayScan(
    const ResolvedArrayScan* node) {
  // Get deep copy of input_scan field.
  ZETASQL_ASSIGN_OR_RETURN(
      std::unique_ptr<ResolvedScan> input_scan,
      ProcessNode(node->input_scan()));

  // Get deep copy of array_expr field.
  ZETASQL_ASSIGN_OR_RETURN(
      std::unique_ptr<ResolvedExpr> array_expr,
      ProcessNode(node->array_expr()));

  // Get deep copy of array_offset_column field.
  ZETASQL_ASSIGN_OR_RETURN(
      std::unique_ptr<ResolvedColumnHolder> array_offset_column,
      ProcessNode(node->array_offset_column()));

  // Get deep copy of join_expr field.
  ZETASQL_ASSIGN_OR_RETURN(
      std::unique_ptr<ResolvedExpr> join_expr,
      ProcessNode(node->join_expr()));

  // Get a deep copy of hint_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedOption>> hint_list,
      ProcessNodeList(node->hint_list()));

  // Create a mutable instance of ResolvedArrayScan.
  auto copy = MakeResolvedArrayScan(
    node->column_list(),
    std::move(input_scan),
    std::move(array_expr),
    node->element_column(),
    std::move(array_offset_column),
    std::move(join_expr),
    node->is_outer()
  );

  // Copy the hint list explicitly because hint_list is not a constructor arg.
  // Because it is not a constructor arg, the only way to copy the value is to
  // copy it explicitly.
  ZETASQL_RETURN_IF_ERROR(CopyHintList<ResolvedArrayScan>(node, copy.get()));

  // Copy the is_ordered field explicitly because it is not a constructor arg.
  copy.get()->set_is_ordered(node->is_ordered());

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedColumnHolder(
    const ResolvedColumnHolder* node) {
  // Create a mutable instance of ResolvedColumnHolder.
  auto copy = MakeResolvedColumnHolder(
    node->column()
  );

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedFilterScan(
    const ResolvedFilterScan* node) {
  // Get deep copy of input_scan field.
  ZETASQL_ASSIGN_OR_RETURN(
      std::unique_ptr<ResolvedScan> input_scan,
      ProcessNode(node->input_scan()));

  // Get deep copy of filter_expr field.
  ZETASQL_ASSIGN_OR_RETURN(
      std::unique_ptr<ResolvedExpr> filter_expr,
      ProcessNode(node->filter_expr()));

  // Get a deep copy of hint_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedOption>> hint_list,
      ProcessNodeList(node->hint_list()));

  // Create a mutable instance of ResolvedFilterScan.
  auto copy = MakeResolvedFilterScan(
    node->column_list(),
    std::move(input_scan),
    std::move(filter_expr)
  );

  // Copy the hint list explicitly because hint_list is not a constructor arg.
  // Because it is not a constructor arg, the only way to copy the value is to
  // copy it explicitly.
  ZETASQL_RETURN_IF_ERROR(CopyHintList<ResolvedFilterScan>(node, copy.get()));

  // Copy the is_ordered field explicitly because it is not a constructor arg.
  copy.get()->set_is_ordered(node->is_ordered());

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedGroupingSet(
    const ResolvedGroupingSet* node) {
  // Get a deep copy of group_by_column_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedColumnRef>> group_by_column_list,
      ProcessNodeList(node->group_by_column_list()));

  // Create a mutable instance of ResolvedGroupingSet.
  auto copy = MakeResolvedGroupingSet(
    std::move(group_by_column_list)
  );

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedAggregateScan(
    const ResolvedAggregateScan* node) {
  // Get a deep copy of grouping_set_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedGroupingSet>> grouping_set_list,
      ProcessNodeList(node->grouping_set_list()));

  // Get a deep copy of rollup_column_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedColumnRef>> rollup_column_list,
      ProcessNodeList(node->rollup_column_list()));

  // Get a deep copy of hint_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedOption>> hint_list,
      ProcessNodeList(node->hint_list()));

  // Get deep copy of input_scan field.
  ZETASQL_ASSIGN_OR_RETURN(
      std::unique_ptr<ResolvedScan> input_scan,
      ProcessNode(node->input_scan()));

  // Get a deep copy of group_by_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedComputedColumn>> group_by_list,
      ProcessNodeList(node->group_by_list()));

  // Get a deep copy of aggregate_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedComputedColumn>> aggregate_list,
      ProcessNodeList(node->aggregate_list()));

  // Create a mutable instance of ResolvedAggregateScan.
  auto copy = MakeResolvedAggregateScan(
    node->column_list(),
    std::move(input_scan),
    std::move(group_by_list),
    std::move(aggregate_list),
    std::move(grouping_set_list),
    std::move(rollup_column_list)
  );

  // Copy the hint list explicitly because hint_list is not a constructor arg.
  // Because it is not a constructor arg, the only way to copy the value is to
  // copy it explicitly.
  ZETASQL_RETURN_IF_ERROR(CopyHintList<ResolvedAggregateScan>(node, copy.get()));

  // Copy the is_ordered field explicitly because it is not a constructor arg.
  copy.get()->set_is_ordered(node->is_ordered());

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedSetOperationItem(
    const ResolvedSetOperationItem* node) {
  // Get deep copy of scan field.
  ZETASQL_ASSIGN_OR_RETURN(
      std::unique_ptr<ResolvedScan> scan,
      ProcessNode(node->scan()));

  // Create a mutable instance of ResolvedSetOperationItem.
  auto copy = MakeResolvedSetOperationItem(
    std::move(scan),
    node->output_column_list()
  );

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedSetOperationScan(
    const ResolvedSetOperationScan* node) {
  // Get a deep copy of input_item_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedSetOperationItem>> input_item_list,
      ProcessNodeList(node->input_item_list()));

  // Get a deep copy of hint_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedOption>> hint_list,
      ProcessNodeList(node->hint_list()));

  // Create a mutable instance of ResolvedSetOperationScan.
  auto copy = MakeResolvedSetOperationScan(
    node->column_list(),
    node->op_type(),
    std::move(input_item_list)
  );

  // Copy the hint list explicitly because hint_list is not a constructor arg.
  // Because it is not a constructor arg, the only way to copy the value is to
  // copy it explicitly.
  ZETASQL_RETURN_IF_ERROR(CopyHintList<ResolvedSetOperationScan>(node, copy.get()));

  // Copy the is_ordered field explicitly because it is not a constructor arg.
  copy.get()->set_is_ordered(node->is_ordered());

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedOrderByScan(
    const ResolvedOrderByScan* node) {
  // Get deep copy of input_scan field.
  ZETASQL_ASSIGN_OR_RETURN(
      std::unique_ptr<ResolvedScan> input_scan,
      ProcessNode(node->input_scan()));

  // Get a deep copy of order_by_item_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedOrderByItem>> order_by_item_list,
      ProcessNodeList(node->order_by_item_list()));

  // Get a deep copy of hint_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedOption>> hint_list,
      ProcessNodeList(node->hint_list()));

  // Create a mutable instance of ResolvedOrderByScan.
  auto copy = MakeResolvedOrderByScan(
    node->column_list(),
    std::move(input_scan),
    std::move(order_by_item_list)
  );

  // Copy the hint list explicitly because hint_list is not a constructor arg.
  // Because it is not a constructor arg, the only way to copy the value is to
  // copy it explicitly.
  ZETASQL_RETURN_IF_ERROR(CopyHintList<ResolvedOrderByScan>(node, copy.get()));

  // Copy the is_ordered field explicitly because it is not a constructor arg.
  copy.get()->set_is_ordered(node->is_ordered());

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedLimitOffsetScan(
    const ResolvedLimitOffsetScan* node) {
  // Get deep copy of input_scan field.
  ZETASQL_ASSIGN_OR_RETURN(
      std::unique_ptr<ResolvedScan> input_scan,
      ProcessNode(node->input_scan()));

  // Get deep copy of limit field.
  ZETASQL_ASSIGN_OR_RETURN(
      std::unique_ptr<ResolvedExpr> limit,
      ProcessNode(node->limit()));

  // Get deep copy of offset field.
  ZETASQL_ASSIGN_OR_RETURN(
      std::unique_ptr<ResolvedExpr> offset,
      ProcessNode(node->offset()));

  // Get a deep copy of hint_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedOption>> hint_list,
      ProcessNodeList(node->hint_list()));

  // Create a mutable instance of ResolvedLimitOffsetScan.
  auto copy = MakeResolvedLimitOffsetScan(
    node->column_list(),
    std::move(input_scan),
    std::move(limit),
    std::move(offset)
  );

  // Copy the hint list explicitly because hint_list is not a constructor arg.
  // Because it is not a constructor arg, the only way to copy the value is to
  // copy it explicitly.
  ZETASQL_RETURN_IF_ERROR(CopyHintList<ResolvedLimitOffsetScan>(node, copy.get()));

  // Copy the is_ordered field explicitly because it is not a constructor arg.
  copy.get()->set_is_ordered(node->is_ordered());

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedWithRefScan(
    const ResolvedWithRefScan* node) {
  // Get a deep copy of hint_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedOption>> hint_list,
      ProcessNodeList(node->hint_list()));

  // Create a mutable instance of ResolvedWithRefScan.
  auto copy = MakeResolvedWithRefScan(
    node->column_list(),
    node->with_query_name()
  );

  // Copy the hint list explicitly because hint_list is not a constructor arg.
  // Because it is not a constructor arg, the only way to copy the value is to
  // copy it explicitly.
  ZETASQL_RETURN_IF_ERROR(CopyHintList<ResolvedWithRefScan>(node, copy.get()));

  // Copy the is_ordered field explicitly because it is not a constructor arg.
  copy.get()->set_is_ordered(node->is_ordered());

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedAnalyticScan(
    const ResolvedAnalyticScan* node) {
  // Get deep copy of input_scan field.
  ZETASQL_ASSIGN_OR_RETURN(
      std::unique_ptr<ResolvedScan> input_scan,
      ProcessNode(node->input_scan()));

  // Get a deep copy of function_group_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedAnalyticFunctionGroup>> function_group_list,
      ProcessNodeList(node->function_group_list()));

  // Get a deep copy of hint_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedOption>> hint_list,
      ProcessNodeList(node->hint_list()));

  // Create a mutable instance of ResolvedAnalyticScan.
  auto copy = MakeResolvedAnalyticScan(
    node->column_list(),
    std::move(input_scan),
    std::move(function_group_list)
  );

  // Copy the hint list explicitly because hint_list is not a constructor arg.
  // Because it is not a constructor arg, the only way to copy the value is to
  // copy it explicitly.
  ZETASQL_RETURN_IF_ERROR(CopyHintList<ResolvedAnalyticScan>(node, copy.get()));

  // Copy the is_ordered field explicitly because it is not a constructor arg.
  copy.get()->set_is_ordered(node->is_ordered());

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedSampleScan(
    const ResolvedSampleScan* node) {
  // Get deep copy of input_scan field.
  ZETASQL_ASSIGN_OR_RETURN(
      std::unique_ptr<ResolvedScan> input_scan,
      ProcessNode(node->input_scan()));

  // Get deep copy of size field.
  ZETASQL_ASSIGN_OR_RETURN(
      std::unique_ptr<ResolvedExpr> size,
      ProcessNode(node->size()));

  // Get deep copy of repeatable_argument field.
  ZETASQL_ASSIGN_OR_RETURN(
      std::unique_ptr<ResolvedExpr> repeatable_argument,
      ProcessNode(node->repeatable_argument()));

  // Get deep copy of weight_column field.
  ZETASQL_ASSIGN_OR_RETURN(
      std::unique_ptr<ResolvedColumnHolder> weight_column,
      ProcessNode(node->weight_column()));

  // Get a deep copy of partition_by_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedExpr>> partition_by_list,
      ProcessNodeList(node->partition_by_list()));

  // Get a deep copy of hint_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedOption>> hint_list,
      ProcessNodeList(node->hint_list()));

  // Create a mutable instance of ResolvedSampleScan.
  auto copy = MakeResolvedSampleScan(
    node->column_list(),
    std::move(input_scan),
    node->method(),
    std::move(size),
    node->unit(),
    std::move(repeatable_argument),
    std::move(weight_column),
    std::move(partition_by_list)
  );

  // Copy the hint list explicitly because hint_list is not a constructor arg.
  // Because it is not a constructor arg, the only way to copy the value is to
  // copy it explicitly.
  ZETASQL_RETURN_IF_ERROR(CopyHintList<ResolvedSampleScan>(node, copy.get()));

  // Copy the is_ordered field explicitly because it is not a constructor arg.
  copy.get()->set_is_ordered(node->is_ordered());

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedComputedColumn(
    const ResolvedComputedColumn* node) {
  // Get deep copy of expr field.
  ZETASQL_ASSIGN_OR_RETURN(
      std::unique_ptr<ResolvedExpr> expr,
      ProcessNode(node->expr()));

  // Create a mutable instance of ResolvedComputedColumn.
  auto copy = MakeResolvedComputedColumn(
    node->column(),
    std::move(expr)
  );

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedOrderByItem(
    const ResolvedOrderByItem* node) {
  // Get deep copy of column_ref field.
  ZETASQL_ASSIGN_OR_RETURN(
      std::unique_ptr<ResolvedColumnRef> column_ref,
      ProcessNode(node->column_ref()));

  // Get deep copy of collation_name field.
  ZETASQL_ASSIGN_OR_RETURN(
      std::unique_ptr<ResolvedExpr> collation_name,
      ProcessNode(node->collation_name()));

  // Create a mutable instance of ResolvedOrderByItem.
  auto copy = MakeResolvedOrderByItem(
    std::move(column_ref),
    std::move(collation_name),
    node->is_descending()
  );

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedColumnAnnotations(
    const ResolvedColumnAnnotations* node) {
  // Get a deep copy of option_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedOption>> option_list,
      ProcessNodeList(node->option_list()));

  // Get a deep copy of child_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedColumnAnnotations>> child_list,
      ProcessNodeList(node->child_list()));

  // Create a mutable instance of ResolvedColumnAnnotations.
  auto copy = MakeResolvedColumnAnnotations(
    node->not_null(),
    std::move(option_list),
    std::move(child_list)
  );

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedGeneratedColumnInfo(
    const ResolvedGeneratedColumnInfo* node) {
  // Get deep copy of expression field.
  ZETASQL_ASSIGN_OR_RETURN(
      std::unique_ptr<ResolvedExpr> expression,
      ProcessNode(node->expression()));

  // Create a mutable instance of ResolvedGeneratedColumnInfo.
  auto copy = MakeResolvedGeneratedColumnInfo(
    std::move(expression),
    node->is_stored()
  );

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedColumnDefinition(
    const ResolvedColumnDefinition* node) {
  // Get deep copy of annotations field.
  ZETASQL_ASSIGN_OR_RETURN(
      std::unique_ptr<ResolvedColumnAnnotations> annotations,
      ProcessNode(node->annotations()));

  // Get deep copy of generated_column_info field.
  ZETASQL_ASSIGN_OR_RETURN(
      std::unique_ptr<ResolvedGeneratedColumnInfo> generated_column_info,
      ProcessNode(node->generated_column_info()));

  // Create a mutable instance of ResolvedColumnDefinition.
  auto copy = MakeResolvedColumnDefinition(
    node->name(),
    node->type(),
    std::move(annotations),
    node->is_hidden(),
    node->column(),
    std::move(generated_column_info)
  );

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedPrimaryKey(
    const ResolvedPrimaryKey* node) {
  // Get a deep copy of option_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedOption>> option_list,
      ProcessNodeList(node->option_list()));

  // Create a mutable instance of ResolvedPrimaryKey.
  auto copy = MakeResolvedPrimaryKey(
    node->column_offset_list(),
    std::move(option_list)
  );

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedForeignKey(
    const ResolvedForeignKey* node) {
  // Get a deep copy of option_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedOption>> option_list,
      ProcessNodeList(node->option_list()));

  // Create a mutable instance of ResolvedForeignKey.
  auto copy = MakeResolvedForeignKey(
    node->constraint_name(),
    node->referencing_column_offset_list(),
    node->referenced_table(),
    node->referenced_column_offset_list(),
    node->match_mode(),
    node->update_action(),
    node->delete_action(),
    node->enforced(),
    std::move(option_list)
  );

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedCheckConstraint(
    const ResolvedCheckConstraint* node) {
  // Get deep copy of expression field.
  ZETASQL_ASSIGN_OR_RETURN(
      std::unique_ptr<ResolvedExpr> expression,
      ProcessNode(node->expression()));

  // Get a deep copy of option_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedOption>> option_list,
      ProcessNodeList(node->option_list()));

  // Create a mutable instance of ResolvedCheckConstraint.
  auto copy = MakeResolvedCheckConstraint(
    node->constraint_name(),
    std::move(expression),
    node->enforced(),
    std::move(option_list)
  );

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedOutputColumn(
    const ResolvedOutputColumn* node) {
  // Create a mutable instance of ResolvedOutputColumn.
  auto copy = MakeResolvedOutputColumn(
    node->name(),
    node->column()
  );

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedProjectScan(
    const ResolvedProjectScan* node) {
  // Get a deep copy of expr_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedComputedColumn>> expr_list,
      ProcessNodeList(node->expr_list()));

  // Get deep copy of input_scan field.
  ZETASQL_ASSIGN_OR_RETURN(
      std::unique_ptr<ResolvedScan> input_scan,
      ProcessNode(node->input_scan()));

  // Get a deep copy of hint_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedOption>> hint_list,
      ProcessNodeList(node->hint_list()));

  // Create a mutable instance of ResolvedProjectScan.
  auto copy = MakeResolvedProjectScan(
    node->column_list(),
    std::move(expr_list),
    std::move(input_scan)
  );

  // Copy the hint list explicitly because hint_list is not a constructor arg.
  // Because it is not a constructor arg, the only way to copy the value is to
  // copy it explicitly.
  ZETASQL_RETURN_IF_ERROR(CopyHintList<ResolvedProjectScan>(node, copy.get()));

  // Copy the is_ordered field explicitly because it is not a constructor arg.
  copy.get()->set_is_ordered(node->is_ordered());

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedTVFScan(
    const ResolvedTVFScan* node) {
  // Get a deep copy of argument_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedTVFArgument>> argument_list,
      ProcessNodeList(node->argument_list()));

  // Get a deep copy of hint_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedOption>> hint_list,
      ProcessNodeList(node->hint_list()));

  // Create a mutable instance of ResolvedTVFScan.
  auto copy = MakeResolvedTVFScan(
    node->column_list(),
    node->tvf(),
    node->signature(),
    std::move(argument_list),
    node->alias()
  );

  // Copy the hint list explicitly because hint_list is not a constructor arg.
  // Because it is not a constructor arg, the only way to copy the value is to
  // copy it explicitly.
  ZETASQL_RETURN_IF_ERROR(CopyHintList<ResolvedTVFScan>(node, copy.get()));

  // Copy the is_ordered field explicitly because it is not a constructor arg.
  copy.get()->set_is_ordered(node->is_ordered());

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedTVFArgument(
    const ResolvedTVFArgument* node) {
  // Get deep copy of expr field.
  ZETASQL_ASSIGN_OR_RETURN(
      std::unique_ptr<ResolvedExpr> expr,
      ProcessNode(node->expr()));

  // Get deep copy of scan field.
  ZETASQL_ASSIGN_OR_RETURN(
      std::unique_ptr<ResolvedScan> scan,
      ProcessNode(node->scan()));

  // Get deep copy of model field.
  ZETASQL_ASSIGN_OR_RETURN(
      std::unique_ptr<ResolvedModel> model,
      ProcessNode(node->model()));

  // Create a mutable instance of ResolvedTVFArgument.
  auto copy = MakeResolvedTVFArgument(
    std::move(expr),
    std::move(scan),
    std::move(model),
    node->argument_column_list()
  );

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedExplainStmt(
    const ResolvedExplainStmt* node) {
  // Get deep copy of statement field.
  ZETASQL_ASSIGN_OR_RETURN(
      std::unique_ptr<ResolvedStatement> statement,
      ProcessNode(node->statement()));

  // Get a deep copy of hint_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedOption>> hint_list,
      ProcessNodeList(node->hint_list()));

  // Create a mutable instance of ResolvedExplainStmt.
  auto copy = MakeResolvedExplainStmt(
    std::move(statement)
  );

  // Copy the hint list explicitly because hint_list is not a constructor arg.
  // Because it is not a constructor arg, the only way to copy the value is to
  // copy it explicitly.
  ZETASQL_RETURN_IF_ERROR(CopyHintList<ResolvedExplainStmt>(node, copy.get()));

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedQueryStmt(
    const ResolvedQueryStmt* node) {
  // Get a deep copy of output_column_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedOutputColumn>> output_column_list,
      ProcessNodeList(node->output_column_list()));

  // Get deep copy of query field.
  ZETASQL_ASSIGN_OR_RETURN(
      std::unique_ptr<ResolvedScan> query,
      ProcessNode(node->query()));

  // Get a deep copy of hint_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedOption>> hint_list,
      ProcessNodeList(node->hint_list()));

  // Create a mutable instance of ResolvedQueryStmt.
  auto copy = MakeResolvedQueryStmt(
    std::move(output_column_list),
    node->is_value_table(),
    std::move(query)
  );

  // Copy the hint list explicitly because hint_list is not a constructor arg.
  // Because it is not a constructor arg, the only way to copy the value is to
  // copy it explicitly.
  ZETASQL_RETURN_IF_ERROR(CopyHintList<ResolvedQueryStmt>(node, copy.get()));

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedCreateDatabaseStmt(
    const ResolvedCreateDatabaseStmt* node) {
  // Get a deep copy of option_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedOption>> option_list,
      ProcessNodeList(node->option_list()));

  // Get a deep copy of hint_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedOption>> hint_list,
      ProcessNodeList(node->hint_list()));

  // Create a mutable instance of ResolvedCreateDatabaseStmt.
  auto copy = MakeResolvedCreateDatabaseStmt(
    node->name_path(),
    std::move(option_list)
  );

  // Copy the hint list explicitly because hint_list is not a constructor arg.
  // Because it is not a constructor arg, the only way to copy the value is to
  // copy it explicitly.
  ZETASQL_RETURN_IF_ERROR(CopyHintList<ResolvedCreateDatabaseStmt>(node, copy.get()));

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedIndexItem(
    const ResolvedIndexItem* node) {
  // Get deep copy of column_ref field.
  ZETASQL_ASSIGN_OR_RETURN(
      std::unique_ptr<ResolvedColumnRef> column_ref,
      ProcessNode(node->column_ref()));

  // Create a mutable instance of ResolvedIndexItem.
  auto copy = MakeResolvedIndexItem(
    std::move(column_ref),
    node->descending()
  );

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedUnnestItem(
    const ResolvedUnnestItem* node) {
  // Get deep copy of array_expr field.
  ZETASQL_ASSIGN_OR_RETURN(
      std::unique_ptr<ResolvedExpr> array_expr,
      ProcessNode(node->array_expr()));

  // Get deep copy of array_offset_column field.
  ZETASQL_ASSIGN_OR_RETURN(
      std::unique_ptr<ResolvedColumnHolder> array_offset_column,
      ProcessNode(node->array_offset_column()));

  // Create a mutable instance of ResolvedUnnestItem.
  auto copy = MakeResolvedUnnestItem(
    std::move(array_expr),
    node->element_column(),
    std::move(array_offset_column)
  );

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedCreateIndexStmt(
    const ResolvedCreateIndexStmt* node) {
  // Get deep copy of table_scan field.
  ZETASQL_ASSIGN_OR_RETURN(
      std::unique_ptr<ResolvedTableScan> table_scan,
      ProcessNode(node->table_scan()));

  // Get a deep copy of index_item_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedIndexItem>> index_item_list,
      ProcessNodeList(node->index_item_list()));

  // Get a deep copy of storing_expression_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedExpr>> storing_expression_list,
      ProcessNodeList(node->storing_expression_list()));

  // Get a deep copy of option_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedOption>> option_list,
      ProcessNodeList(node->option_list()));

  // Get a deep copy of computed_columns_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedComputedColumn>> computed_columns_list,
      ProcessNodeList(node->computed_columns_list()));

  // Get a deep copy of unnest_expressions_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedUnnestItem>> unnest_expressions_list,
      ProcessNodeList(node->unnest_expressions_list()));

  // Get a deep copy of hint_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedOption>> hint_list,
      ProcessNodeList(node->hint_list()));

  // Create a mutable instance of ResolvedCreateIndexStmt.
  auto copy = MakeResolvedCreateIndexStmt(
    node->name_path(),
    node->create_scope(),
    node->create_mode(),
    node->table_name_path(),
    std::move(table_scan),
    node->is_unique(),
    std::move(index_item_list),
    std::move(storing_expression_list),
    std::move(option_list),
    std::move(computed_columns_list),
    std::move(unnest_expressions_list)
  );

  // Copy the hint list explicitly because hint_list is not a constructor arg.
  // Because it is not a constructor arg, the only way to copy the value is to
  // copy it explicitly.
  ZETASQL_RETURN_IF_ERROR(CopyHintList<ResolvedCreateIndexStmt>(node, copy.get()));

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedCreateTableStmt(
    const ResolvedCreateTableStmt* node) {
  // Get a deep copy of hint_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedOption>> hint_list,
      ProcessNodeList(node->hint_list()));

  // Get a deep copy of option_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedOption>> option_list,
      ProcessNodeList(node->option_list()));

  // Get a deep copy of column_definition_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedColumnDefinition>> column_definition_list,
      ProcessNodeList(node->column_definition_list()));

  // Get deep copy of primary_key field.
  ZETASQL_ASSIGN_OR_RETURN(
      std::unique_ptr<ResolvedPrimaryKey> primary_key,
      ProcessNode(node->primary_key()));

  // Get a deep copy of foreign_key_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedForeignKey>> foreign_key_list,
      ProcessNodeList(node->foreign_key_list()));

  // Get a deep copy of check_constraint_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedCheckConstraint>> check_constraint_list,
      ProcessNodeList(node->check_constraint_list()));

  // Get a deep copy of partition_by_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedExpr>> partition_by_list,
      ProcessNodeList(node->partition_by_list()));

  // Get a deep copy of cluster_by_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedExpr>> cluster_by_list,
      ProcessNodeList(node->cluster_by_list()));

  // Create a mutable instance of ResolvedCreateTableStmt.
  auto copy = MakeResolvedCreateTableStmt(
    node->name_path(),
    node->create_scope(),
    node->create_mode(),
    std::move(option_list),
    std::move(column_definition_list),
    node->pseudo_column_list(),
    std::move(primary_key),
    std::move(foreign_key_list),
    std::move(check_constraint_list),
    std::move(partition_by_list),
    std::move(cluster_by_list),
    node->is_value_table()
  );

  // Copy the hint list explicitly because hint_list is not a constructor arg.
  // Because it is not a constructor arg, the only way to copy the value is to
  // copy it explicitly.
  ZETASQL_RETURN_IF_ERROR(CopyHintList<ResolvedCreateTableStmt>(node, copy.get()));

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedCreateTableAsSelectStmt(
    const ResolvedCreateTableAsSelectStmt* node) {
  // Get a deep copy of output_column_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedOutputColumn>> output_column_list,
      ProcessNodeList(node->output_column_list()));

  // Get deep copy of query field.
  ZETASQL_ASSIGN_OR_RETURN(
      std::unique_ptr<ResolvedScan> query,
      ProcessNode(node->query()));

  // Get a deep copy of hint_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedOption>> hint_list,
      ProcessNodeList(node->hint_list()));

  // Get a deep copy of option_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedOption>> option_list,
      ProcessNodeList(node->option_list()));

  // Get a deep copy of column_definition_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedColumnDefinition>> column_definition_list,
      ProcessNodeList(node->column_definition_list()));

  // Get deep copy of primary_key field.
  ZETASQL_ASSIGN_OR_RETURN(
      std::unique_ptr<ResolvedPrimaryKey> primary_key,
      ProcessNode(node->primary_key()));

  // Get a deep copy of foreign_key_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedForeignKey>> foreign_key_list,
      ProcessNodeList(node->foreign_key_list()));

  // Get a deep copy of check_constraint_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedCheckConstraint>> check_constraint_list,
      ProcessNodeList(node->check_constraint_list()));

  // Get a deep copy of partition_by_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedExpr>> partition_by_list,
      ProcessNodeList(node->partition_by_list()));

  // Get a deep copy of cluster_by_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedExpr>> cluster_by_list,
      ProcessNodeList(node->cluster_by_list()));

  // Create a mutable instance of ResolvedCreateTableAsSelectStmt.
  auto copy = MakeResolvedCreateTableAsSelectStmt(
    node->name_path(),
    node->create_scope(),
    node->create_mode(),
    std::move(option_list),
    std::move(column_definition_list),
    node->pseudo_column_list(),
    std::move(primary_key),
    std::move(foreign_key_list),
    std::move(check_constraint_list),
    std::move(partition_by_list),
    std::move(cluster_by_list),
    node->is_value_table(),
    std::move(output_column_list),
    std::move(query)
  );

  // Copy the hint list explicitly because hint_list is not a constructor arg.
  // Because it is not a constructor arg, the only way to copy the value is to
  // copy it explicitly.
  ZETASQL_RETURN_IF_ERROR(CopyHintList<ResolvedCreateTableAsSelectStmt>(node, copy.get()));

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedCreateModelStmt(
    const ResolvedCreateModelStmt* node) {
  // Get a deep copy of option_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedOption>> option_list,
      ProcessNodeList(node->option_list()));

  // Get a deep copy of output_column_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedOutputColumn>> output_column_list,
      ProcessNodeList(node->output_column_list()));

  // Get deep copy of query field.
  ZETASQL_ASSIGN_OR_RETURN(
      std::unique_ptr<ResolvedScan> query,
      ProcessNode(node->query()));

  // Get a deep copy of transform_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedComputedColumn>> transform_list,
      ProcessNodeList(node->transform_list()));

  // Get a deep copy of transform_output_column_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedOutputColumn>> transform_output_column_list,
      ProcessNodeList(node->transform_output_column_list()));

  // Get a deep copy of hint_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedOption>> hint_list,
      ProcessNodeList(node->hint_list()));

  // Create a mutable instance of ResolvedCreateModelStmt.
  auto copy = MakeResolvedCreateModelStmt(
    node->name_path(),
    node->create_scope(),
    node->create_mode(),
    std::move(option_list),
    std::move(output_column_list),
    std::move(query),
    std::move(transform_list),
    std::move(transform_output_column_list)
  );

  // Copy the hint list explicitly because hint_list is not a constructor arg.
  // Because it is not a constructor arg, the only way to copy the value is to
  // copy it explicitly.
  ZETASQL_RETURN_IF_ERROR(CopyHintList<ResolvedCreateModelStmt>(node, copy.get()));

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedCreateViewStmt(
    const ResolvedCreateViewStmt* node) {
  // Get a deep copy of hint_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedOption>> hint_list,
      ProcessNodeList(node->hint_list()));

  // Get a deep copy of option_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedOption>> option_list,
      ProcessNodeList(node->option_list()));

  // Get a deep copy of output_column_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedOutputColumn>> output_column_list,
      ProcessNodeList(node->output_column_list()));

  // Get deep copy of query field.
  ZETASQL_ASSIGN_OR_RETURN(
      std::unique_ptr<ResolvedScan> query,
      ProcessNode(node->query()));

  // Create a mutable instance of ResolvedCreateViewStmt.
  auto copy = MakeResolvedCreateViewStmt(
    node->name_path(),
    node->create_scope(),
    node->create_mode(),
    std::move(option_list),
    std::move(output_column_list),
    std::move(query),
    node->sql(),
    node->sql_security(),
    node->is_value_table()
  );

  // Copy the hint list explicitly because hint_list is not a constructor arg.
  // Because it is not a constructor arg, the only way to copy the value is to
  // copy it explicitly.
  ZETASQL_RETURN_IF_ERROR(CopyHintList<ResolvedCreateViewStmt>(node, copy.get()));

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedCreateExternalTableStmt(
    const ResolvedCreateExternalTableStmt* node) {
  // Get a deep copy of option_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedOption>> option_list,
      ProcessNodeList(node->option_list()));

  // Get a deep copy of hint_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedOption>> hint_list,
      ProcessNodeList(node->hint_list()));

  // Create a mutable instance of ResolvedCreateExternalTableStmt.
  auto copy = MakeResolvedCreateExternalTableStmt(
    node->name_path(),
    node->create_scope(),
    node->create_mode(),
    std::move(option_list)
  );

  // Copy the hint list explicitly because hint_list is not a constructor arg.
  // Because it is not a constructor arg, the only way to copy the value is to
  // copy it explicitly.
  ZETASQL_RETURN_IF_ERROR(CopyHintList<ResolvedCreateExternalTableStmt>(node, copy.get()));

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedExportDataStmt(
    const ResolvedExportDataStmt* node) {
  // Get a deep copy of option_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedOption>> option_list,
      ProcessNodeList(node->option_list()));

  // Get a deep copy of output_column_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedOutputColumn>> output_column_list,
      ProcessNodeList(node->output_column_list()));

  // Get deep copy of query field.
  ZETASQL_ASSIGN_OR_RETURN(
      std::unique_ptr<ResolvedScan> query,
      ProcessNode(node->query()));

  // Get a deep copy of hint_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedOption>> hint_list,
      ProcessNodeList(node->hint_list()));

  // Create a mutable instance of ResolvedExportDataStmt.
  auto copy = MakeResolvedExportDataStmt(
    std::move(option_list),
    std::move(output_column_list),
    node->is_value_table(),
    std::move(query)
  );

  // Copy the hint list explicitly because hint_list is not a constructor arg.
  // Because it is not a constructor arg, the only way to copy the value is to
  // copy it explicitly.
  ZETASQL_RETURN_IF_ERROR(CopyHintList<ResolvedExportDataStmt>(node, copy.get()));

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedDefineTableStmt(
    const ResolvedDefineTableStmt* node) {
  // Get a deep copy of option_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedOption>> option_list,
      ProcessNodeList(node->option_list()));

  // Get a deep copy of hint_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedOption>> hint_list,
      ProcessNodeList(node->hint_list()));

  // Create a mutable instance of ResolvedDefineTableStmt.
  auto copy = MakeResolvedDefineTableStmt(
    node->name_path(),
    std::move(option_list)
  );

  // Copy the hint list explicitly because hint_list is not a constructor arg.
  // Because it is not a constructor arg, the only way to copy the value is to
  // copy it explicitly.
  ZETASQL_RETURN_IF_ERROR(CopyHintList<ResolvedDefineTableStmt>(node, copy.get()));

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedDescribeStmt(
    const ResolvedDescribeStmt* node) {
  // Get a deep copy of hint_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedOption>> hint_list,
      ProcessNodeList(node->hint_list()));

  // Create a mutable instance of ResolvedDescribeStmt.
  auto copy = MakeResolvedDescribeStmt(
    node->object_type(),
    node->name_path(),
    node->from_name_path()
  );

  // Copy the hint list explicitly because hint_list is not a constructor arg.
  // Because it is not a constructor arg, the only way to copy the value is to
  // copy it explicitly.
  ZETASQL_RETURN_IF_ERROR(CopyHintList<ResolvedDescribeStmt>(node, copy.get()));

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedShowStmt(
    const ResolvedShowStmt* node) {
  // Get deep copy of like_expr field.
  ZETASQL_ASSIGN_OR_RETURN(
      std::unique_ptr<ResolvedLiteral> like_expr,
      ProcessNode(node->like_expr()));

  // Get a deep copy of hint_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedOption>> hint_list,
      ProcessNodeList(node->hint_list()));

  // Create a mutable instance of ResolvedShowStmt.
  auto copy = MakeResolvedShowStmt(
    node->identifier(),
    node->name_path(),
    std::move(like_expr)
  );

  // Copy the hint list explicitly because hint_list is not a constructor arg.
  // Because it is not a constructor arg, the only way to copy the value is to
  // copy it explicitly.
  ZETASQL_RETURN_IF_ERROR(CopyHintList<ResolvedShowStmt>(node, copy.get()));

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedBeginStmt(
    const ResolvedBeginStmt* node) {
  // Get a deep copy of hint_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedOption>> hint_list,
      ProcessNodeList(node->hint_list()));

  // Create a mutable instance of ResolvedBeginStmt.
  auto copy = MakeResolvedBeginStmt(
    node->read_write_mode(),
    node->isolation_level_list()
  );

  // Copy the hint list explicitly because hint_list is not a constructor arg.
  // Because it is not a constructor arg, the only way to copy the value is to
  // copy it explicitly.
  ZETASQL_RETURN_IF_ERROR(CopyHintList<ResolvedBeginStmt>(node, copy.get()));

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedSetTransactionStmt(
    const ResolvedSetTransactionStmt* node) {
  // Get a deep copy of hint_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedOption>> hint_list,
      ProcessNodeList(node->hint_list()));

  // Create a mutable instance of ResolvedSetTransactionStmt.
  auto copy = MakeResolvedSetTransactionStmt(
    node->read_write_mode(),
    node->isolation_level_list()
  );

  // Copy the hint list explicitly because hint_list is not a constructor arg.
  // Because it is not a constructor arg, the only way to copy the value is to
  // copy it explicitly.
  ZETASQL_RETURN_IF_ERROR(CopyHintList<ResolvedSetTransactionStmt>(node, copy.get()));

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedCommitStmt(
    const ResolvedCommitStmt* node) {
  // Get a deep copy of hint_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedOption>> hint_list,
      ProcessNodeList(node->hint_list()));

  // Create a mutable instance of ResolvedCommitStmt.
  auto copy = MakeResolvedCommitStmt(
  );

  // Copy the hint list explicitly because hint_list is not a constructor arg.
  // Because it is not a constructor arg, the only way to copy the value is to
  // copy it explicitly.
  ZETASQL_RETURN_IF_ERROR(CopyHintList<ResolvedCommitStmt>(node, copy.get()));

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedRollbackStmt(
    const ResolvedRollbackStmt* node) {
  // Get a deep copy of hint_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedOption>> hint_list,
      ProcessNodeList(node->hint_list()));

  // Create a mutable instance of ResolvedRollbackStmt.
  auto copy = MakeResolvedRollbackStmt(
  );

  // Copy the hint list explicitly because hint_list is not a constructor arg.
  // Because it is not a constructor arg, the only way to copy the value is to
  // copy it explicitly.
  ZETASQL_RETURN_IF_ERROR(CopyHintList<ResolvedRollbackStmt>(node, copy.get()));

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedStartBatchStmt(
    const ResolvedStartBatchStmt* node) {
  // Get a deep copy of hint_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedOption>> hint_list,
      ProcessNodeList(node->hint_list()));

  // Create a mutable instance of ResolvedStartBatchStmt.
  auto copy = MakeResolvedStartBatchStmt(
    node->batch_type()
  );

  // Copy the hint list explicitly because hint_list is not a constructor arg.
  // Because it is not a constructor arg, the only way to copy the value is to
  // copy it explicitly.
  ZETASQL_RETURN_IF_ERROR(CopyHintList<ResolvedStartBatchStmt>(node, copy.get()));

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedRunBatchStmt(
    const ResolvedRunBatchStmt* node) {
  // Get a deep copy of hint_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedOption>> hint_list,
      ProcessNodeList(node->hint_list()));

  // Create a mutable instance of ResolvedRunBatchStmt.
  auto copy = MakeResolvedRunBatchStmt(
  );

  // Copy the hint list explicitly because hint_list is not a constructor arg.
  // Because it is not a constructor arg, the only way to copy the value is to
  // copy it explicitly.
  ZETASQL_RETURN_IF_ERROR(CopyHintList<ResolvedRunBatchStmt>(node, copy.get()));

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedAbortBatchStmt(
    const ResolvedAbortBatchStmt* node) {
  // Get a deep copy of hint_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedOption>> hint_list,
      ProcessNodeList(node->hint_list()));

  // Create a mutable instance of ResolvedAbortBatchStmt.
  auto copy = MakeResolvedAbortBatchStmt(
  );

  // Copy the hint list explicitly because hint_list is not a constructor arg.
  // Because it is not a constructor arg, the only way to copy the value is to
  // copy it explicitly.
  ZETASQL_RETURN_IF_ERROR(CopyHintList<ResolvedAbortBatchStmt>(node, copy.get()));

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedDropStmt(
    const ResolvedDropStmt* node) {
  // Get a deep copy of hint_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedOption>> hint_list,
      ProcessNodeList(node->hint_list()));

  // Create a mutable instance of ResolvedDropStmt.
  auto copy = MakeResolvedDropStmt(
    node->object_type(),
    node->is_if_exists(),
    node->name_path()
  );

  // Copy the hint list explicitly because hint_list is not a constructor arg.
  // Because it is not a constructor arg, the only way to copy the value is to
  // copy it explicitly.
  ZETASQL_RETURN_IF_ERROR(CopyHintList<ResolvedDropStmt>(node, copy.get()));

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedDropMaterializedViewStmt(
    const ResolvedDropMaterializedViewStmt* node) {
  // Get a deep copy of hint_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedOption>> hint_list,
      ProcessNodeList(node->hint_list()));

  // Create a mutable instance of ResolvedDropMaterializedViewStmt.
  auto copy = MakeResolvedDropMaterializedViewStmt(
    node->is_if_exists(),
    node->name_path()
  );

  // Copy the hint list explicitly because hint_list is not a constructor arg.
  // Because it is not a constructor arg, the only way to copy the value is to
  // copy it explicitly.
  ZETASQL_RETURN_IF_ERROR(CopyHintList<ResolvedDropMaterializedViewStmt>(node, copy.get()));

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedWithScan(
    const ResolvedWithScan* node) {
  // Get a deep copy of with_entry_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedWithEntry>> with_entry_list,
      ProcessNodeList(node->with_entry_list()));

  // Get deep copy of query field.
  ZETASQL_ASSIGN_OR_RETURN(
      std::unique_ptr<ResolvedScan> query,
      ProcessNode(node->query()));

  // Get a deep copy of hint_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedOption>> hint_list,
      ProcessNodeList(node->hint_list()));

  // Create a mutable instance of ResolvedWithScan.
  auto copy = MakeResolvedWithScan(
    node->column_list(),
    std::move(with_entry_list),
    std::move(query)
  );

  // Copy the hint list explicitly because hint_list is not a constructor arg.
  // Because it is not a constructor arg, the only way to copy the value is to
  // copy it explicitly.
  ZETASQL_RETURN_IF_ERROR(CopyHintList<ResolvedWithScan>(node, copy.get()));

  // Copy the is_ordered field explicitly because it is not a constructor arg.
  copy.get()->set_is_ordered(node->is_ordered());

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedWithEntry(
    const ResolvedWithEntry* node) {
  // Get deep copy of with_subquery field.
  ZETASQL_ASSIGN_OR_RETURN(
      std::unique_ptr<ResolvedScan> with_subquery,
      ProcessNode(node->with_subquery()));

  // Create a mutable instance of ResolvedWithEntry.
  auto copy = MakeResolvedWithEntry(
    node->with_query_name(),
    std::move(with_subquery)
  );

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedOption(
    const ResolvedOption* node) {
  // Get deep copy of value field.
  ZETASQL_ASSIGN_OR_RETURN(
      std::unique_ptr<ResolvedExpr> value,
      ProcessNode(node->value()));

  // Create a mutable instance of ResolvedOption.
  auto copy = MakeResolvedOption(
    node->qualifier(),
    node->name(),
    std::move(value)
  );

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedWindowPartitioning(
    const ResolvedWindowPartitioning* node) {
  // Get a deep copy of partition_by_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedColumnRef>> partition_by_list,
      ProcessNodeList(node->partition_by_list()));

  // Get a deep copy of hint_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedOption>> hint_list,
      ProcessNodeList(node->hint_list()));

  // Create a mutable instance of ResolvedWindowPartitioning.
  auto copy = MakeResolvedWindowPartitioning(
    std::move(partition_by_list)
  );

  // Copy the hint list explicitly because hint_list is not a constructor arg.
  // Because it is not a constructor arg, the only way to copy the value is to
  // copy it explicitly.
  ZETASQL_RETURN_IF_ERROR(CopyHintList<ResolvedWindowPartitioning>(node, copy.get()));

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedWindowOrdering(
    const ResolvedWindowOrdering* node) {
  // Get a deep copy of order_by_item_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedOrderByItem>> order_by_item_list,
      ProcessNodeList(node->order_by_item_list()));

  // Get a deep copy of hint_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedOption>> hint_list,
      ProcessNodeList(node->hint_list()));

  // Create a mutable instance of ResolvedWindowOrdering.
  auto copy = MakeResolvedWindowOrdering(
    std::move(order_by_item_list)
  );

  // Copy the hint list explicitly because hint_list is not a constructor arg.
  // Because it is not a constructor arg, the only way to copy the value is to
  // copy it explicitly.
  ZETASQL_RETURN_IF_ERROR(CopyHintList<ResolvedWindowOrdering>(node, copy.get()));

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedWindowFrame(
    const ResolvedWindowFrame* node) {
  // Get deep copy of start_expr field.
  ZETASQL_ASSIGN_OR_RETURN(
      std::unique_ptr<ResolvedWindowFrameExpr> start_expr,
      ProcessNode(node->start_expr()));

  // Get deep copy of end_expr field.
  ZETASQL_ASSIGN_OR_RETURN(
      std::unique_ptr<ResolvedWindowFrameExpr> end_expr,
      ProcessNode(node->end_expr()));

  // Create a mutable instance of ResolvedWindowFrame.
  auto copy = MakeResolvedWindowFrame(
    node->frame_unit(),
    std::move(start_expr),
    std::move(end_expr)
  );

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedAnalyticFunctionGroup(
    const ResolvedAnalyticFunctionGroup* node) {
  // Get deep copy of partition_by field.
  ZETASQL_ASSIGN_OR_RETURN(
      std::unique_ptr<ResolvedWindowPartitioning> partition_by,
      ProcessNode(node->partition_by()));

  // Get deep copy of order_by field.
  ZETASQL_ASSIGN_OR_RETURN(
      std::unique_ptr<ResolvedWindowOrdering> order_by,
      ProcessNode(node->order_by()));

  // Get a deep copy of analytic_function_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedComputedColumn>> analytic_function_list,
      ProcessNodeList(node->analytic_function_list()));

  // Create a mutable instance of ResolvedAnalyticFunctionGroup.
  auto copy = MakeResolvedAnalyticFunctionGroup(
    std::move(partition_by),
    std::move(order_by),
    std::move(analytic_function_list)
  );

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedWindowFrameExpr(
    const ResolvedWindowFrameExpr* node) {
  // Get deep copy of expression field.
  ZETASQL_ASSIGN_OR_RETURN(
      std::unique_ptr<ResolvedExpr> expression,
      ProcessNode(node->expression()));

  // Create a mutable instance of ResolvedWindowFrameExpr.
  auto copy = MakeResolvedWindowFrameExpr(
    node->boundary_type(),
    std::move(expression)
  );

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedDMLValue(
    const ResolvedDMLValue* node) {
  // Get deep copy of value field.
  ZETASQL_ASSIGN_OR_RETURN(
      std::unique_ptr<ResolvedExpr> value,
      ProcessNode(node->value()));

  // Create a mutable instance of ResolvedDMLValue.
  auto copy = MakeResolvedDMLValue(
    std::move(value)
  );

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedDMLDefault(
    const ResolvedDMLDefault* node) {
  // Create a mutable instance of ResolvedDMLDefault.
  auto copy = MakeResolvedDMLDefault(
    node->type()
  );

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedAssertStmt(
    const ResolvedAssertStmt* node) {
  // Get deep copy of expression field.
  ZETASQL_ASSIGN_OR_RETURN(
      std::unique_ptr<ResolvedExpr> expression,
      ProcessNode(node->expression()));

  // Get a deep copy of hint_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedOption>> hint_list,
      ProcessNodeList(node->hint_list()));

  // Create a mutable instance of ResolvedAssertStmt.
  auto copy = MakeResolvedAssertStmt(
    std::move(expression),
    node->description()
  );

  // Copy the hint list explicitly because hint_list is not a constructor arg.
  // Because it is not a constructor arg, the only way to copy the value is to
  // copy it explicitly.
  ZETASQL_RETURN_IF_ERROR(CopyHintList<ResolvedAssertStmt>(node, copy.get()));

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedAssertRowsModified(
    const ResolvedAssertRowsModified* node) {
  // Get deep copy of rows field.
  ZETASQL_ASSIGN_OR_RETURN(
      std::unique_ptr<ResolvedExpr> rows,
      ProcessNode(node->rows()));

  // Create a mutable instance of ResolvedAssertRowsModified.
  auto copy = MakeResolvedAssertRowsModified(
    std::move(rows)
  );

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedInsertRow(
    const ResolvedInsertRow* node) {
  // Get a deep copy of value_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedDMLValue>> value_list,
      ProcessNodeList(node->value_list()));

  // Create a mutable instance of ResolvedInsertRow.
  auto copy = MakeResolvedInsertRow(
    std::move(value_list)
  );

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedInsertStmt(
    const ResolvedInsertStmt* node) {
  // Get deep copy of table_scan field.
  ZETASQL_ASSIGN_OR_RETURN(
      std::unique_ptr<ResolvedTableScan> table_scan,
      ProcessNode(node->table_scan()));

  // Get deep copy of assert_rows_modified field.
  ZETASQL_ASSIGN_OR_RETURN(
      std::unique_ptr<ResolvedAssertRowsModified> assert_rows_modified,
      ProcessNode(node->assert_rows_modified()));

  // Get a deep copy of query_parameter_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedColumnRef>> query_parameter_list,
      ProcessNodeList(node->query_parameter_list()));

  // Get deep copy of query field.
  ZETASQL_ASSIGN_OR_RETURN(
      std::unique_ptr<ResolvedScan> query,
      ProcessNode(node->query()));

  // Get a deep copy of row_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedInsertRow>> row_list,
      ProcessNodeList(node->row_list()));

  // Get a deep copy of hint_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedOption>> hint_list,
      ProcessNodeList(node->hint_list()));

  // Create a mutable instance of ResolvedInsertStmt.
  auto copy = MakeResolvedInsertStmt(
    std::move(table_scan),
    node->insert_mode(),
    std::move(assert_rows_modified),
    node->insert_column_list(),
    std::move(query_parameter_list),
    std::move(query),
    node->query_output_column_list(),
    std::move(row_list)
  );

  // Copy the hint list explicitly because hint_list is not a constructor arg.
  // Because it is not a constructor arg, the only way to copy the value is to
  // copy it explicitly.
  ZETASQL_RETURN_IF_ERROR(CopyHintList<ResolvedInsertStmt>(node, copy.get()));

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedDeleteStmt(
    const ResolvedDeleteStmt* node) {
  // Get deep copy of table_scan field.
  ZETASQL_ASSIGN_OR_RETURN(
      std::unique_ptr<ResolvedTableScan> table_scan,
      ProcessNode(node->table_scan()));

  // Get deep copy of assert_rows_modified field.
  ZETASQL_ASSIGN_OR_RETURN(
      std::unique_ptr<ResolvedAssertRowsModified> assert_rows_modified,
      ProcessNode(node->assert_rows_modified()));

  // Get deep copy of array_offset_column field.
  ZETASQL_ASSIGN_OR_RETURN(
      std::unique_ptr<ResolvedColumnHolder> array_offset_column,
      ProcessNode(node->array_offset_column()));

  // Get deep copy of where_expr field.
  ZETASQL_ASSIGN_OR_RETURN(
      std::unique_ptr<ResolvedExpr> where_expr,
      ProcessNode(node->where_expr()));

  // Get a deep copy of hint_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedOption>> hint_list,
      ProcessNodeList(node->hint_list()));

  // Create a mutable instance of ResolvedDeleteStmt.
  auto copy = MakeResolvedDeleteStmt(
    std::move(table_scan),
    std::move(assert_rows_modified),
    std::move(array_offset_column),
    std::move(where_expr)
  );

  // Copy the hint list explicitly because hint_list is not a constructor arg.
  // Because it is not a constructor arg, the only way to copy the value is to
  // copy it explicitly.
  ZETASQL_RETURN_IF_ERROR(CopyHintList<ResolvedDeleteStmt>(node, copy.get()));

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedUpdateItem(
    const ResolvedUpdateItem* node) {
  // Get deep copy of target field.
  ZETASQL_ASSIGN_OR_RETURN(
      std::unique_ptr<ResolvedExpr> target,
      ProcessNode(node->target()));

  // Get deep copy of set_value field.
  ZETASQL_ASSIGN_OR_RETURN(
      std::unique_ptr<ResolvedDMLValue> set_value,
      ProcessNode(node->set_value()));

  // Get deep copy of element_column field.
  ZETASQL_ASSIGN_OR_RETURN(
      std::unique_ptr<ResolvedColumnHolder> element_column,
      ProcessNode(node->element_column()));

  // Get a deep copy of array_update_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedUpdateArrayItem>> array_update_list,
      ProcessNodeList(node->array_update_list()));

  // Get a deep copy of delete_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedDeleteStmt>> delete_list,
      ProcessNodeList(node->delete_list()));

  // Get a deep copy of update_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedUpdateStmt>> update_list,
      ProcessNodeList(node->update_list()));

  // Get a deep copy of insert_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedInsertStmt>> insert_list,
      ProcessNodeList(node->insert_list()));

  // Create a mutable instance of ResolvedUpdateItem.
  auto copy = MakeResolvedUpdateItem(
    std::move(target),
    std::move(set_value),
    std::move(element_column),
    std::move(array_update_list),
    std::move(delete_list),
    std::move(update_list),
    std::move(insert_list)
  );

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedUpdateArrayItem(
    const ResolvedUpdateArrayItem* node) {
  // Get deep copy of offset field.
  ZETASQL_ASSIGN_OR_RETURN(
      std::unique_ptr<ResolvedExpr> offset,
      ProcessNode(node->offset()));

  // Get deep copy of update_item field.
  ZETASQL_ASSIGN_OR_RETURN(
      std::unique_ptr<ResolvedUpdateItem> update_item,
      ProcessNode(node->update_item()));

  // Create a mutable instance of ResolvedUpdateArrayItem.
  auto copy = MakeResolvedUpdateArrayItem(
    std::move(offset),
    std::move(update_item)
  );

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedUpdateStmt(
    const ResolvedUpdateStmt* node) {
  // Get deep copy of table_scan field.
  ZETASQL_ASSIGN_OR_RETURN(
      std::unique_ptr<ResolvedTableScan> table_scan,
      ProcessNode(node->table_scan()));

  // Get deep copy of assert_rows_modified field.
  ZETASQL_ASSIGN_OR_RETURN(
      std::unique_ptr<ResolvedAssertRowsModified> assert_rows_modified,
      ProcessNode(node->assert_rows_modified()));

  // Get deep copy of array_offset_column field.
  ZETASQL_ASSIGN_OR_RETURN(
      std::unique_ptr<ResolvedColumnHolder> array_offset_column,
      ProcessNode(node->array_offset_column()));

  // Get deep copy of where_expr field.
  ZETASQL_ASSIGN_OR_RETURN(
      std::unique_ptr<ResolvedExpr> where_expr,
      ProcessNode(node->where_expr()));

  // Get a deep copy of update_item_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedUpdateItem>> update_item_list,
      ProcessNodeList(node->update_item_list()));

  // Get deep copy of from_scan field.
  ZETASQL_ASSIGN_OR_RETURN(
      std::unique_ptr<ResolvedScan> from_scan,
      ProcessNode(node->from_scan()));

  // Get a deep copy of hint_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedOption>> hint_list,
      ProcessNodeList(node->hint_list()));

  // Create a mutable instance of ResolvedUpdateStmt.
  auto copy = MakeResolvedUpdateStmt(
    std::move(table_scan),
    std::move(assert_rows_modified),
    std::move(array_offset_column),
    std::move(where_expr),
    std::move(update_item_list),
    std::move(from_scan)
  );

  // Copy the hint list explicitly because hint_list is not a constructor arg.
  // Because it is not a constructor arg, the only way to copy the value is to
  // copy it explicitly.
  ZETASQL_RETURN_IF_ERROR(CopyHintList<ResolvedUpdateStmt>(node, copy.get()));

  // Copy the column_access_list field explicitly because it is not a
  // constructor arg.
  copy.get()->set_column_access_list(node->column_access_list());

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedMergeWhen(
    const ResolvedMergeWhen* node) {
  // Get deep copy of match_expr field.
  ZETASQL_ASSIGN_OR_RETURN(
      std::unique_ptr<ResolvedExpr> match_expr,
      ProcessNode(node->match_expr()));

  // Get deep copy of insert_row field.
  ZETASQL_ASSIGN_OR_RETURN(
      std::unique_ptr<ResolvedInsertRow> insert_row,
      ProcessNode(node->insert_row()));

  // Get a deep copy of update_item_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedUpdateItem>> update_item_list,
      ProcessNodeList(node->update_item_list()));

  // Create a mutable instance of ResolvedMergeWhen.
  auto copy = MakeResolvedMergeWhen(
    node->match_type(),
    std::move(match_expr),
    node->action_type(),
    node->insert_column_list(),
    std::move(insert_row),
    std::move(update_item_list)
  );

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedMergeStmt(
    const ResolvedMergeStmt* node) {
  // Get deep copy of table_scan field.
  ZETASQL_ASSIGN_OR_RETURN(
      std::unique_ptr<ResolvedTableScan> table_scan,
      ProcessNode(node->table_scan()));

  // Get deep copy of from_scan field.
  ZETASQL_ASSIGN_OR_RETURN(
      std::unique_ptr<ResolvedScan> from_scan,
      ProcessNode(node->from_scan()));

  // Get deep copy of merge_expr field.
  ZETASQL_ASSIGN_OR_RETURN(
      std::unique_ptr<ResolvedExpr> merge_expr,
      ProcessNode(node->merge_expr()));

  // Get a deep copy of when_clause_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedMergeWhen>> when_clause_list,
      ProcessNodeList(node->when_clause_list()));

  // Get a deep copy of hint_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedOption>> hint_list,
      ProcessNodeList(node->hint_list()));

  // Create a mutable instance of ResolvedMergeStmt.
  auto copy = MakeResolvedMergeStmt(
    std::move(table_scan),
    std::move(from_scan),
    std::move(merge_expr),
    std::move(when_clause_list)
  );

  // Copy the hint list explicitly because hint_list is not a constructor arg.
  // Because it is not a constructor arg, the only way to copy the value is to
  // copy it explicitly.
  ZETASQL_RETURN_IF_ERROR(CopyHintList<ResolvedMergeStmt>(node, copy.get()));

  // Copy the column_access_list field explicitly because it is not a
  // constructor arg.
  copy.get()->set_column_access_list(node->column_access_list());

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedPrivilege(
    const ResolvedPrivilege* node) {
  // Create a mutable instance of ResolvedPrivilege.
  auto copy = MakeResolvedPrivilege(
    node->action_type(),
    node->unit_list()
  );

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedGrantStmt(
    const ResolvedGrantStmt* node) {
  // Get a deep copy of hint_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedOption>> hint_list,
      ProcessNodeList(node->hint_list()));

  // Get a deep copy of privilege_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedPrivilege>> privilege_list,
      ProcessNodeList(node->privilege_list()));

  // Get a deep copy of grantee_expr_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedExpr>> grantee_expr_list,
      ProcessNodeList(node->grantee_expr_list()));

  // Create a mutable instance of ResolvedGrantStmt.
  auto copy = MakeResolvedGrantStmt(
    std::move(privilege_list),
    node->object_type(),
    node->name_path(),
    node->grantee_list(),
    std::move(grantee_expr_list)
  );

  // Copy the hint list explicitly because hint_list is not a constructor arg.
  // Because it is not a constructor arg, the only way to copy the value is to
  // copy it explicitly.
  ZETASQL_RETURN_IF_ERROR(CopyHintList<ResolvedGrantStmt>(node, copy.get()));

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedRevokeStmt(
    const ResolvedRevokeStmt* node) {
  // Get a deep copy of hint_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedOption>> hint_list,
      ProcessNodeList(node->hint_list()));

  // Get a deep copy of privilege_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedPrivilege>> privilege_list,
      ProcessNodeList(node->privilege_list()));

  // Get a deep copy of grantee_expr_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedExpr>> grantee_expr_list,
      ProcessNodeList(node->grantee_expr_list()));

  // Create a mutable instance of ResolvedRevokeStmt.
  auto copy = MakeResolvedRevokeStmt(
    std::move(privilege_list),
    node->object_type(),
    node->name_path(),
    node->grantee_list(),
    std::move(grantee_expr_list)
  );

  // Copy the hint list explicitly because hint_list is not a constructor arg.
  // Because it is not a constructor arg, the only way to copy the value is to
  // copy it explicitly.
  ZETASQL_RETURN_IF_ERROR(CopyHintList<ResolvedRevokeStmt>(node, copy.get()));

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedAlterMaterializedViewStmt(
    const ResolvedAlterMaterializedViewStmt* node) {
  // Get a deep copy of hint_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedOption>> hint_list,
      ProcessNodeList(node->hint_list()));

  // Get a deep copy of alter_action_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedAlterAction>> alter_action_list,
      ProcessNodeList(node->alter_action_list()));

  // Create a mutable instance of ResolvedAlterMaterializedViewStmt.
  auto copy = MakeResolvedAlterMaterializedViewStmt(
    node->name_path(),
    std::move(alter_action_list),
    node->is_if_exists()
  );

  // Copy the hint list explicitly because hint_list is not a constructor arg.
  // Because it is not a constructor arg, the only way to copy the value is to
  // copy it explicitly.
  ZETASQL_RETURN_IF_ERROR(CopyHintList<ResolvedAlterMaterializedViewStmt>(node, copy.get()));

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedAlterTableStmt(
    const ResolvedAlterTableStmt* node) {
  // Get a deep copy of hint_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedOption>> hint_list,
      ProcessNodeList(node->hint_list()));

  // Get a deep copy of alter_action_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedAlterAction>> alter_action_list,
      ProcessNodeList(node->alter_action_list()));

  // Create a mutable instance of ResolvedAlterTableStmt.
  auto copy = MakeResolvedAlterTableStmt(
    node->name_path(),
    std::move(alter_action_list),
    node->is_if_exists()
  );

  // Copy the hint list explicitly because hint_list is not a constructor arg.
  // Because it is not a constructor arg, the only way to copy the value is to
  // copy it explicitly.
  ZETASQL_RETURN_IF_ERROR(CopyHintList<ResolvedAlterTableStmt>(node, copy.get()));

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedAlterViewStmt(
    const ResolvedAlterViewStmt* node) {
  // Get a deep copy of hint_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedOption>> hint_list,
      ProcessNodeList(node->hint_list()));

  // Get a deep copy of alter_action_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedAlterAction>> alter_action_list,
      ProcessNodeList(node->alter_action_list()));

  // Create a mutable instance of ResolvedAlterViewStmt.
  auto copy = MakeResolvedAlterViewStmt(
    node->name_path(),
    std::move(alter_action_list),
    node->is_if_exists()
  );

  // Copy the hint list explicitly because hint_list is not a constructor arg.
  // Because it is not a constructor arg, the only way to copy the value is to
  // copy it explicitly.
  ZETASQL_RETURN_IF_ERROR(CopyHintList<ResolvedAlterViewStmt>(node, copy.get()));

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedSetOptionsAction(
    const ResolvedSetOptionsAction* node) {
  // Get a deep copy of option_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedOption>> option_list,
      ProcessNodeList(node->option_list()));

  // Create a mutable instance of ResolvedSetOptionsAction.
  auto copy = MakeResolvedSetOptionsAction(
    std::move(option_list)
  );

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedAlterTableSetOptionsStmt(
    const ResolvedAlterTableSetOptionsStmt* node) {
  // Get a deep copy of option_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedOption>> option_list,
      ProcessNodeList(node->option_list()));

  // Get a deep copy of hint_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedOption>> hint_list,
      ProcessNodeList(node->hint_list()));

  // Create a mutable instance of ResolvedAlterTableSetOptionsStmt.
  auto copy = MakeResolvedAlterTableSetOptionsStmt(
    node->name_path(),
    std::move(option_list),
    node->is_if_exists()
  );

  // Copy the hint list explicitly because hint_list is not a constructor arg.
  // Because it is not a constructor arg, the only way to copy the value is to
  // copy it explicitly.
  ZETASQL_RETURN_IF_ERROR(CopyHintList<ResolvedAlterTableSetOptionsStmt>(node, copy.get()));

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedRenameStmt(
    const ResolvedRenameStmt* node) {
  // Get a deep copy of hint_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedOption>> hint_list,
      ProcessNodeList(node->hint_list()));

  // Create a mutable instance of ResolvedRenameStmt.
  auto copy = MakeResolvedRenameStmt(
    node->object_type(),
    node->old_name_path(),
    node->new_name_path()
  );

  // Copy the hint list explicitly because hint_list is not a constructor arg.
  // Because it is not a constructor arg, the only way to copy the value is to
  // copy it explicitly.
  ZETASQL_RETURN_IF_ERROR(CopyHintList<ResolvedRenameStmt>(node, copy.get()));

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedCreateRowPolicyStmt(
    const ResolvedCreateRowPolicyStmt* node) {
  // Get a deep copy of grantee_expr_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedExpr>> grantee_expr_list,
      ProcessNodeList(node->grantee_expr_list()));

  // Get deep copy of table_scan field.
  ZETASQL_ASSIGN_OR_RETURN(
      std::unique_ptr<ResolvedTableScan> table_scan,
      ProcessNode(node->table_scan()));

  // Get deep copy of predicate field.
  ZETASQL_ASSIGN_OR_RETURN(
      std::unique_ptr<ResolvedExpr> predicate,
      ProcessNode(node->predicate()));

  // Get a deep copy of hint_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedOption>> hint_list,
      ProcessNodeList(node->hint_list()));

  // Create a mutable instance of ResolvedCreateRowPolicyStmt.
  auto copy = MakeResolvedCreateRowPolicyStmt(
    node->create_mode(),
    node->name(),
    node->target_name_path(),
    node->grantee_list(),
    std::move(grantee_expr_list),
    std::move(table_scan),
    std::move(predicate),
    node->predicate_str()
  );

  // Copy the hint list explicitly because hint_list is not a constructor arg.
  // Because it is not a constructor arg, the only way to copy the value is to
  // copy it explicitly.
  ZETASQL_RETURN_IF_ERROR(CopyHintList<ResolvedCreateRowPolicyStmt>(node, copy.get()));

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedDropRowPolicyStmt(
    const ResolvedDropRowPolicyStmt* node) {
  // Get a deep copy of hint_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedOption>> hint_list,
      ProcessNodeList(node->hint_list()));

  // Create a mutable instance of ResolvedDropRowPolicyStmt.
  auto copy = MakeResolvedDropRowPolicyStmt(
    node->is_drop_all(),
    node->is_if_exists(),
    node->name(),
    node->target_name_path()
  );

  // Copy the hint list explicitly because hint_list is not a constructor arg.
  // Because it is not a constructor arg, the only way to copy the value is to
  // copy it explicitly.
  ZETASQL_RETURN_IF_ERROR(CopyHintList<ResolvedDropRowPolicyStmt>(node, copy.get()));

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedAlterRowPolicyStmt(
    const ResolvedAlterRowPolicyStmt* node) {
  // Get a deep copy of grantee_expr_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedExpr>> grantee_expr_list,
      ProcessNodeList(node->grantee_expr_list()));

  // Get deep copy of table_scan field.
  ZETASQL_ASSIGN_OR_RETURN(
      std::unique_ptr<ResolvedTableScan> table_scan,
      ProcessNode(node->table_scan()));

  // Get deep copy of predicate field.
  ZETASQL_ASSIGN_OR_RETURN(
      std::unique_ptr<ResolvedExpr> predicate,
      ProcessNode(node->predicate()));

  // Get a deep copy of hint_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedOption>> hint_list,
      ProcessNodeList(node->hint_list()));

  // Create a mutable instance of ResolvedAlterRowPolicyStmt.
  auto copy = MakeResolvedAlterRowPolicyStmt(
    node->name(),
    node->new_name(),
    node->target_name_path(),
    node->grantee_list(),
    std::move(grantee_expr_list),
    std::move(table_scan),
    std::move(predicate),
    node->predicate_str()
  );

  // Copy the hint list explicitly because hint_list is not a constructor arg.
  // Because it is not a constructor arg, the only way to copy the value is to
  // copy it explicitly.
  ZETASQL_RETURN_IF_ERROR(CopyHintList<ResolvedAlterRowPolicyStmt>(node, copy.get()));

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedCreateConstantStmt(
    const ResolvedCreateConstantStmt* node) {
  // Get deep copy of expr field.
  ZETASQL_ASSIGN_OR_RETURN(
      std::unique_ptr<ResolvedExpr> expr,
      ProcessNode(node->expr()));

  // Get a deep copy of hint_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedOption>> hint_list,
      ProcessNodeList(node->hint_list()));

  // Create a mutable instance of ResolvedCreateConstantStmt.
  auto copy = MakeResolvedCreateConstantStmt(
    node->name_path(),
    node->create_scope(),
    node->create_mode(),
    std::move(expr)
  );

  // Copy the hint list explicitly because hint_list is not a constructor arg.
  // Because it is not a constructor arg, the only way to copy the value is to
  // copy it explicitly.
  ZETASQL_RETURN_IF_ERROR(CopyHintList<ResolvedCreateConstantStmt>(node, copy.get()));

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedCreateFunctionStmt(
    const ResolvedCreateFunctionStmt* node) {
  // Get a deep copy of aggregate_expression_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedComputedColumn>> aggregate_expression_list,
      ProcessNodeList(node->aggregate_expression_list()));

  // Get deep copy of function_expression field.
  ZETASQL_ASSIGN_OR_RETURN(
      std::unique_ptr<ResolvedExpr> function_expression,
      ProcessNode(node->function_expression()));

  // Get a deep copy of option_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedOption>> option_list,
      ProcessNodeList(node->option_list()));

  // Get a deep copy of hint_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedOption>> hint_list,
      ProcessNodeList(node->hint_list()));

  // Create a mutable instance of ResolvedCreateFunctionStmt.
  auto copy = MakeResolvedCreateFunctionStmt(
    node->name_path(),
    node->create_scope(),
    node->create_mode(),
    node->has_explicit_return_type(),
    node->return_type(),
    node->argument_name_list(),
    node->signature(),
    node->is_aggregate(),
    node->language(),
    node->code(),
    std::move(aggregate_expression_list),
    std::move(function_expression),
    std::move(option_list),
    node->sql_security()
  );

  // Copy the hint list explicitly because hint_list is not a constructor arg.
  // Because it is not a constructor arg, the only way to copy the value is to
  // copy it explicitly.
  ZETASQL_RETURN_IF_ERROR(CopyHintList<ResolvedCreateFunctionStmt>(node, copy.get()));

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedArgumentDef(
    const ResolvedArgumentDef* node) {
  // Create a mutable instance of ResolvedArgumentDef.
  auto copy = MakeResolvedArgumentDef(
    node->name(),
    node->type(),
    node->argument_kind()
  );

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedArgumentRef(
    const ResolvedArgumentRef* node) {
  // Create a mutable instance of ResolvedArgumentRef.
  auto copy = MakeResolvedArgumentRef(
    node->type(),
    node->name(),
    node->argument_kind()
  );

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedCreateTableFunctionStmt(
    const ResolvedCreateTableFunctionStmt* node) {
  // Get a deep copy of option_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedOption>> option_list,
      ProcessNodeList(node->option_list()));

  // Get deep copy of query field.
  ZETASQL_ASSIGN_OR_RETURN(
      std::unique_ptr<ResolvedScan> query,
      ProcessNode(node->query()));

  // Get a deep copy of output_column_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedOutputColumn>> output_column_list,
      ProcessNodeList(node->output_column_list()));

  // Get a deep copy of hint_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedOption>> hint_list,
      ProcessNodeList(node->hint_list()));

  // Create a mutable instance of ResolvedCreateTableFunctionStmt.
  auto copy = MakeResolvedCreateTableFunctionStmt(
    node->name_path(),
    node->create_scope(),
    node->create_mode(),
    node->argument_name_list(),
    node->signature(),
    std::move(option_list),
    node->language(),
    node->code(),
    std::move(query),
    std::move(output_column_list),
    node->is_value_table(),
    node->sql_security()
  );

  // Copy the hint list explicitly because hint_list is not a constructor arg.
  // Because it is not a constructor arg, the only way to copy the value is to
  // copy it explicitly.
  ZETASQL_RETURN_IF_ERROR(CopyHintList<ResolvedCreateTableFunctionStmt>(node, copy.get()));

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedRelationArgumentScan(
    const ResolvedRelationArgumentScan* node) {
  // Get a deep copy of hint_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedOption>> hint_list,
      ProcessNodeList(node->hint_list()));

  // Create a mutable instance of ResolvedRelationArgumentScan.
  auto copy = MakeResolvedRelationArgumentScan(
    node->column_list(),
    node->name(),
    node->is_value_table()
  );

  // Copy the hint list explicitly because hint_list is not a constructor arg.
  // Because it is not a constructor arg, the only way to copy the value is to
  // copy it explicitly.
  ZETASQL_RETURN_IF_ERROR(CopyHintList<ResolvedRelationArgumentScan>(node, copy.get()));

  // Copy the is_ordered field explicitly because it is not a constructor arg.
  copy.get()->set_is_ordered(node->is_ordered());

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedArgumentList(
    const ResolvedArgumentList* node) {
  // Get a deep copy of arg_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedArgumentDef>> arg_list,
      ProcessNodeList(node->arg_list()));

  // Create a mutable instance of ResolvedArgumentList.
  auto copy = MakeResolvedArgumentList(
    std::move(arg_list)
  );

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedFunctionSignatureHolder(
    const ResolvedFunctionSignatureHolder* node) {
  // Create a mutable instance of ResolvedFunctionSignatureHolder.
  auto copy = MakeResolvedFunctionSignatureHolder(
    node->signature()
  );

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedDropFunctionStmt(
    const ResolvedDropFunctionStmt* node) {
  // Get deep copy of arguments field.
  ZETASQL_ASSIGN_OR_RETURN(
      std::unique_ptr<ResolvedArgumentList> arguments,
      ProcessNode(node->arguments()));

  // Get deep copy of signature field.
  ZETASQL_ASSIGN_OR_RETURN(
      std::unique_ptr<ResolvedFunctionSignatureHolder> signature,
      ProcessNode(node->signature()));

  // Get a deep copy of hint_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedOption>> hint_list,
      ProcessNodeList(node->hint_list()));

  // Create a mutable instance of ResolvedDropFunctionStmt.
  auto copy = MakeResolvedDropFunctionStmt(
    node->is_if_exists(),
    node->name_path(),
    std::move(arguments),
    std::move(signature)
  );

  // Copy the hint list explicitly because hint_list is not a constructor arg.
  // Because it is not a constructor arg, the only way to copy the value is to
  // copy it explicitly.
  ZETASQL_RETURN_IF_ERROR(CopyHintList<ResolvedDropFunctionStmt>(node, copy.get()));

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedCallStmt(
    const ResolvedCallStmt* node) {
  // Get a deep copy of argument_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedExpr>> argument_list,
      ProcessNodeList(node->argument_list()));

  // Get a deep copy of hint_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedOption>> hint_list,
      ProcessNodeList(node->hint_list()));

  // Create a mutable instance of ResolvedCallStmt.
  auto copy = MakeResolvedCallStmt(
    node->procedure(),
    node->signature(),
    std::move(argument_list)
  );

  // Copy the hint list explicitly because hint_list is not a constructor arg.
  // Because it is not a constructor arg, the only way to copy the value is to
  // copy it explicitly.
  ZETASQL_RETURN_IF_ERROR(CopyHintList<ResolvedCallStmt>(node, copy.get()));

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedImportStmt(
    const ResolvedImportStmt* node) {
  // Get a deep copy of option_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedOption>> option_list,
      ProcessNodeList(node->option_list()));

  // Get a deep copy of hint_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedOption>> hint_list,
      ProcessNodeList(node->hint_list()));

  // Create a mutable instance of ResolvedImportStmt.
  auto copy = MakeResolvedImportStmt(
    node->import_kind(),
    node->name_path(),
    node->file_path(),
    node->alias_path(),
    node->into_alias_path(),
    std::move(option_list)
  );

  // Copy the hint list explicitly because hint_list is not a constructor arg.
  // Because it is not a constructor arg, the only way to copy the value is to
  // copy it explicitly.
  ZETASQL_RETURN_IF_ERROR(CopyHintList<ResolvedImportStmt>(node, copy.get()));

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedModuleStmt(
    const ResolvedModuleStmt* node) {
  // Get a deep copy of option_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedOption>> option_list,
      ProcessNodeList(node->option_list()));

  // Get a deep copy of hint_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedOption>> hint_list,
      ProcessNodeList(node->hint_list()));

  // Create a mutable instance of ResolvedModuleStmt.
  auto copy = MakeResolvedModuleStmt(
    node->name_path(),
    std::move(option_list)
  );

  // Copy the hint list explicitly because hint_list is not a constructor arg.
  // Because it is not a constructor arg, the only way to copy the value is to
  // copy it explicitly.
  ZETASQL_RETURN_IF_ERROR(CopyHintList<ResolvedModuleStmt>(node, copy.get()));

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedAggregateHavingModifier(
    const ResolvedAggregateHavingModifier* node) {
  // Get deep copy of having_expr field.
  ZETASQL_ASSIGN_OR_RETURN(
      std::unique_ptr<ResolvedExpr> having_expr,
      ProcessNode(node->having_expr()));

  // Create a mutable instance of ResolvedAggregateHavingModifier.
  auto copy = MakeResolvedAggregateHavingModifier(
    node->kind(),
    std::move(having_expr)
  );

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedCreateMaterializedViewStmt(
    const ResolvedCreateMaterializedViewStmt* node) {
  // Get a deep copy of hint_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedOption>> hint_list,
      ProcessNodeList(node->hint_list()));

  // Get a deep copy of option_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedOption>> option_list,
      ProcessNodeList(node->option_list()));

  // Get a deep copy of output_column_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedOutputColumn>> output_column_list,
      ProcessNodeList(node->output_column_list()));

  // Get deep copy of query field.
  ZETASQL_ASSIGN_OR_RETURN(
      std::unique_ptr<ResolvedScan> query,
      ProcessNode(node->query()));

  // Create a mutable instance of ResolvedCreateMaterializedViewStmt.
  auto copy = MakeResolvedCreateMaterializedViewStmt(
    node->name_path(),
    node->create_scope(),
    node->create_mode(),
    std::move(option_list),
    std::move(output_column_list),
    std::move(query),
    node->sql(),
    node->sql_security(),
    node->is_value_table()
  );

  // Copy the hint list explicitly because hint_list is not a constructor arg.
  // Because it is not a constructor arg, the only way to copy the value is to
  // copy it explicitly.
  ZETASQL_RETURN_IF_ERROR(CopyHintList<ResolvedCreateMaterializedViewStmt>(node, copy.get()));

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

zetasql_base::Status
ResolvedASTDeepCopyVisitor::CopyVisitResolvedCreateProcedureStmt(
    const ResolvedCreateProcedureStmt* node) {
  // Get a deep copy of option_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedOption>> option_list,
      ProcessNodeList(node->option_list()));

  // Get a deep copy of hint_list vector.
  ZETASQL_ASSIGN_OR_RETURN(
      std::vector<std::unique_ptr<ResolvedOption>> hint_list,
      ProcessNodeList(node->hint_list()));

  // Create a mutable instance of ResolvedCreateProcedureStmt.
  auto copy = MakeResolvedCreateProcedureStmt(
    node->name_path(),
    node->create_scope(),
    node->create_mode(),
    node->argument_name_list(),
    node->signature(),
    std::move(option_list),
    node->procedure_body()
  );

  // Copy the hint list explicitly because hint_list is not a constructor arg.
  // Because it is not a constructor arg, the only way to copy the value is to
  // copy it explicitly.
  ZETASQL_RETURN_IF_ERROR(CopyHintList<ResolvedCreateProcedureStmt>(node, copy.get()));

  // Set parse location range if it was previously set, as this is not a
  // constructor arg.
  const auto parse_location = node->GetParseLocationRangeOrNULL();
  if (parse_location != nullptr) {
    copy.get()->SetParseLocationRange(*parse_location);
  }

  // Add the non-abstract node to the stack.
  PushNodeToStack(std::move(copy));
  return zetasql_base::OkStatus();
}

}  // namespace zetasql